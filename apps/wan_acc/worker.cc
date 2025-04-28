#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <assert.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <ev.h>

#include "utils.h"
#include "netutils.h"
#include "io.h"
#include "app.h"
#include "acc.h"

#include "worker.h"
#include "acc/dedup.h"
#include "acc/compression.h"

static void front_worker_dedup(struct stream_entry *s, char *data, int len);
static void back_worker_compress_send(struct data_entry *de, struct worker *w);
static void
#ifdef PERF_PROFILING
back_worker_decompress_send(struct chunk *rx_ck, struct stream_entry *wan, 
    struct wanacc_app *app, uint64_t ck_ts);
#else
back_worker_decompress_send(struct chunk *rx_ck, struct stream_entry *wan, 
    struct wanacc_app *app);
#endif

static void dummy_cb(EV_P_ ev_timer *w, int revents);

int DEDUP_ENABLED = 1;
int COMPRESSION_ENABLED = 1;

/*
 * Called when:
 *	ES: NEVER 
 *	MS: NEVER
 */
void 
front_worker_queueing_cb(EV_P_ ev_async *w, int revents)
{
	DBG("front_worker_queuing_cb should never be called");
	exit(0);
}

/*
 * Called when:
 *	ES: REM_RX
 *	MS: CLI_RX
 */
void 
front_worker_fd_cb(EV_P_ ev_io *w, int revents)
{
	struct stream_ev_io *sei;
	struct stream_entry *stream;
	char buf[WANACC_IO_BUFFER_SIZE];
	int n;
	int ioe_complete;
	struct io_buffer_entry *ioe, *ioe_tmp;
	char *bp;
#ifdef PERF_PROFILING
	uint32_t start_time, end_time;

	start_time = get_time_us();
#endif

	sei = (struct stream_ev_io *)w;
	stream = sei->stream;

	n = readonce_socket(stream->fd, buf, sizeof(buf));
	if (n == -1) {
		APPERR("Connection was closed by client (Err %d).\n", errno);
		stream_clean(stream);
		return;
	}
	if (n == 0) {
		DBG("fd%d read returned 0.", stream->fd);
		stream_clean(stream);
		return;
	}
   
	if (sei->stream_type == STREAM_IO_TARGETFD) 
		DBG("TRAFFIC - Target fd %d sent %d byte(s).", stream->fd, n);
	else
		DBG("TRAFFIC - Client fd %d sent %d byte(s).", stream->fd, n);

	buf[n] = '\0';

#ifdef PROTO_BATCHING
	ioe_complete = ioq_append_data(&stream->ioq, WANACC_IO_PROTO_AUTO, buf, n, stream);
	if (!ioe_complete) 
		return;

	TAILQ_FOREACH_SAFE(ioe, &stream->ioq, list, ioe_tmp) {
		if (!ioe->complete)
			break;
		
		bp = ioe->buf;
		front_worker_dedup(stream, bp, ioe->len);
		chunk_free(ioe->buf);
		ioq_remove_data(&stream->ioq, ioe);
	}
#else 
	front_worker_dedup(stream, buf, n);
#endif

#ifdef PERF_PROFILING
	end_time = get_time_us();

	stream->worker->front_fd_total += (end_time - start_time);
	stream->worker->front_fd_count++;
#endif
}

/*
 * Called when:
 *	ES: REM_RX->QUEUE->FRONT_ASYNC 
 *	MS: CLI_RX->QUEUE->FRONT_ASYNC
 */
void 
back_worker_queueing_cb(EV_P_ ev_async *w, int revents)
{
	struct queue_ev_io *qio;
	struct worker *worker;
	struct data_entry *de, *tmp;
#ifdef PERF_PROFILING
	uint32_t start_time, end_time;

	start_time = get_time_us();
#endif

	qio = (struct queue_ev_io *)w;
	worker = qio->worker;

	TAILQ_FOREACH_SAFE(de, &worker->dtq, list, tmp) {
		back_worker_compress_send(de, worker);

		pthread_mutex_lock(&worker->dtq_mtx);
		TAILQ_REMOVE(&worker->dtq, de, list);
		pthread_mutex_unlock(&worker->dtq_mtx);
		if (de->data && (!(de->data->flag & CHUNK_FLAG_DONTFREE))) {
			chunk_free(de->data);
		}
		free(de);
	}

#ifdef PERF_PROFILING
	end_time = get_time_us();

	worker->back_queue_total += (end_time - start_time);
	worker->back_queue_count++;
#endif
}

/*
 * Called when:
 *	ES: WAN_MS_RX
 *	MS: WAN_ES_RX
 */
void 
back_worker_fd_cb(EV_P_ ev_io *w, int revents)
{
	struct stream_ev_io *sei;
	struct stream_entry *stream;
	struct wanacc_app *app;
	struct worker *worker;
	struct chunk *ck;
	struct io_buffer_entry *ioe, *ioe_tmp;
	char buf[WANACC_IO_BUFFER_SIZE], *bp;
	int n, ioe_complete;
#ifdef PERF_PROFILING
	uint64_t end_time;
#endif

	sei = (struct stream_ev_io *)w;
	stream = sei->stream;
	app = stream->app;
	worker = stream->worker;

	/* TODO: handle chunked packet */
	n = readonce_socket(stream->fd, buf, sizeof(buf));
	if (n == -1) {
		APPERR("Connection was closed by remote wan (Err %d).\n", errno);
		stream_clean(stream);
		return;
	}
	if (n == 0) {
		APPERR("Connection was closing.\n");
		stream_clean(stream);
		return;
	}
	
	DBG("TRAFFIC - WAN fd %d sent %d byte(s).", stream->fd, n);

	ioe_complete = ioq_append_data(&worker->ioq, WANACC_IO_PROTO_WANACC, 
					buf, n, stream);
	if (!ioe_complete) 
		return;

	TAILQ_FOREACH_SAFE(ioe, &worker->ioq, list, ioe_tmp) {
		if (!ioe->complete)
			break;

		bp = ioe->buf;
		for (int i=0;i<app->n_plugins;i++) {
			if (!app->plugins[i].enabled) 
				continue;
			(*(app->plugins[i].wanacc_plugin_src_packet_rx))(
			    app, NULL, &bp, ioe->len);
		}

		ck = (struct chunk *)bp;

#ifdef PERF_PROFILING
		back_worker_decompress_send(ck, ioe->stream, app, ioe->ts);
#else
		back_worker_decompress_send(ck, ioe->stream, app);
#endif

#ifdef PERF_PROFILING
		end_time = get_time_us();
		worker->back_fd_total += (end_time - ioe->ts);
		worker->back_fd_count++;
#endif
		chunk_free(ck);
		ioq_remove_data(&worker->ioq, ioe);
	}
}

static void
front_worker_dedup(struct stream_entry *s, char *data, int len)
{
	struct data_entry *de = NULL;
	struct chunk *ck;
	int d_len;
	int d_offset;
	struct worker *w, *bw;
	struct wanacc_app *app;
#ifdef PERF_PROFILING
	uint64_t ts;
	uint64_t cycle_st, cycle_ed;

	ts = get_time_us();
#endif

	d_len = len;
	d_offset = 0;
	w = s->worker;
	app = s->app;

	/* Select back worker */
	if (app->mode == WANACC_SERVER) {
		bw = s->wan->worker;
	} else {
		bw = s->b_worker;
		/*
		bw = &app->back_workers[w->next_back_worker++];
		if (w->next_back_worker >= app->back_worker_count)
			w->next_back_worker = 0;
		*/
	}

	while (d_len > 0) {
		/* 
		 * Either chunk and dedup the data or just copy the original
		 * data.
		 */
		if (DEDUP_ENABLED) {
#ifdef PERF_PROFILING
			cycle_st = get_cpucycle();
#endif
			ck = dedup_chunk_data(data + d_offset, 
				CHUNK_SIZE_TARGET, CHUNK_SIZE_MIN, 
				CHUNK_SIZE_MAX, d_len, &bw->ht);
#ifdef PERF_PROFILING
			cycle_ed = get_cpucycle();
			w->dedup_cycle_total += (cycle_ed - cycle_st);
			w->dedup_cycle_count++;

#endif
		} else {
			ck = chunk_alloc(len);
			ck->len = len;
			ck->flag = CHUNK_FLAG_DONTCACHE;
			memcpy(CHUNK_DATA(ck), data, len);
		}

		ck->src_len = ck->len;

		/* 
		 * The client connection on MS is 1:1 mapped on remote connection
		 * on ES.
		 * For MS, set the hash value in header to the client fd.
		 * For ES, set the hash value in header to the hash in mapped
		 * connection(ES<->REMOTE).
		 */
		if (app->mode == WANACC_SERVER) {
			ck->dhdr.hash = s->hash;
		} else {
			ck->dhdr.hash = s->fd;
		}

		ck->dhdr.len = len;
		d_len -= ck->len;
		d_offset += ck->len;

		/* Setup data_entry for next stage */
		de = calloc(1, sizeof(struct data_entry));
		if (!de) {
			SYSERR(errno, "Failed to allocate memory for data entry");
			return;
		}
		de->len = ck->len;
		de->flag = 0;
		de->stream = s;
		de->data = ck;
#ifdef PERF_PROFILING
		de->ts = ts;
#endif

		ck = NULL;

		//DBG("ck len%u src_len%u flag%u\n", ck->len, ck->src_len, ck->flag);
		
		/* Append to the selected back worker data queue */
		pthread_mutex_lock(&bw->dtq_mtx);
		TAILQ_INSERT_TAIL(&bw->dtq, de, list);
		pthread_mutex_unlock(&bw->dtq_mtx);

		/* Notify the back worker */
		if (!ev_async_pending(&bw->ev_queue.io)) {
			ev_async_send(bw->loop, &bw->ev_queue.io);
		}
	}
}

static void
back_worker_compress_send(struct data_entry *de, struct worker *w)
{
	int len;
	struct chunk *ck = NULL;
#ifdef PERF_PROFILING
	uint64_t ck_ts, ts;
	uint64_t cycle_st, cycle_ed;

	ck_ts = de->ts;
#endif

	/* 
	 * Compress chunk if 
	 *  1. This is not a dupped chunk
	 *  2. Compression is enabled
	 */
	if ((!(de->data->flag & CHUNK_FLAG_DUP)) && (COMPRESSION_ENABLED)) {
#ifdef PERF_PROFILING
		cycle_st = get_cpucycle();
#endif
		ck = compress_chunk(de->data);
#ifdef PERF_PROFILING
		cycle_ed = get_cpucycle();

		w->compz_cycle_total += (cycle_ed - cycle_st);
		w->compz_cycle_count++;
#endif
		if (ck == NULL) {
			DBG("Failed to compress the chunk");
		} else {
			de->data = ck;
		}
	}

	len = CHUNK_LEN(de->data);

	/* 
	 * Send through the wan port
	 *  If we are [ES], then we send to [MS].
	 *  Vice versa.
	 */
	DBG("Send %d bytes through WAN fd %d", len, w->wan_stream->fd);
	
	write_socket(w->wan_stream->fd, (char *)de->data, len);

#ifdef PERF_PROFILING
	ts = get_time_us();

	w->in_path_total += (ts - ck_ts);
	w->in_path_count++;
#endif
}

static void
#ifdef PERF_PROFILING
back_worker_decompress_send(struct chunk *rx_ck, struct stream_entry *wan, 
    struct wanacc_app *app, uint64_t ck_ts)
#else
back_worker_decompress_send(struct chunk *rx_ck, struct stream_entry *wan, 
    struct wanacc_app *app)
#endif
{
	struct chunk *ck;
	struct worker *selected_worker;
	struct stream_entry *new_stream, *tmp;
	int error, found = 0, n;
#ifdef PERF_PROFILING
	uint64_t ts;
	uint64_t cycle_st, cycle_ed;
#endif

	ck = chunk_alloc(rx_ck->src_len);
	ck->len = rx_ck->len;
	ck->flag = rx_ck->flag;
	ck->src_len = rx_ck->src_len;
	ck->dhdr = rx_ck->dhdr;
	memcpy(ck->hash, rx_ck->hash, HASH_LENGTH);

	DBG("Len: %d, Srclen: %d, flag: %d hash %u", 
	    ck->len, ck->src_len, ck->flag, ck->dhdr.hash);

	/* First always clear DONTFREE flag */
	ck->flag &= ~CHUNK_FLAG_DONTFREE;

	if (ck->flag & CHUNK_FLAG_COMPRESSED) {
		DBG("Decompressing packet..");
		decompress_chunk_raw(CHUNK_DATA(rx_ck), &ck->len, &ck->src_len, ck);
	}

	if (ck->flag & CHUNK_FLAG_DUP) {
		DBG("Dup packet, fetching from ht.. (hash%u)", ck->dhdr.hash);
		dedup_get_orig_chunk(&ck, &wan->worker->ht);
	} else {
		if (!(ck->flag & CHUNK_FLAG_COMPRESSED))
			memcpy(CHUNK_DATA(ck), CHUNK_DATA(rx_ck), ck->src_len);
		if (!(ck->flag & CHUNK_FLAG_DONTCACHE)) {
			dedup_record_chunk(ck, &wan->worker->ht);
			DBG("Brand new packet, recorded.");
		}
	}

	/* 
	 * On End Server, we are maintaining the 1:1 mapping for the conenction
	 * between ES<->REMOTE and CLIENT<->MS. 
	 * So here we are checking if this connection is in our record, if so we
	 * reuse this connection otherwise we establish a new connection.
	 */
	TAILQ_FOREACH_SAFE(new_stream, &(app->streams), list, tmp) {
		if (new_stream->hash == ck->dhdr.hash) {
			found = 1;
			break;
		}
	}
	if (app->mode == WANACC_SERVER) {
		int fd;

		if (!found) {
			/* If listen_on_remote is ON, take the established
			 * connection from back worker */
			if (app->listen_on_remote) {
				fd = app->remote_fds[wan->worker->id];
				DBG("Use existing fd %d from worker %p", fd, wan->worker);
				goto create_stream;
			}
			
			error = init_socket(&fd);
			if (error) {
				SYSERR(errno, "Failed to create socket fd.");
				exit(0);
			}

			error = connect_socket(fd, app->wan_addr, app->wan_port, 
			    app->somig_on_wan ? app->somig_mode : 0,
			    app->wan_mso_addr, app->wan_ctl_port,
			    app->wan_rso_addr, app->wan_ctl_port);
			if (error) {
				SYSERR(errno, "Failed to connect to remote WAN.");
				exit(0);
			}

create_stream:
			/* Choose a front worker to handle the rx event */
			assert(app->front_worker_next < app->front_worker_count);
			selected_worker = &app->front_workers[app->front_worker_next++];
			if (app->front_worker_next >= app->front_worker_count)
				app->front_worker_next = 0;

			new_stream = (struct stream_entry *)calloc(1, sizeof(struct stream_entry));
			new_stream->fd = fd;
			new_stream->app = app;
			new_stream->wan = wan; 
			new_stream->worker = selected_worker;
			new_stream->io.stream_type = STREAM_IO_TARGETFD;
			new_stream->io.stream = new_stream;
			new_stream->hash = ck->dhdr.hash;
			TAILQ_INIT(&new_stream->ioq);

			//printf("new conn rem fd %d worker %d\n", fd, selected_worker->id);
			 
			pthread_mutex_lock(&app->streams_mtx);

			TAILQ_INSERT_TAIL(&(app->streams), new_stream, list);

			ev_io_init(&new_stream->io.evio, front_worker_fd_cb,
			    new_stream->fd, EV_READ);
			ev_io_start(selected_worker->loop, &new_stream->io.evio);

			pthread_mutex_unlock(&app->streams_mtx);

			found = 1;
		}
	}

	if (!found) {
		APPERR("Failed to find corresponding stream.");
		exit(0);
	}

	n = write_socket(new_stream->fd, CHUNK_DATA(ck), ck->src_len);
	if (n == -1) {
		SYSERR(errno, "Failed to send payload to remote WAN (fd %d)", new_stream->fd);
		stream_clean(new_stream);
	}

	if (!(ck->flag & CHUNK_FLAG_DONTFREE))
		chunk_free(ck);

#ifdef PERF_PROFILING
	ts = get_time_us();

	wan->worker->out_path_total += (ts - ck_ts);
	wan->worker->out_path_count++;
#endif
}

static void 
dummy_cb(EV_P_ ev_timer *w, int revents) {
}

void *
worker_loop(void *worker)
{
	struct worker *w = (struct worker *)worker;
	struct wanacc_app *app = w->app;
	ev_timer dummy_watcher;

	w->loop = ev_loop_new(0);
	ev_async_start(w->loop, &w->ev_queue.io);
	
	ev_timer_init(&dummy_watcher, &dummy_cb, 1, 1);
	ev_timer_start(w->loop, &dummy_watcher);

	pthread_mutex_lock(&app->worker_mtx);
	app->worker_count++;
	pthread_mutex_unlock(&app->worker_mtx);

	DBG("worker id%d type%d loop@%p started.", w->id, w->type, w->loop);
	ev_run(w->loop, 0);

	DBG("worker id%d type%d loop@%p stopping..", w->id, w->type, w->loop);
	ev_loop_destroy(w->loop);

	return (0);
}

