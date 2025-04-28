#ifndef ACC_H_
#define ACC_H_

#include "plugin/plugin.h"

#define	STREAM_IO_CLIFD			0
#define STREAM_IO_LISTENFD		2
#define STREAM_IO_WANFD			3
#define STREAM_IO_TARGETFD		4

struct stream_ev_io {
	ev_io evio;
	int stream_type;
	union {
		struct stream_entry *stream;
		struct wanacc_app *app;
	};
};

struct stat_ev_io {
	ev_timer tmout_w;
	struct wanacc_app *app;
};

struct queue_ev_io {
	ev_async io;
	struct worker *worker;
};


struct stream_entry {
	struct stream_ev_io	io;
	int			fd;
	uint64_t		hash;
	struct stream_entry	*wan;	
	struct worker		*worker;
	struct worker		*b_worker;   //preferred back worker
	struct wanacc_app	*app;
	struct io_buffer_queue	ioq;

	TAILQ_ENTRY(stream_entry) list;
};

void wanacc_stat_cb(EV_P_ ev_io *w, int revents);
#ifdef PERF_PROFILING
void wanacc_perf_cb(EV_P_ ev_timer *w, int revents);
#endif
void wanacc_new_wan_cb(EV_P_ ev_io *ws, int revents);
void wanacc_new_stream_cb(EV_P_ ev_io *ws, int revents);
void stream_clean(struct stream_entry *stream);

#endif
