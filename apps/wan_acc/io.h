#ifndef IO_H_
#define IO_H_

#include <sys/queue.h>

#define IO_BUFFER_LENGTH_MAX		65536 * 2 

#define WANACC_IO_PROTO_UNKNOWN		0
#define WANACC_IO_PROTO_WANACC		1
#define WANACC_IO_PROTO_HTTP		2
#define WANACC_IO_PROTO_AUTO		100

#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

struct io_buffer_entry {
	int type;
	uint32_t len;
	uint32_t pld_len;
	uint32_t offset;
	int complete;

#ifdef PERF_PROFILING
	uint64_t ts;
#endif
	struct stream_entry *stream;
	char *buf;

	TAILQ_ENTRY(io_buffer_entry) list;
};

TAILQ_HEAD(io_buffer_queue, io_buffer_entry);

int ioq_append_data(struct io_buffer_queue *ioq, int io_type, char * buf, int length, struct stream_entry *stream);
void ioq_remove_data(struct io_buffer_queue *ioq, struct io_buffer_entry *ioe);

#endif
