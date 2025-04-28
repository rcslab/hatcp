#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/queue.h>

#include <ev.h>

#include "acc/chunk.h"
#include "io.h"
#include "netutils.h"
#include "app.h"
#include "utils.h"
#include "acc.h"

/*
 * Extract and return payload size from proto header
 */
static void
ioe_original_length(void * buf, int len, int type, int* pld_len)
{
	int olen;

	*pld_len = 0;

	switch (type) {
	case WANACC_IO_PROTO_WANACC:
		if (len < sizeof(struct chunk))
			return;

		olen = get_chunk_size(buf, len);
		if (olen > 0)
			*pld_len = olen;

		if (IS_CHUNK_DUP(buf)) {
			*pld_len = sizeof(struct chunk);
		}
		return;
	case WANACC_IO_PROTO_HTTP:
		*pld_len = get_http_payload_size(buf, len);
		if (*pld_len < 0) {
			break;
		}
		return;
	case WANACC_IO_PROTO_AUTO:
		/* XXX: todo */
		*pld_len = get_http_payload_size(buf, len);
		if (*pld_len < 0) {
			break;
		}
		return;
	case WANACC_IO_PROTO_UNKNOWN:
	default:
		break;
	}

	*pld_len = len;
}

int 
ioq_append_data(struct io_buffer_queue *ioq, int io_type, char * buf, int length, struct stream_entry *stream)
{
	int offset, len, rt = 0, copy_len = 0, chop_len;
	int ioe_complete;
	struct io_buffer_entry *ioe;

	len = length;
	offset = 0;

append:
	ioe = TAILQ_LAST(ioq, io_buffer_queue);
	if (ioe == NULL) 
		ioe_complete = 1;
	else
		ioe_complete = ioe->complete;

	if (ioe_complete) {
		ioe = (struct io_buffer_entry *)calloc(1, sizeof(struct io_buffer_entry));
		ioe->stream = stream;
		ioe->type = io_type;
		ioe->buf = calloc(1, max(len, IO_BUFFER_LENGTH_MAX) + 1); 
		TAILQ_INSERT_TAIL(ioq, ioe, list);
#ifdef PERF_PROFILING
		ioe->ts = get_time_us();
#endif
		ioe_original_length(buf + offset, len, io_type, &ioe->pld_len);

		DBG("Packet type %d, size decoded from hdr %d recv'd %d",
		    io_type, ioe->pld_len, len);

		/* We don't have the full header yet */
		if (ioe->pld_len <= 0) {
			memcpy(ioe->buf, buf + offset, len);
			ioe->len += len;
			return (rt);
		}

		/* Copy the full/incomplete packet */
		copy_len = min(ioe->pld_len, len);
		memcpy(ioe->buf, buf + offset, copy_len);
		ioe->len += copy_len;
		offset += copy_len;
		len -= copy_len;
		if (ioe->pld_len == ioe->len) { 
			DBG("Get full packet type %d size %d", io_type, ioe->pld_len);
			ioe->buf[ioe->pld_len] = '\0';
			ioe->complete = 1;
			rt = 1;
		}

		if (len > 0)
			goto append;
		else 
			goto delivery;
	} else {
		/* If we knew the payload length from the header */
		if (ioe->pld_len != 0) {
			/* If current data chunk has all payloads */
			if (len >= ioe->pld_len - ioe->len) {
				/* Copy the full/incomplete packet */
				copy_len = min(ioe->pld_len - ioe->len, len);
				if (sizeof(ioe->buf) < ioe->pld_len + 1) {
					ioe->buf = realloc(ioe->buf, ioe->pld_len + 1);
				}
				memcpy(ioe->buf + ioe->len, buf + offset, copy_len);
				ioe->len += copy_len;
				offset += copy_len;
				len -= copy_len;
				if (ioe->pld_len == ioe->len) { 
					ioe->buf[ioe->pld_len] = '\0';
					ioe->complete = 1;
					rt = 1;
				}

				DBG("%d: Packet type %d, size decoded from hdr %d, curr %d",
					__LINE__, io_type, ioe->pld_len, ioe->len);

				if (len > 0)
					goto append;
				else 
					goto delivery;
			}

			/* Otherwise append the data to the end */
			if (sizeof(ioe->buf) < ioe->pld_len + 1) {
				ioe->buf = realloc(ioe->buf, ioe->pld_len + 1);
			}
			memcpy(ioe->buf + ioe->len, buf + offset, len);
			ioe->len += len;
			return (rt);
		}
		
		/* We don't get the full header yet, try to see if we can get
		 * full header with the current data appended */
		if (sizeof(ioe->buf) < ioe->len + len + 1) {
			ioe->buf = realloc(ioe->buf, max(sizeof(ioe->buf) * 2, ioe->len + len) + 1);
		}
		memcpy(ioe->buf + ioe->len, buf + offset, len);
		ioe->len += len;
		offset += len;
		len = 0;
		
		ioe_original_length(ioe->buf, ioe->len, ioe->type, &ioe->pld_len);
		DBG("%d: Packet type %d, size decoded from hdr %d, curr %d",
			__LINE__, io_type, ioe->pld_len, ioe->len);
		/* Still don't get the full header */
		if (ioe->len < ioe->pld_len) {
			return (rt);
		}
		/* Just get the full packet, perfect */
		if (ioe->pld_len == ioe->len) {
			ioe->buf[ioe->pld_len] = '\0';
			ioe->complete = 1;
			goto delivery;
		}

		/* Get too much, chop it */
		chop_len = ioe->len - ioe->pld_len;
		ioe->buf[ioe->pld_len] = '\0';
		ioe->len -= chop_len;
		ioe->complete = 1;
		rt = 1;
		len = chop_len;
		offset -= chop_len;
		goto append;
	}

delivery:
	if (len > 0) {
		printf("Called delivery_check when len is not 0\n");
		exit(0);
	}
	rt = 1;

	return (rt);
}

void
ioq_remove_data(struct io_buffer_queue *ioq, struct io_buffer_entry *ioe)
{
	TAILQ_REMOVE(ioq, ioe, list);
	free(ioe);
}
