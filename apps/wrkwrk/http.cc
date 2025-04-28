#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <netinet/in.h>

#include "utils.h"
#include "http.h"
#include "wrkwrk.h"
#include "netutil.h"

#define HTTP_GET_COMPOSER_STAGE_HOST	0
#define HTTP_GET_COMPOSER_STAGE_TRANS0	1
#define HTTP_GET_COMPOSER_STAGE_REQ	2

#define HOST_BUF_SIZE	256
#define BUF_SIZE	8192

const char * HTTP_STRING_HOST = "Host: ";
const char * HTTP_STRING_HTTP = "http://";
const char * HTTP_STRING_HTTPS = "https://";
const char * HTTP_STRING_HTTP_VER = "HTTP/1.1";
const char * HTTP_STRING_DEFAULT_DOCUMENT = "index.html";
const char * HTTP_STRING_CONTENT_LENGTH = "Content-Length: ";
const char * HTTP_STRING_FIELD_KEEP_ALIVE = "Connection: Keep-Alive\r\n";

static int http_get_status_code(char * resp, int len);

int 
compose_http_get_request(int type, char * in, int len_in, char * out, 
    uint32_t * host, uint16_t * port)
{
	char host_buf[HOST_BUF_SIZE];
	char req[BUF_SIZE];
	int host_len = 0, len = 0, state = 0, done = 0, val;
	int slash_pos = 0, https = 0;
	
	switch (type) {
	case WRKWRK_MODE_TRACE_FILE:
		for (int i=0;i<len_in;i++) {
			switch (state) {
			case HTTP_GET_COMPOSER_STAGE_HOST:
				if (in[i] == ' ') {
					state++;
					break;
				}
				host_buf[host_len++] = in[i];
				host_buf[host_len] = '\0';
				break;
			case HTTP_GET_COMPOSER_STAGE_TRANS0:
				if (in[i] == '"')
					state++;
				break;
			case HTTP_GET_COMPOSER_STAGE_REQ:
				/* 
				 * 2nd and following coniditions are for
				 * handling suspicious reqs form stupid hackers
				 */
				if (in[i] == '"' 
				    && ((i==len_in-1)?1:(in[i+1] == ' '))
				    && ((i<8)?0:(strncmp(in+i-8, "HTTP", 4)==0))) {
					state++;
					req[len++] = '\r';
					req[len++] = '\n';
					break;
				}
				req[len++] = in[i];
				break;
			}

			if (done) 
			    break;
		}

		break;
	case WRKWRK_MODE_HTTP_PATH:
		if (strncmp_ci(in, HTTP_STRING_HTTP, 7) != 0) {
			if (strncmp_ci(in, HTTP_STRING_HTTPS, 8)!= 0) {
				return 0;
			} else
				https = 1;
		}
		for (int i=7 + https;i<len_in;i++) {
			if (in[i] == '/') {
				slash_pos = i;
				break;
			}
			host_buf[host_len++] = in[i];
		}

		/* GET */
		host_buf[host_len] = '\0';
		req[0] = 'G';
		req[1] = 'E';
		req[2] = 'T';
		req[3] = ' ';

		/* Document path */
		if (slash_pos == 0) {
			req[4] = '/';
			memcpy(req + 5, HTTP_STRING_DEFAULT_DOCUMENT, 10);
			len = 15;
		} else {
			memcpy(req + 4, in + slash_pos, len_in - slash_pos);
			len = 4 + len_in - slash_pos;
		}

		req[len++] = ' ';
		
		/* HTTP/X.X */
		memcpy(req + len, HTTP_STRING_HTTP_VER, 8);
		len += 8;

		req[len++] = '\r';
		req[len++] = '\n';
		
		break;
	}
	
	/* Host field */
	memcpy(req + len, HTTP_STRING_HOST, 6);
	len += 6;

	val = 0;
	for (int i=host_len-1;i>=0;i--) {
		if (host_len - i >= 7) {
			break;
		}
		if (host_buf[i] == ':') {
			host_buf[i] = '\0';
			val = 0;
			for (int j=i+1;j<host_len;j++) {
				if (host_buf[j] >= '0' && host_buf[j] <= '9') {
					val = (val * 10) + (host_buf[j] - '0'); 
					host_buf[j] = '\0';
				}
				else
					break;
			}
			host_len -= (host_len - i);
		}
	}
	if (val != 0)
		*port = htons(val);
	else 
		*port = htons(HTTP_SERVER_DEFAULT_PORT);

	*host = get_ip_from_hostname(host_buf);
	if (*host == 0) 
		return 0;

	/* Host value */
	memcpy(req + len, host_buf, host_len);
	len += host_len;

	req[len++] = '\r';
	req[len++] = '\n';

	/* Connection: keep-alive */ 
	memcpy(req + len, HTTP_STRING_FIELD_KEEP_ALIVE, 24);
	len += 24;

	req[len++] = '\r';
	req[len++] = '\n';
	
	memcpy(out, req, len);

	return len;
}

int
parse_http_response(char * resp, int len, struct http_response_field *fields, int count)
{
	int field_len = 0, val_len = 0, colon = 0, found = 0, i = -1;
	char field[256];
	char val[256];
	struct http_response_field *f;
	
	if (count == 0) 
		goto rt;

	//for (int i=0;i<len;i++) {
	while (++i < len)	{
		if (i > 0 && resp[i] == '\n' && resp[i-1] == '\r') {
			if (field_len == 1) {
				/* We are currently on \r\n line before payload */
				break;
			}
			if (colon == 0) {
				colon = 0;
				field_len = 0;
				val_len = 0;
				continue;
			}

			/* Remove extra CR */
			field_len--;
			val_len--;
			for (int j=0;j<count;j++) {
				f = fields + j;
				if (strncmp_ci(field, f->field, field_len) == 0) {
					f->status = WRKWRK_HTTP_RESP_FOUND;
					f->value = (char *)malloc(val_len + 1);
					memcpy(f->value, val, val_len);
					f->value[val_len] = '\0';
					f->value_len = val_len;
					found++;
					break;
				}
			}
			colon = 0;
			field_len = 0;
			val_len = 0;
			
			if (found == count)
				break;
			
			continue;
		}
		
		if (resp[i] == ':') {
			colon = 1;
			i++;
			continue;
		}
		
		if (colon == 0) 
			field[field_len++] = resp[i];
		else if (colon == 1)
			val[val_len++] = resp[i];
	}

rt:
	return (http_get_status_code(resp, len));
}

void
clean_http_response_field(struct http_response_field *f)
{
	if (f) {
		if (f->field) free(f->field);
		if (f->value) free(f->value);
	}
}

void
make_http_response_field(struct http_response_field *f, const char * field)
{
	if (f) {
		f->status = WRKWRK_HTTP_RESP_NOT_FOUND; 
		f->field = (char *)malloc(strlen(field));
		f->field_len = strlen(field);
		memcpy(f->field, field, f->field_len);

		f->value = NULL;
	}
}

static int
http_get_status_code(char * resp, int len)
{
	int rt;
	
	if (len < 12 || strncmp(resp, "HTTP", 4) != 0)
		return HTTP_INVALID;
	
	if (resp[4] != '/' || resp[6] != '.' || resp[8] != ' ')
		return HTTP_INVALID;

	rt = 0;
	for (int i=9;i<12;i++) {
		if (resp[i] >= '0' && resp[i] <= '9') {
			rt = (rt * 10) + (resp[i] - '0');
		} else
			return HTTP_INVALID;
	}

	return rt;
}

int 
find_http_content_offset(char *resp, int len)
{
	for (int i=0;i<len;i++) {
		if (i>=4 && 
		    resp[i-4] == '\r' && resp[i-3] == '\n' &&
		    resp[i-2] == '\r' && resp[i-1] == '\n') {
			return i;
		}
	}
	return 0;
}
