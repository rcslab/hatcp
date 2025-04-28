#include <stdlib.h>
#include <string.h>

#include "http.h"

#define HTTP_FIELDS_COUNT 1
static const char * HTTP_FIELDS[HTTP_FIELDS_COUNT] = {
	"Content-Length"
};

#define HTTP_RESP_FOUND		0
#define HTTP_RESP_NOT_FOUND	1

#define HTTP_INVALID		0

struct http_response_field {
	char * field;
	int field_len;
	int status;
	char * value;
	int value_len;
};

static int parse_http_response(char * resp, int len, struct http_response_field *fields, int count);
static int http_get_status_code(char * resp, int len);
static int find_http_content_offset(char *resp, int len);
static int strncmp_ci(char const *a, char const *b, int n);

static int
strncmp_ci(char const *a, char const *b, int n)
{
    for (int i=0;i<n;i++, a++, b++) {
		int c = tolower((unsigned char)*a) - tolower((unsigned char)*b);
		if (c != 0 || !*a || !*b)
			return c;
    }

    return 0;
}

static int
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
					f->status = HTTP_RESP_FOUND;
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

static int 
find_http_content_offset(char *resp, int len)
{
	if (len >= 4) {
		if (resp[len-4] == '\r' && resp[len-3] == '\n' && 
		    resp[len-2] == '\r' && resp[len-1] == '\n')
			return len;
	}

	for (int i=0;i<len;i++) {
		if (i>=4 && 
		    resp[i-4] == '\r' && resp[i-3] == '\n' &&
		    resp[i-2] == '\r' && resp[i-1] == '\n') {
			return i;
		}
	}
	
	return 0;
}

int
get_http_payload_size(void *buf, int len)
{
	int content_len = 0, content_pos = 0;
	struct http_response_field field;
	int http_code;
	
	field.status = HTTP_RESP_NOT_FOUND;
	field.field = "Content-Length";
	field.field_len = 14;
	field.value = NULL;

	content_pos = find_http_content_offset((char *)buf, len);
	if (content_pos <= 0) {
		if (len >= 8190)
			return (-1);
	}

	http_code = parse_http_response((char *)buf, len, &field, 1);
	if (http_code == HTTP_INVALID) {
		if (content_pos > 0)
			return (-1);

		return (0);
	}

	if (field.status == HTTP_RESP_FOUND) {
		return (atoi(field.value) + content_pos);
	} else
		return (content_pos);

	return (0);
}
