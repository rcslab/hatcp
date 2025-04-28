#ifndef HTTP_H_
#define HTTP_H_

#define WRKWRK_HTTP_RESP_FOUND		0
#define WRKWRK_HTTP_RESP_NOT_FOUND	1

#define HTTP_SERVER_DEFAULT_PORT	80

#define HTTP_INVALID			0

#define HTTP_FIELD_CONNECTION		0
#define HTTP_FIELD_CONTENT_LENGTH	1

#define HTTP_FIELDS_COUNT	2

#define HTTP_HEADER_MAX_LEN	8192 

static const char * HTTP_FIELDS[HTTP_FIELDS_COUNT] = {
	"Connection",
	"Content-Length"
};

static const char * HTTP_FIELD_CONNECTION_KEEPALIVE = "keep-alive";

struct http_response_field {
	char * field;
	int field_len;
	int status;
	char * value;
	int value_len;
};

int compose_http_get_request(int type, char * in, int len_in, char * out, 
    uint32_t * host, uint16_t * port);
int parse_http_response(char * resp, int len, struct http_response_field *fields, int count);

void clean_http_response_field(struct http_response_field *f);
void make_http_response_field(struct http_response_field *f, const char * field);

int find_http_content_offset(char *resp, int len);

#endif
