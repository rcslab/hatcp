#ifndef TRACE_H_
#define TRACE_H_

int init_trace_file(char * path);
int get_trace_line(int line, char * buf, int buf_len);
void free_trace_file();

#endif
