#ifndef UTILS_H_
#define UTILS_H_

#define LOG_INFO		0
#define LOG_APPERR		1
#define LOG_SYSERR		2
#define LOG_DEBUG		9

#define DBG(...) debug_log(__FILE__, __func__, __LINE__, __VA_ARGS__)

void APPERR(const char *, ...);
void SYSERR(int, const char *, ...);
void debug_log(const char *, const char *, int, ...);
void INFO(const char *, ...);
void log(int, const char *, va_list ap);
int get_ts_us();


#endif
