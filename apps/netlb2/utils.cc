#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <sys/time.h>

#include "utils.h"

int APP_VERBOSE;

void 
APPERR(const char *fmt, ...) 
{
	va_list ap;

	va_start(ap, fmt);
	log(LOG_APPERR, fmt, ap);
	va_end(ap);
}

void 
SYSERR(int error, const char *fmt, ...)
{
	va_list ap;
	char buf[255];
	char fmt_buf[300];

	strcpy(fmt_buf, fmt);
	sprintf(buf, "(Errno %d)\n", error);
	strcat(fmt_buf, buf);

	va_start(ap, fmt);
	log(LOG_SYSERR, fmt_buf, ap);
	va_end(ap);
}

void
INFO(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	log(LOG_INFO, fmt, ap);
	va_end(ap);
}

void
debug_log(const char *fname, const char *func, int line, ...)
{
	char buf[65535];
	char *fmt;
	va_list ap;

	if (!APP_VERBOSE)
		return;

	va_start(ap, line);
	fmt = va_arg(ap, char *);
	sprintf(buf, "[%s:%s(%d)] %s\n", fname, func, line, fmt);
	log(LOG_DEBUG, buf, ap);
	va_end(ap);
}

void
log(int type, const char *fmt, va_list ap)
{
	switch (type) {
	case LOG_SYSERR:
	case LOG_APPERR:
	case LOG_DEBUG:
	default:
		break;
	}

	vprintf(fmt, ap);
}

int
get_ts_us() {
    int us;
    struct timeval te; 

    gettimeofday(&te, NULL);
    us = te.tv_sec*1000*1000 + te.tv_usec;

    return us;
}


