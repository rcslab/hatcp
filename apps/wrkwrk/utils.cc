#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include "utils.h"

int APP_VERBOSE;

void 
APPERR(const char *fmt, ...) 
{
	va_list ap;

	char buf[255];
	char fmt_buf[65535];

	strcpy(fmt_buf, fmt);
	sprintf(buf, "(APPERR)\n");
	strcat(fmt_buf, buf);

	va_start(ap, fmt);
	log(LOG_APPERR, fmt, ap);
	va_end(ap);
}

void 
SYSERR(int error, const char *fmt, ...)
{
	va_list ap;
	char buf[255];
	char fmt_buf[65535];

	strcpy(fmt_buf, fmt);
	sprintf(buf, "(SYSERR Errno %d)\n", error);
	strcat(fmt_buf, buf);

	va_start(ap, fmt);
	log(LOG_SYSERR, fmt, ap);
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
strncmp_ci(char const *a, char const *b, int n)
{
    for (int i=0;i<n;i++, a++, b++) {
		int c = tolower((unsigned char)*a) - tolower((unsigned char)*b);
		if (c != 0 || !*a || !*b)
			return c;
    }

    return 0;
}


