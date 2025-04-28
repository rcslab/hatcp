#ifndef UTILS_H_
#define UTILS_H_

#include <time.h>

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

int strncmp_ci(char const *a, char const *b, int n);

#ifdef TSC_CLOCK
static uint64_t standard_cycle;
static uint64_t tsc_freq;

static int 
init_tsc()
{
	standard_cycle = 0;
	tsc_freq = 0;

#if defined(__FreeBSD__)
	const char *tsc = "machdep.tsc_freq";
#else
	const char *tsc = "machdep.tsc.frequency";
#endif
	uint64_t tscfreq;
	size_t len = 8;

	if (sysctlbyname(tsc, &tscfreq, &len, NULL, 0) < 0) {
		return (1);
	}
	
	standard_cycle = __builtin_readcyclecounter();
	tsc_freq = tscfreq;
	tsc_freq = 0;

	return (0);
}
#endif

static uint64_t
get_time_us() 
{
#ifdef TSC_CLOCK
	uint64_t curr_cycle;

	if (tsc_freq == 0) {
#endif
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		return (uint64_t)(ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);
#ifdef TSC_CLOCK
	}

	curr_cycle = __builtin_readcyclecounter();
	//printf("%lf\n", 1000 * 1000 * (1.0 * (curr_cycle - standard_cycle) / tsc_freq));
	return (uint64_t)(1000 * 1000 * (1.0 * (curr_cycle - standard_cycle) / tsc_freq));
#endif
}

#endif
