#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "utils.h"
#include "trace.h"

static int trace_lines;
static int trace_allocated_size;
static char ** traces;

#define TRACE_FILE_READ_CHUNK		1

int 
init_trace_file(char * path)
{
	int len;
	FILE * fp;
	char ** new_traces;
	char line[65536];

	trace_lines = 0;

	fp = fopen(path, "r");
	if (fp == NULL) {
		APPERR("Failed to open trace file %s", path);
		exit(0);
	}

	traces = calloc(TRACE_FILE_READ_CHUNK, sizeof(char *));
	trace_allocated_size = TRACE_FILE_READ_CHUNK;

	while (1) {
		memset(line, '\0', sizeof(line));
		if (fgets(line, sizeof(line), fp) == NULL) {
			break;
		}
		if (trace_lines >= trace_allocated_size) {
			new_traces = realloc(traces, (trace_allocated_size + TRACE_FILE_READ_CHUNK) * sizeof(char *));
			if (new_traces == NULL) {
				APPERR("Failed to load trace file. Cannot realloc.");
				fclose(fp);
				free_trace_file();
				exit(0);
			}

			traces = new_traces;
			trace_allocated_size += TRACE_FILE_READ_CHUNK;
		}

		len = strlen(line);
		traces[trace_lines] = calloc(len + 1, sizeof(char));
		if (traces[trace_lines] == NULL) {
			APPERR("Failed to load trace file. Cannot calloc");
			exit(0);
		}
		memcpy(traces[trace_lines], line, len);

		trace_lines++;
	}

	fclose(fp);

	return trace_lines;
}

int
get_trace_line(int line, char * buf, int buf_len)
{
	int len;
	if (buf == NULL)
		return 0;

	if (line >= trace_lines) 
		goto error;

	len = strlen(traces[line]);
	if (buf_len < len)
		goto error;

	memcpy(buf, traces[line], len);
	return len;

error:
	buf[0] = '\0';
	return 0;
}

void
free_trace_file()
{
	for (int i=0;i<trace_lines;i++) {
		free(traces[i]);
	}

	free(traces);
}
