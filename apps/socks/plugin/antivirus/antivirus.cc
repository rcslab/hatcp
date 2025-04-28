#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include <unistd.h>
#include <fcntl.h>

#include "../plugin.h"	
#include "../../utils.h"
#include "antivirus.h"

#include "clamav.h"

#define ANTIVIRUS_VERSION "1.0"

int null_func() {return (0);};
int src_rx(struct socks_entry *socks, char *pld);
int dst_rx(struct socks_entry *socks, char *pld);
int plugin_init();
int plugin_unload();

static struct cl_scan_options options;
static struct cl_engine *engine;

int 
socks_antivirus(struct socks_plugin *sp)
{
	if (sp) {
		strcpy(sp->name, "antivirus");
		strcpy(sp->producer, "SOCKS");
		strcpy(sp->desc, "SOCKS built-in antivirus plugin powered by libclamav");
		strcpy(sp->ver, ANTIVIRUS_VERSION);
		sp->enabled = 1;
		sp->socks_plugin_init = &plugin_init;
		sp->socks_plugin_src_packet_rx = &src_rx;
		sp->socks_plugin_dst_packet_rx = &dst_rx;
		sp->socks_plugin_clean = &plugin_unload;
		return (0);
	}

	return (1);
}

int 
src_rx(struct socks_entry *socks, char *pld)
{
	
	return (0);
}

int 
dst_rx(struct socks_entry *socks, char *pld)
{
	FILE *fp;
	int fd, rt;
	const char *fn, *vn;
	unsigned long int size = 0;

	fp = fopen("antivirus.tmp", "w");
	if (fp == NULL) {
		DBG("Cannot open tmp file to write.");
		return (0);
	}

	fprintf(fp, "%s", pld);
	fflush(fp);

	//fd = fileno(fp);
	fclose(fp);
	fd = open("antivirus.tmp", O_RDONLY);
	rt = cl_scandesc(fd, fn, &vn, &size, engine, &options);
	if (rt == CL_VIRUS) {
		INFO("ANTIVIRUS: VIRUS DETECTED!");
	}
	close(fd);

	return (0);
}

int 
plugin_init()
{
	unsigned int sigs = 0;
	int error;

	INFO("ANTIVIRUS: initializing..\n");
	if (engine == NULL) {
		error = cl_init(CL_INIT_DEFAULT);
		if (error != CL_SUCCESS) {
			DBG("Failed to load libclamav.");
			return (1);
		}

		engine = cl_engine_new();
		if (!engine) {
			DBG("Failed to init clamav engine.");
			return (1);
		}

		/* load all available databases */
		error = cl_load(cl_retdbdir(), engine, &sigs, CL_DB_STDOPT);
		if (error != CL_SUCCESS) {
			DBG("Failed to load clamav database.");
			cl_engine_free(engine);
			return (1);
		}

		INFO("ANTIVIRUS: signature %u loaded.\n", sigs);

		/* build engine */
		error = cl_engine_compile(engine);
		if (error != CL_SUCCESS) {
			INFO("Failed to init database: %s\n", cl_strerror(error));
			cl_engine_free(engine);
			return (1);
		}

		memset(&options, 0, sizeof(struct cl_scan_options));
		/* enable all parsers */
		options.parse |= ~0;
		 /* enable heuristic alert options */
		options.general |= CL_SCAN_GENERAL_HEURISTICS;
	}

	INFO("ANTIVIRUS: initialized.");
	return (0);
}


int
plugin_unload()
{
	cl_engine_free(engine);	
}
