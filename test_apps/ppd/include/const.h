#pragma once

#include <stdint.h>

enum WORKLOAD_TYPE {
	ECHO = 0,
	TOUCH = 1,
	RDB = 2,
	HTTP = 3,
};

struct ppd_msg {
	uint32_t size;
	char payload[0];
};

static constexpr int PPD_RDB_OP_GET = 0;
static constexpr int PPD_RDB_OP_PUT = 1;
static constexpr int PPD_RDB_OP_SEEK = 2;
