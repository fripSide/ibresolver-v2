#pragma once

#include <stdio.h>

#define DEBUG

#ifdef DEBUG
#define DEBUG_LOG(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define DEBUG_LOG(fmt, ...)	\
	do {						\
	} while (0)	
#endif