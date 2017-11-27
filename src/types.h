#pragma once

#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS
#include <stdint.h>

#define __need_size_t
#define __need_NULL
#if __GNUC__ > 4 || \
	(__GNUC__  == 4 && __GNUC_MINOR__ >= 9)
	#include <stddef.h>
#endif
#include <cstddef>

// nullptr is keyword from C++11
#ifndef nullptr
#define nullptr NULL
#endif
