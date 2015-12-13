#pragma once

#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS
#include <stdint.h>

#define __need_size_t
#define __need_NULL
#include <cstddef>

// nullptr is keyword from C++11
#ifndef nullptr
#define nullptr NULL
#endif
