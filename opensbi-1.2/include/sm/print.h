#ifndef SM_PRINT_H
#define SM_PRINT_H

#include <sbi/sbi_console.h>
#define PENGLAI_DEBUG
#ifdef PENGLAI_DEBUG
#define printm(...) sbi_printf(__VA_ARGS__)
#else
#define printm(...)
#endif

//For report error messages, always enabled
#define printm_err(...) sbi_printf(__VA_ARGS__)

#endif
