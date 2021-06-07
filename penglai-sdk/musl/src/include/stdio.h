#ifndef STDIO_H
#define STDIO_H

#define __DEFINED_struct__IO_FILE

#include "../../include/stdio.h"

#undef stdin
#undef stdout
#undef stderr
#define DEFAULT_UNTRUSTED_PTR   0x0000001000000000
#define OCALL_NR_WRITE         88

extern hidden FILE __stdin_FILE;
extern hidden FILE __stdout_FILE;
extern hidden FILE __stderr_FILE;

#define stdin (&__stdin_FILE)
#define stdout (&__stdout_FILE)
#define stderr (&__stderr_FILE)

#endif
