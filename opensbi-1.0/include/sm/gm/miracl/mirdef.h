/*
 *   MIRACL compiler/hardware definitions - mirdef.h
 */
#define MR_LITTLE_ENDIAN
#define MIRACL 32
#define mr_utype int
#define mr_dltype long
#define MR_IBITS 32
#define MR_LBITS 64
#define mr_unsign32 unsigned int
#define mr_unsign64 unsigned long
#define MR_STRIPPED_DOWN
#define MR_NO_STANDARD_IO
#define MR_NO_FILE_IO
#define MAXBASE ((mr_small)1<<(MIRACL-1))
#define MR_BITSINCHAR 8
#define MR_SMALL_AES

// #define MR_GENERIC_MT
#define MR_STATIC 20
#define MR_ALWAYS_BINARY
#define MR_SIMPLE_BASE
#define MR_SIMPLE_IO
#define MR_NOASM
