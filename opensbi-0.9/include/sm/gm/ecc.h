#ifndef _ECC_H_
#define _ECC_H_

#include "sm/gm/typedef.h"

#define ECC_WORDSIZE 8
#define ECC_NUMBITS 256
#define ECC_NUMWORD (ECC_NUMBITS/ECC_WORDSIZE) //32

#define ECC_MAX_DIGITS  4

#define SWAP(a,b) { u32 t = a; a = b; b = t;}

typedef struct ecc_point
{
  u64 x[ECC_MAX_DIGITS];
  u64 y[ECC_MAX_DIGITS];
} ecc_point;

struct ecc_curve {
  u8 ndigits;
  struct ecc_point g;
  u64 p[ECC_MAX_DIGITS];
  u64 n[ECC_MAX_DIGITS];
  u64 h[ECC_MAX_DIGITS];
  u64 a[ECC_MAX_DIGITS];
  u64 b[ECC_MAX_DIGITS];
};

void ecc_bytes2native(u64 *native, void *bytes, u8 ndigits);
void ecc_native2bytes(void *bytes, u64 *native, u8 ndigits);

void ecc_point_add(struct ecc_curve *curve, ecc_point *result, ecc_point *x, ecc_point *y);
void ecc_point_mult(struct ecc_curve *curve, ecc_point *result, ecc_point *point, u64 *scalar, u64 *initialZ);
void ecc_point_mult2(struct ecc_curve *curve, ecc_point *result, ecc_point *g, ecc_point *p, u64 *s, u64 *t);
int ecc_point_is_zero(struct ecc_curve *curve, ecc_point *point);

#endif
