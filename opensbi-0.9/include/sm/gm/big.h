#ifndef _BIG_H_
#define _BIG_H_

#include "sm/gm/typedef.h"

#define VLI_DIGIT_BITS               64
#define VLI_DIGIT_BYTES              (VLI_DIGIT_BITS/8)

void vli_clear(u64 *vli, u8 ndigits);

/* Returns true if vli == 0, false otherwise. */
int vli_is_zero(u64 *vli, u8 ndigits);

/* Returns nonzero if bit bit of vli is set. */
u64 vli_test_bit(u64 *vli, u8 bit, u8 ndigits);

/* Counts the number of 8-bit "digits" in vli. */
u32 vli_num_digits(u64 *vli, u8 ndigits);

/* Counts the number of bits required for vli. */
u32 vli_num_bits(u64 *vli, u8 ndigits);
/* Sets dest = src. */

void vli_set(u64 *dest, u64 *src, u8 ndigits);

/* Returns sign of left - right. */
int vli_cmp(u64 *left, u64 *right, u8 ndigits);

/* Computes result = in << c, returning carry. Can modify in place
 * (if result == in). 0 < shift < 8.
 */
u64 vli_lshift(u64 *result, u64 *in, u32 shift, u8 ndigits);

/* Computes result = (left * right) % curve->p. */
void vli_mod_mult_fast(u64 *result, u64 *left, u64 *right, u64 *mod, u8 ndigits);

/* Computes result = left^2 % curve->p. */
void vli_mod_square_fast(u64 *result, u64 *left, u64 *mod, u8 ndigits);

/* Computes result = in >> c, returning carry. Can modify in place
 * (if result == in). 0 < shift < 64.
 */
u64 vli_rshift(u64 *result, u64 *in, u32 shift, u8 ndigits);

/* Computes result = left + right, returning carry. Can modify in place. */
u64 vli_add(u64 *result, u64 *left, u64 *right, u8 ndigits);

/* Computes result = left - right, returning borrow. Can modify in place. */
u64 vli_sub(u64 *result, u64 *left, u64 *right, u8 ndigits);

/* Computes result = left * right. */
void vli_mult(u64 *result, u64 *left, u64 *right, u8 ndigits);

/* Computes result = left^2. */
void vli_square(u64 *result, u64 *left, u8 ndigits);

/* Computes result = (left + right) % mod.
   Assumes that left < mod and right < mod, result != mod. */
void vli_mod_add(u64 *result, u64 *left, u64 *right, u64 *mod, u8 ndigits);

/* Computes result = (left - right) % mod.
   Assumes that left < mod and right < mod, result != mod. */
void vli_mod_sub(u64 *result, u64 *left, u64 *right, u64 *mod, u8 ndigits);

/* Computes result = (left * right) % mod. */
void vli_mod_mult(u64 *result, u64 *left, u64 *right, u64 *mod, u8 ndigits);

/* Computes result = left^2 % mod. */
void vli_mod_square(u64 *result, u64 *left, u64 *mod, u8 ndigits);

/* Computes result = left^p % mod. */
void vli_mod_exp(u64 *result, u64 *left, u64 *p, u64 *mod, u8 ndigits);

/* Computes result = (product) % mod. */
void vli_mod(u64 *result, u64 *product, u64 *mod, u8 ndigits);

/* Computes result = (1 / input) % mod. All VLIs are the same size.
 * See "From Euclid's GCD to Montgomery Multiplication to the Great Divide"
 * https://labs.oracle.com/techrep/2001/smli_tr-2001-95.pdf
 */
void vli_mod_inv(u64 *result, u64 *input, u64 *mod, u8 ndigits);

/* Computes result = (left / right).
 * remainder = (left % right).
 */
void vli_div(u64 *result, u64 *remainder, u64 *left, u64 cdigits, u64 *right, u8 ddigits);

#endif
