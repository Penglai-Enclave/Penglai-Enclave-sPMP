#include "sm/gm/big.h"

typedef struct
{
  u64 m_low;
  u64 m_high;
} uint128_t;

void vli_clear(u64 *vli, u8 ndigits)
{
  int i;

  for(i = 0; i < ndigits; ++i){
    vli[i] = 0;
  }
}

/* Returns true if vli == 0, false otherwise. */
int vli_is_zero(u64 *vli, u8 ndigits)
{
  int i;

  for(i = 0; i < ndigits; ++i){
    if (vli[i])
      return 0;
  }

  return 1;
}

/* Returns nonzero if bit bit of vli is set. */
u64 vli_test_bit(u64 *vli, u8 bit, u8 ndigits)
{
  return (vli[bit/64] & ((u64)1 << (bit % 64)));
}

/* Counts the number of 64-bit "digits" in vli. */
u32 vli_num_digits(u64 *vli, u8 ndigits)
{
  int i;
  /* Search from the end until we find a non-zero digit.
   * We do it in reverse because we expect that most digits will
   * be nonzero.
   */
  for(i = ndigits - 1; i >= 0 && vli[i] == 0; --i);

  return (i + 1);
}

/* Counts the number of bits required for vli. */
u32 vli_num_bits(u64 *vli, u8 ndigits)
{
  u32 i, num_digits;
  u64 digit;

  num_digits = vli_num_digits(vli, ndigits);
  if(num_digits == 0)
    return 0;

  digit = vli[num_digits - 1];
  for(i = 0; digit; ++i)
  digit >>= 1;

  return ((num_digits - 1) * 64 + i);
}

/* Sets dest = src. */
void vli_set(u64 *dest, u64 *src, u8 ndigits)
{
  u32 i;

  for(i = 0; i < ndigits; ++i)
    dest[i] = src[i];
}

/* Returns sign of left - right. */
int vli_cmp(u64 *left, u64 *right, u8 ndigits)
{
  int i;

  for(i = ndigits - 1; i >= 0; --i){
    if(left[i] > right[i])
      return 1;
    else if (left[i] < right[i])
      return -1;
  }
  return 0;
}

/* Computes result = in << c, returning carry. Can modify in place
 * (if result == in). 0 < shift < 64.
 */
u64 vli_lshift(u64 *result, u64 *in, u32 shift, u8 ndigits)
{
  u64 carry = 0;
  int i;

  for(i = 0; i < ndigits; ++i){
    u64 temp = in[i];
    result[i] = (temp << shift) | carry;
    carry = shift ? temp >> (64 - shift) : 0;
  }

  return carry;
}

/* Computes result = in >> c, returning carry. Can modify in place
 * (if result == in). 0 < shift < 64.
 */
u64 vli_rshift(u64 *result, u64 *in, u32 shift, u8 ndigits)
{
  u64 carry = 0;
  int i;

  for(i = ndigits -1; i >= 0; --i){
    u64 temp = in[i];
    result[i] = (temp >> shift) | carry;
    carry = shift ? temp << (64 - shift) : 0;
  }

  return carry;
}

/* Computes result = left + right, returning carry. Can modify in place. */
u64 vli_add(u64 *result, u64 *left, u64 *right, u8 ndigits)
{
  u64 carry = 0;
  u32 i;

  for(i = 0; i < ndigits; ++i){
    u64 sum;

    sum = left[i] + right[i] + carry;
    if(sum != left[i]){
      carry = (sum < left[i]);
    }
    result[i] = sum;
  }

  return carry;
}

/* Computes result = left - right, returning borrow. Can modify in place. */
u64 vli_sub(u64 *result, u64 *left, u64 *right, u8 ndigits)
{
  u64 borrow = 0;
  int i;

  for(i = 0; i < ndigits; ++i){
    u64 diff;

    diff = left[i] - right[i] - borrow;
    if (diff != left[i])
      borrow = (diff > left[i]);

    result[i] = diff;
  }

  return borrow;
}

static uint128_t mul_64_64(u64 left, u64 right)
{
  u64 a0 = left & 0xffffffffull;
  u64 a1 = left >> 32;
  u64 b0 = right & 0xffffffffull;
  u64 b1 = right >> 32;
  u64 m0 = a0 * b0;
  u64 m1 = a0 * b1;
  u64 m2 = a1 * b0;
  u64 m3 = a1 * b1;
  uint128_t result;

  m2 += (m0 >> 32);
  m2 += m1;

  /* Overflow */
  if (m2 < m1)
  m3 += 0x100000000ull;

  result.m_low = (m0 & 0xffffffffull) | (m2 << 32);
  result.m_high = m3 + (m2 >> 32);

  return result;
}

static uint128_t add_128_128(uint128_t a, uint128_t b)
{
  uint128_t result;

  result.m_low = a.m_low + b.m_low;
  result.m_high = a.m_high + b.m_high + (result.m_low < a.m_low);

  return result;
}

static u64 vli_add_digit_mul(u64 *result, u64 *b, u64 c, u64 *d, u8 digits)
{
  uint128_t mul;
  u64 carry;
  u32 i;

  if(c == 0)
    return 0;

  carry = 0;
  for (i = 0; i < digits; i++) {
    mul = mul_64_64(c, d[i]);
    if((result[i] = b[i] + carry) < carry){
      carry = 1;
    }
    else{
      carry = 0;
    }
    if((result[i] += mul.m_low) < mul.m_low){
      carry++;
    }
    carry += mul.m_high;
  }

  return carry;
}

void bn_mult(u64 *result, u64 *left, u64 *right, u8 ndigits)
{
  u64 t[2*ndigits];
  u32 bdigits, cdigits, i;

  vli_clear(t, 2*ndigits);

  bdigits = vli_num_digits(left, ndigits);
  cdigits = vli_num_digits(right, ndigits);

  for(i=0; i<bdigits; i++){
    t[i+cdigits] += vli_add_digit_mul(&t[i], &t[i], left[i], right, cdigits);
  }

  vli_set(result, t, 2*ndigits);
}

#define BN_DIGIT_BITS  32
#define BN_MAX_DIGIT   0xFFFFFFFF
static u32 vli_sub_digit_mult(u32 *a, u32 *b, u32 c, u32 *d, u32 digits)
{
  u64 result;
  u32 borrow, rh, rl;
  u32 i;

  if(c == 0)
  return 0;

  borrow = 0;
  for(i=0; i<digits; i++) {
    result = (u64)c * d[i];
    rl = result & BN_MAX_DIGIT;
    rh = (result >> BN_DIGIT_BITS) & BN_MAX_DIGIT;
    if((a[i] = b[i] - borrow) > (BN_MAX_DIGIT - borrow)){
      borrow = 1;
    }else{
      borrow = 0;
    }
    if((a[i] -= rl) > (BN_MAX_DIGIT - rl)){
      borrow++;
    }
    borrow += rh;
  }

  return borrow;
}

static u32 bn_digit_bits(u32 a)
{
  u32 i;

  for(i = 0; i< sizeof(a) * 8; i++){
    if(a == 0)
      break;
    a >>= 1;
  }

  return i;
}

void bn_div(u32 *a, u32 *b, u32 *c, u32 cdigits, u32 *d, u32 ddigits)
{
  u32 ai, t, cc[cdigits+1], dd[cdigits/2];
  u32 dddigits, shift;
  u64 tmp;
  int i;

  dddigits = ddigits;

  shift = BN_DIGIT_BITS - bn_digit_bits(d[dddigits-1]);
  vli_clear((u64*)cc, dddigits/2);
  cc[cdigits] = vli_lshift((u64*)cc, (u64*)c, shift, cdigits/2);
  vli_lshift((u64*)dd, (u64*)d, shift, dddigits/2);
  t = dd[dddigits-1];

  vli_clear((u64*)a, cdigits/2);
  i = cdigits - dddigits;
  for(; i>=0; i--){
    if(t == BN_MAX_DIGIT){
      ai = cc[i+dddigits];
    }else{
      tmp = cc[i+dddigits-1];
      tmp += (u64)cc[i+dddigits] << BN_DIGIT_BITS;
      ai = tmp / (t + 1);
    }

    cc[i+dddigits] -= vli_sub_digit_mult(&cc[i], &cc[i], ai, dd, dddigits);
    while(cc[i+dddigits] || (vli_cmp((u64*)&cc[i], (u64*)dd, dddigits/2) >= 0)){
      ai++;
      cc[i+dddigits] -= vli_sub((u64*)&cc[i], (u64*)&cc[i], (u64*)dd, dddigits/2);
    }
    a[i] = ai;
  }

  vli_rshift((u64*)b, (u64*)cc, shift, dddigits/2);
}

void vli_div(u64 *result, u64 *remainder, u64 *left, u64 cdigits, u64 *right, u8 ddigits)
{
  bn_div((u32*)result, (u32*)remainder, (u32*)left, cdigits*2, (u32*)right, ddigits*2);
}

void bn_mod(u64 *result, u64 *left, u64 *right, u8 ndigits)
{
  u64 t[2*ndigits];

  vli_div(t, result, left, ndigits*2, right, ndigits);
}

void _vli_mult(u64 *result, u64 *left, u64 *right, u8 ndigits)
{
  uint128_t r01 = { 0, 0 };
  u64 r2 = 0;
  unsigned int i, k;

  /* Compute each digit of result in sequence, maintaining the
   * carries.
   */
  for(k = 0; k < ndigits * 2 - 1; k++){
    unsigned int min;

    if(k < ndigits)
      min = 0;
    else
      min = (k + 1) - ndigits;

    for(i = min; i <= k && i < ndigits; i++){
      uint128_t product;

      product = mul_64_64(left[i], right[k - i]);

      r01 = add_128_128(r01, product);
      r2 += (r01.m_high < product.m_high);
    }

    result[k] = r01.m_low;
    r01.m_low = r01.m_high;
    r01.m_high = r2;
    r2 = 0;
  }

  result[ndigits * 2 - 1] = r01.m_low;
}

void vli_mult(u64 *result, u64 *left, u64 *right, u8 ndigits)
{
#if 1
  bn_mult(result, left, right, ndigits);
#else
  _vli_mult(result, left, right, ndigits);
#endif
}

void vli_square(u64 *result, u64 *left, u8 ndigits)
{
  uint128_t r01 = { 0, 0 };
  u64 r2 = 0;
  int i, k;

  for(k = 0; k < ndigits * 2 - 1; k++){
    unsigned int min;

    if(k < ndigits)
      min = 0;
    else
      min = (k + 1) - ndigits;

    for(i = min; i <= k && i <= k - i; i++){
      uint128_t product;

      product = mul_64_64(left[i], left[k - i]);

      if(i < k - i){
        r2 += product.m_high >> 63;
        product.m_high = (product.m_high << 1) |
          (product.m_low >> 63);
        product.m_low <<= 1;
      }

      r01 = add_128_128(r01, product);
      r2 += (r01.m_high < product.m_high);
    }

    result[k] = r01.m_low;
    r01.m_low = r01.m_high;
    r01.m_high = r2;
    r2 = 0;
  }

  result[ndigits * 2 - 1] = r01.m_low;
}

/* Computes result = (left + right) % mod.
   Assumes that left < mod and right < mod, result != mod. */
void vli_mod_add(u64 *result, u64 *left, u64 *right, u64 *mod, u8 ndigits)
{
  u64 carry;

  carry = vli_add(result, left, right, ndigits);
  /* result > mod (result = mod + remainder), so subtract mod to
   * get remainder.
   */

  if(carry || vli_cmp(result, mod, ndigits) >= 0){
    /* result > mod (result = mod + remainder), so subtract mod to get remainder. */
    vli_sub(result, result, mod, ndigits);
  }
}

/* Computes result = (left - right) % mod.
 * Assumes that left < mod and right < mod, result != mod.
 */
void vli_mod_sub(u64 *result, u64 *left, u64 *right, u64 *mod, u8 ndigits)
{
  u64 borrow;

  borrow = vli_sub(result, left, right, ndigits);
  /* In this case, result == -diff == (max int) - diff.
   * Since -x % d == d - x, we can get the correct result from
   * result + mod (with overflow).
   */
  if(borrow)
    vli_add(result, result, mod, ndigits);
}

/* Computes result = product % curve_prime
 * from http://www.nsa.gov/ia/_files/nist-routines.pdf
 */
void vli_mmod_fast_nist_256(u64 *result, u64 *product, u64 *curve_prime, u8 ndigits)
{
  u64 tmp[2 * ndigits];
  int carry;

  /* t */
  vli_set(result, product, ndigits);

  /* s1 */
  tmp[0] = 0;
  tmp[1] = product[5] & 0xffffffff00000000ull;
  tmp[2] = product[6];
  tmp[3] = product[7];
  carry = vli_lshift(tmp, tmp, 1, ndigits);
  carry += vli_add(result, result, tmp, ndigits);

  /* s2 */
  tmp[1] = product[6] << 32;
  tmp[2] = (product[6] >> 32) | (product[7] << 32);
  tmp[3] = product[7] >> 32;
  carry += vli_lshift(tmp, tmp, 1, ndigits);
  carry += vli_add(result, result, tmp, ndigits);

  /* s3 */
  tmp[0] = product[4];
  tmp[1] = product[5] & 0xffffffff;
  tmp[2] = 0;
  tmp[3] = product[7];
  carry += vli_add(result, result, tmp, ndigits);

  /* s4 */
  tmp[0] = (product[4] >> 32) | (product[5] << 32);
  tmp[1] = (product[5] >> 32) | (product[6] & 0xffffffff00000000ull);
  tmp[2] = product[7];
  tmp[3] = (product[6] >> 32) | (product[4] << 32);
  carry += vli_add(result, result, tmp, ndigits);

  /* d1 */
  tmp[0] = (product[5] >> 32) | (product[6] << 32);
  tmp[1] = (product[6] >> 32);
  tmp[2] = 0;
  tmp[3] = (product[4] & 0xffffffff) | (product[5] << 32);
  carry -= vli_sub(result, result, tmp, ndigits);

  /* d2 */
  tmp[0] = product[6];
  tmp[1] = product[7];
  tmp[2] = 0;
  tmp[3] = (product[4] >> 32) | (product[5] & 0xffffffff00000000ull);
  carry -= vli_sub(result, result, tmp, ndigits);

  /* d3 */
  tmp[0] = (product[6] >> 32) | (product[7] << 32);
  tmp[1] = (product[7] >> 32) | (product[4] << 32);
  tmp[2] = (product[4] >> 32) | (product[5] << 32);
  tmp[3] = (product[6] << 32);
  carry -= vli_sub(result, result, tmp, ndigits);

  /* d4 */
  tmp[0] = product[7];
  tmp[1] = product[4] & 0xffffffff00000000ull;
  tmp[2] = product[5];
  tmp[3] = product[6] & 0xffffffff00000000ull;
  carry -= vli_sub(result, result, tmp, ndigits);

  if (carry < 0) {
    do{
      carry += vli_add(result, result, curve_prime, ndigits);
    }while(carry < 0);
  }
  else{
    while(carry || vli_cmp(curve_prime, result, ndigits) != 1){
      carry -= vli_sub(result, result, curve_prime, ndigits);
    }
  }
}

void vli_mmod_fast_sm2_256(u64 *result, u64 *_product, u64 *mod, u8 ndigits)
{
  u32 tmp1[8];
  u32 tmp2[8];
  u32 tmp3[8];
  u32 *product = (u32 *)_product;
  int carry = 0;

  vli_set(result, (u64 *)product, ndigits);
  vli_clear((u64 *)tmp1, ndigits);
  vli_clear((u64 *)tmp2, ndigits);
  vli_clear((u64 *)tmp3, ndigits);

  /* Y0 */
  tmp1[0] = tmp1[3] = tmp1[7] = product[8];
  tmp2[2] = product[8];
  carry += vli_add(result, result, (u64 *)tmp1, ndigits);
  carry -= vli_sub(result, result, (u64 *)tmp2, ndigits);

  /* Y1 */
  tmp1[0] = tmp1[1] = tmp1[4] = tmp1[7] = product[9];
  tmp1[3] = 0;
  tmp2[2] = product[9];
  carry += vli_add(result, result, (u64 *)tmp1, ndigits);
  carry -= vli_sub(result, result, (u64 *)tmp2, ndigits);

  /* Y2 */
  tmp1[0] = tmp1[1] = tmp1[5] = tmp1[7] = product[10];
  tmp1[4] = 0;
  carry += vli_add(result, result, (u64 *)tmp1, ndigits);

  /* Y3 */
  tmp1[0] = tmp1[1] = tmp1[3] = tmp1[6] = tmp1[7] = product[11];
  tmp1[5] =  0;
  carry += vli_add(result, result, (u64 *)tmp1, ndigits);

  /* Y4 */
  tmp1[0] = tmp1[1] = tmp1[3] = tmp1[4] = tmp1[7] = tmp3[7] = product[12];
  tmp1[6] = 0;
  carry += vli_add(result, result, (u64 *)tmp1, ndigits);
  carry += vli_add(result, result, (u64 *)tmp3, ndigits);

  /* Y5 */
  tmp1[0] = tmp1[1] = tmp1[3] = tmp1[4] = tmp1[5] = tmp1[7] = product[13];
  tmp2[2] = product[13];
  tmp3[0] = tmp3[3] = tmp3[7] = product[13];
  carry += vli_add(result, result, (u64 *)tmp1, ndigits);
  carry += vli_add(result, result, (u64 *)tmp3, ndigits);
  carry -= vli_sub(result, result, (u64 *)tmp2, ndigits);

  /* Y6 */
  tmp1[0] = tmp1[1] = tmp1[3] = tmp1[4] = tmp1[5] = tmp1[6] = tmp1[7] = product[14];
  tmp2[2] = product[14];
  tmp3[0] = tmp3[1] = tmp3[4] = tmp3[7] = product[14];
  tmp3[3] = 0;
  carry += vli_add(result, result, (u64 *)tmp1, ndigits);
  carry += vli_add(result, result, (u64 *)tmp3, ndigits);
  carry -= vli_sub(result, result, (u64 *)tmp2, ndigits);

  /* Y7 */
  tmp1[0] = tmp1[1] = tmp1[3] = tmp1[4] = tmp1[5] = tmp1[6] = tmp1[7] = product[15];
  tmp3[0] = tmp3[1] = tmp3[5]  = product[15];
  tmp3[4] = 0;
  tmp3[7] = 0;
  tmp2[7] = product[15];
  tmp2[2] = 0;
  carry += vli_lshift((u64 *)tmp2, (u64 *)tmp2, 1, ndigits);
  carry += vli_add(result, result, (u64 *)tmp1, ndigits);
  carry += vli_add(result, result, (u64 *)tmp3, ndigits);
  carry += vli_add(result, result, (u64 *)tmp2, ndigits);
  if(carry < 0){
    do{
      carry += vli_add(result, result, mod, ndigits);
    }while(carry < 0);
  }
  else{
    while(carry || vli_cmp(mod, result, ndigits) != 1)
    {
      carry -= vli_sub(result, result, mod, ndigits);
    }
  }
}

/* Computes result = (product) % mod. */
void _vli_mod(u64 *result, u64 *product, u64 *mod, u8 ndigits)
{
  u64 modMultiple[2 * ndigits];
  uint digitShift, bitShift;
  uint productBits;
  uint modBits = vli_num_bits(mod, ndigits);

  productBits = vli_num_bits(product + ndigits, ndigits);
  if(productBits){
    productBits += ndigits * 64;
  }
  else{
    productBits = vli_num_bits(product, ndigits);
  }

  if(productBits < modBits){
    /* product < mod. */
    vli_set(result, product, ndigits);
    return;
  }

  /* Shift mod by (leftBits - modBits). This multiplies mod by the largest
   power of two possible while still resulting in a number less than left. */
  vli_clear(modMultiple, ndigits);
  vli_clear(modMultiple + ndigits, ndigits);
  digitShift = (productBits - modBits) / 64;
  bitShift = (productBits - modBits) % 64;
  if(bitShift){
    modMultiple[digitShift + ndigits] = vli_lshift(modMultiple + digitShift, mod, bitShift, ndigits);
  }
  else{
    vli_set(modMultiple + digitShift, mod, ndigits);
  }

  /* Subtract all multiples of mod to get the remainder. */
  vli_clear(result, ndigits);
  result[0] = 1; /* Use result as a temp var to store 1 (for subtraction) */
  while(productBits > ndigits * 64 || vli_cmp(modMultiple, mod, ndigits) >= 0)
  {
    int cmp = vli_cmp(modMultiple + ndigits, product + ndigits, ndigits);
    if(cmp < 0 || (cmp == 0 && vli_cmp(modMultiple, product, ndigits) <= 0)){
      if (vli_sub(product, product, modMultiple, ndigits))
      {
      /* borrow */
      vli_sub(product + ndigits, product + ndigits, result, ndigits);
      }
      vli_sub(product + ndigits, product + ndigits, modMultiple + ndigits, ndigits);
    }
    u64 carry = (modMultiple[ndigits] & 0x01) << 63;
    vli_rshift(modMultiple + ndigits, modMultiple + ndigits, 1, ndigits);
    vli_rshift(modMultiple, modMultiple, 1, ndigits);
    modMultiple[ndigits-1] |= carry;

    --productBits;
  }
  vli_set(result, product, ndigits);
}

/* Computes result = (product) % mod. */
void vli_mod(u64 *result, u64 *product, u64 *mod, u8 ndigits)
{
#if 1
  bn_mod(result, product, mod, ndigits);
#else
  _vli_mod(result, product, mod, ndigits);
#endif
}

/* Computes result = (left * right) % curve->p. */
void vli_mod_mult_fast(u64 *result, u64 *left, u64 *right, u64 *mod, u8 ndigits)
{
  u64 product[2 * ndigits];

  vli_mult(product, left, right, ndigits);
#if 1
  vli_mod(result, product, mod, ndigits);
#else
  if ( mod[1] == 0xFFFFFFFF00000000ull)
  vli_mmod_fast_sm2_256(result, product, mod, ndigits);
  else
  vli_mmod_fast_nist_256(result, product, mod, ndigits);
#endif
}

/* Computes result = left^2 % curve->p. */
void vli_mod_square_fast(u64 *result, u64 *left, u64 *mod, u8 ndigits)
{
  u64 product[2 * ndigits];

  vli_square(product, left, ndigits);
#if 1
  vli_mod(result, product, mod, ndigits);

#else
  if ( mod[1] == 0xFFFFFFFF00000000ull)
  vli_mmod_fast_sm2_256(result, product, mod, ndigits);
  else
  vli_mmod_fast_nist_256(result, product, mod, ndigits);
#endif
}

/* Computes result = (left * right) % mod. */
void vli_mod_mult(u64 *result, u64 *left, u64 *right, u64 *mod, u8 ndigits)
{
  u64 product[2 * ndigits];

  vli_mult(product, left, right, ndigits);
  vli_mod(result, product, mod, ndigits);
}

/* Computes result = left^2 % mod. */
void vli_mod_square(u64 *result, u64 *left, u64 *mod, u8 ndigits)
{
  u64 product[2 * ndigits];

  vli_square(product, left, ndigits);
  vli_mod(result, product, mod, ndigits);
}

#define DIGIT_2MSB(x)  (u64)(((x) >> (VLI_DIGIT_BITS - 2)) & 0x03)
/* Computes result = left^p % mod. */
void vli_mod_exp(u64 *result, u64 *left, u64 *p, u64 *mod, u8 ndigits)
{
  u64 bpower[3][ndigits], t[ndigits];
  u64 ci_bits, ci;
  u32 j, s;
  u32 digits;
  int i;

  vli_set(bpower[0], left, ndigits);
  vli_mod_mult(bpower[1], bpower[0], left, mod, ndigits);
  vli_mod_mult(bpower[2], bpower[1], left, mod, ndigits);
  vli_clear(t, ndigits);
  t[0] = 1;

  digits = vli_num_digits(p , ndigits);

  i = digits - 1;
  for( ; i >= 0; i--){
    ci = p[i];
    ci_bits = VLI_DIGIT_BITS;

    if(i == (digits - 1)){
      while(!DIGIT_2MSB(ci)){
        ci <<= 2;
        ci_bits -= 2;
      }
    }

    for( j = 0; j < ci_bits; j += 2) {
      vli_mod_mult(t, t, t, mod, ndigits);
      vli_mod_mult(t, t, t, mod, ndigits);
      if((s = DIGIT_2MSB(ci)) != 0){
        vli_mod_mult(t, t, bpower[s-1], mod, ndigits);
      }
      ci <<= 2;
    }
  }

  vli_set(result, t, ndigits);
}

#define EVEN(vli) (!(vli[0] & 1))
/* Computes result = (1 / p_input) % mod. All VLIs are the same size.
 * See "From Euclid's GCD to Montgomery Multiplication to the Great Divide"
 * https://labs.oracle.com/techrep/2001/smli_tr-2001-95.pdf
 */
void vli_mod_inv(u64 *result, u64 *input, u64 *mod, u8 ndigits)
{
  u64 a[ndigits], b[ndigits];
  u64 u[ndigits], v[ndigits];
  u64 carry;
  int cmp_result;

  if(vli_is_zero(input, ndigits)){
    vli_clear(result, ndigits);
    return;
  }

  vli_set(a, input, ndigits);
  vli_set(b, mod, ndigits);
  vli_clear(u, ndigits);
  u[0] = 1;
  vli_clear(v, ndigits);

  while((cmp_result = vli_cmp(a, b, ndigits)) != 0){
    carry = 0;

    if(EVEN(a)){
      vli_rshift(a, a, 1, ndigits);

      if(!EVEN(u))
        carry = vli_add(u, u, mod, ndigits);

      vli_rshift(u, u, 1, ndigits);
      if (carry)
        u[ndigits - 1] |= 0x8000000000000000ull;
    }
    else if(EVEN(b)){
      vli_rshift(b, b, 1, ndigits);

      if(!EVEN(v))
        carry = vli_add(v, v, mod, ndigits);

      vli_rshift(v, v, 1, ndigits);
      if(carry)
        v[ndigits - 1] |= 0x8000000000000000ull;
    }else if(cmp_result > 0){
      vli_sub(a, a, b, ndigits);
      vli_rshift(a, a, 1, ndigits);

      if(vli_cmp(u, v, ndigits) < 0)
        vli_add(u, u, mod, ndigits);

      vli_sub(u, u, v, ndigits);
      if(!EVEN(u))
        carry = vli_add(u, u, mod, ndigits);

      vli_rshift(u, u, 1, ndigits);
      if(carry)
        u[ndigits - 1] |= 0x8000000000000000ull;
    }
    else{
      vli_sub(b, b, a, ndigits);
      vli_rshift(b, b, 1, ndigits);

      if(vli_cmp(v, u, ndigits) < 0)
        vli_add(v, v, mod, ndigits);

      vli_sub(v, v, u, ndigits);
      if(!EVEN(v))
        carry = vli_add(v, v, mod, ndigits);

      vli_rshift(v, v, 1, ndigits);
      if(carry)
        v[ndigits - 1] |= 0x8000000000000000ull;
    }
  }

  vli_set(result, u, ndigits);
}
