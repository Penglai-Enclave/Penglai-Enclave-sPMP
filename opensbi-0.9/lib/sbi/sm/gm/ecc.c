#include "sm/gm/ecc.h"
#include "sm/gm/big.h"

/* Returns 1 if point is the point at infinity, 0 otherwise. */
int ecc_point_is_zero(struct ecc_curve *curve, ecc_point *point)
{
  return (vli_is_zero(point->x, curve->ndigits)
      && vli_is_zero(point->y, curve->ndigits));
}

/* Double in place */
void ecc_point_double_jacobian(struct ecc_curve *curve, u64 *X1, u64 *Y1, u64 *Z1)
{
  /* t1 = X, t2 = Y, t3 = Z */
  u64 t4[ECC_MAX_DIGITS];
  u64 t5[ECC_MAX_DIGITS];

  if(vli_is_zero(Z1, curve->ndigits))
    return;

  vli_mod_square_fast(t4, Y1, curve->p, curve->ndigits);   /* t4 = y1^2 */
  vli_mod_mult_fast(t5, X1, t4, curve->p, curve->ndigits); /* t5 = x1*y1^2 = A */
  vli_mod_square_fast(t4, t4, curve->p, curve->ndigits);   /* t4 = y1^4 */
  vli_mod_mult_fast(Y1, Y1, Z1, curve->p, curve->ndigits); /* t2 = y1*z1 = z3 */
  vli_mod_square_fast(Z1, Z1, curve->p, curve->ndigits);   /* t3 = z1^2 */

  vli_mod_add(X1, X1, Z1, curve->p, curve->ndigits); /* t1 = x1 + z1^2 */
  vli_mod_add(Z1, Z1, Z1, curve->p, curve->ndigits); /* t3 = 2*z1^2 */
  vli_mod_sub(Z1, X1, Z1, curve->p, curve->ndigits); /* t3 = x1 - z1^2 */
  vli_mod_mult_fast(X1, X1, Z1, curve->p, curve->ndigits);    /* t1 = x1^2 - z1^4 */

  vli_mod_add(Z1, X1, X1, curve->p, curve->ndigits); /* t3 = 2*(x1^2 - z1^4) */
  vli_mod_add(X1, X1, Z1, curve->p, curve->ndigits); /* t1 = 3*(x1^2 - z1^4) */
  if(vli_test_bit(X1, 0, curve->ndigits)){
    u64 carry = vli_add(X1, X1, curve->p, curve->ndigits);
    vli_rshift(X1, X1, 1, curve->ndigits);
    X1[ECC_MAX_DIGITS-1] |= carry << 63;
  }
  else{
    vli_rshift(X1, X1, 1, curve->ndigits);
  }

  /* t1 = 3/2*(x1^2 - z1^4) = B */
  vli_mod_square_fast(Z1, X1, curve->p, curve->ndigits);      /* t3 = B^2 */
  vli_mod_sub(Z1, Z1, t5, curve->p, curve->ndigits); /* t3 = B^2 - A */
  vli_mod_sub(Z1, Z1, t5, curve->p, curve->ndigits); /* t3 = B^2 - 2A = x3 */
  vli_mod_sub(t5, t5, Z1, curve->p, curve->ndigits); /* t5 = A - x3 */
  vli_mod_mult_fast(X1, X1, t5, curve->p, curve->ndigits);    /* t1 = B * (A - x3) */
  vli_mod_sub(t4, X1, t4, curve->p, curve->ndigits); /* t4 = B * (A - x3) - y1^4 = y3 */

  vli_set(X1, Z1, curve->ndigits);
  vli_set(Z1, Y1, curve->ndigits);
  vli_set(Y1, t4, curve->ndigits);
}

/* Modify (x1, y1) => (x1 * z^2, y1 * z^3) */
void apply_z(struct ecc_curve *curve, u64 *X1, u64 *Y1, u64 *Z)
{
  u64 t1[ECC_MAX_DIGITS];

  vli_mod_square_fast(t1, Z, curve->p, curve->ndigits);    /* z^2 */
  vli_mod_mult_fast(X1, X1, t1, curve->p, curve->ndigits); /* x1 * z^2 */
  vli_mod_mult_fast(t1, t1, Z, curve->p, curve->ndigits);  /* z^3 */
  vli_mod_mult_fast(Y1, Y1, t1, curve->p, curve->ndigits); /* y1 * z^3 */
}

/* P = (x1, y1) => 2P, (x2, y2) => P' */
void XYcZ_initial_double(struct ecc_curve *curve, u64 *X1, u64 *Y1, u64 *X2, u64 *Y2, u64 *initialZ)
{
  u64 z[ECC_MAX_DIGITS];

  vli_set(X2, X1, curve->ndigits);
  vli_set(Y2, Y1, curve->ndigits);

  if(initialZ){
    vli_set(z, initialZ, curve->ndigits);
  }
  else{
    vli_clear(z, curve->ndigits);
    z[0] = 1;
  }
  apply_z(curve, X1, Y1, z);

  ecc_point_double_jacobian(curve, X1, Y1, z);

  apply_z(curve, X2, Y2, z);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
   or P => P', Q => P + Q
   */
void XYcZ_add(struct ecc_curve *curve, u64 *X1, u64 *Y1, u64 *X2, u64 *Y2)
{
  /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
  u64 t5[ECC_MAX_DIGITS];

  vli_mod_sub(t5, X2, X1, curve->p, curve->ndigits); /* t5 = x2 - x1 */
  vli_mod_square_fast(t5, t5, curve->p, curve->ndigits);      /* t5 = (x2 - x1)^2 = A */
  vli_mod_mult_fast(X1, X1, t5, curve->p, curve->ndigits);    /* t1 = x1*A = B */
  vli_mod_mult_fast(X2, X2, t5, curve->p, curve->ndigits);    /* t3 = x2*A = C */
  vli_mod_sub(Y2, Y2, Y1, curve->p, curve->ndigits); /* t4 = y2 - y1 */
  vli_mod_square_fast(t5, Y2, curve->p, curve->ndigits);      /* t5 = (y2 - y1)^2 = D */

  vli_mod_sub(t5, t5, X1, curve->p, curve->ndigits); /* t5 = D - B */
  vli_mod_sub(t5, t5, X2, curve->p, curve->ndigits); /* t5 = D - B - C = x3 */
  vli_mod_sub(X2, X2, X1, curve->p, curve->ndigits); /* t3 = C - B */
  vli_mod_mult_fast(Y1, Y1, X2, curve->p, curve->ndigits);    /* t2 = y1*(C - B) */
  vli_mod_sub(X2, X1, t5, curve->p, curve->ndigits); /* t3 = B - x3 */
  vli_mod_mult_fast(Y2, Y2, X2, curve->p, curve->ndigits);    /* t4 = (y2 - y1)*(B - x3) */
  vli_mod_sub(Y2, Y2, Y1, curve->p, curve->ndigits); /* t4 = y3 */

  vli_set(X2, t5, curve->ndigits);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
 * Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
 * or P => P - Q, Q => P + Q
 */
void XYcZ_addC(struct ecc_curve *curve, u64 *X1, u64 *Y1, u64 *X2, u64 *Y2)
{
  /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
  u64 t5[ECC_MAX_DIGITS];
  u64 t6[ECC_MAX_DIGITS];
  u64 t7[ECC_MAX_DIGITS];

  vli_mod_sub(t5, X2, X1, curve->p, curve->ndigits); /* t5 = x2 - x1 */
  vli_mod_square_fast(t5, t5, curve->p, curve->ndigits);      /* t5 = (x2 - x1)^2 = A */
  vli_mod_mult_fast(X1, X1, t5, curve->p, curve->ndigits);    /* t1 = x1*A = B */
  vli_mod_mult_fast(X2, X2, t5, curve->p, curve->ndigits);    /* t3 = x2*A = C */
  vli_mod_add(t5, Y2, Y1, curve->p, curve->ndigits); /* t4 = y2 + y1 */
  vli_mod_sub(Y2, Y2, Y1, curve->p, curve->ndigits); /* t4 = y2 - y1 */

  vli_mod_sub(t6, X2, X1, curve->p, curve->ndigits); /* t6 = C - B */
  vli_mod_mult_fast(Y1, Y1, t6, curve->p, curve->ndigits);    /* t2 = y1 * (C - B) */
  vli_mod_add(t6, X1, X2, curve->p, curve->ndigits); /* t6 = B + C */
  vli_mod_square_fast(X2, Y2, curve->p, curve->ndigits);      /* t3 = (y2 - y1)^2 */
  vli_mod_sub(X2, X2, t6, curve->p, curve->ndigits); /* t3 = x3 */

  vli_mod_sub(t7, X1, X2, curve->p, curve->ndigits); /* t7 = B - x3 */
  vli_mod_mult_fast(Y2, Y2, t7, curve->p, curve->ndigits);    /* t4 = (y2 - y1)*(B - x3) */
  vli_mod_sub(Y2, Y2, Y1, curve->p, curve->ndigits); /* t4 = y3 */

  vli_mod_square_fast(t7, t5, curve->p, curve->ndigits);      /* t7 = (y2 + y1)^2 = F */
  vli_mod_sub(t7, t7, t6, curve->p, curve->ndigits); /* t7 = x3' */
  vli_mod_sub(t6, t7, X1, curve->p, curve->ndigits); /* t6 = x3' - B */
  vli_mod_mult_fast(t6, t6, t5, curve->p, curve->ndigits);    /* t6 = (y2 + y1)*(x3' - B) */
  vli_mod_sub(Y1, t6, Y1, curve->p, curve->ndigits); /* t2 = y3' */

  vli_set(X1, t7, curve->ndigits);
}

void ecc_point_mult(struct ecc_curve *curve, ecc_point *result, ecc_point *point, u64 *scalar, u64 *initialZ)
{
  /* R0 and R1 */
  u64 Rx[2][ECC_MAX_DIGITS];
  u64 Ry[2][ECC_MAX_DIGITS];
  u64 z[ECC_MAX_DIGITS];
  int i, nb;

  vli_set(Rx[1], point->x, curve->ndigits);
  vli_set(Ry[1], point->y, curve->ndigits);

  XYcZ_initial_double(curve, Rx[1], Ry[1], Rx[0], Ry[0], initialZ);

  for(i = vli_num_bits(scalar, curve->ndigits) - 2; i > 0; --i){
    nb = !vli_test_bit(scalar, i, curve->ndigits);
    XYcZ_addC(curve, Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);
    XYcZ_add(curve, Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);
  }

  nb = !vli_test_bit(scalar, 0, curve->ndigits);
  XYcZ_addC(curve, Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);

  /* Find final 1/Z value. */
  vli_mod_sub(z, Rx[1], Rx[0], curve->p, curve->ndigits); /* X1 - X0 */
  vli_mod_mult_fast(z, z, Ry[1-nb], curve->p, curve->ndigits);     /* Yb * (X1 - X0) */
  vli_mod_mult_fast(z, z, point->x, curve->p, curve->ndigits);   /* xP * Yb * (X1 - X0) */
  vli_mod_inv(z, z, curve->p, curve->ndigits);            /* 1 / (xP * Yb * (X1 - X0)) */
  vli_mod_mult_fast(z, z, point->y, curve->p, curve->ndigits);   /* yP / (xP * Yb * (X1 - X0)) */
  vli_mod_mult_fast(z, z, Rx[1-nb], curve->p, curve->ndigits);     /* Xb * yP / (xP * Yb * (X1 - X0)) */
  /* End 1/Z calculation */

  XYcZ_add(curve, Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);

  apply_z(curve, Rx[0], Ry[0], z);

  vli_set(result->x, Rx[0], curve->ndigits);
  vli_set(result->y, Ry[0], curve->ndigits);
}

static u32 max(u32 a, u32 b)
{
  return (a > b ? a : b);
}

void ecc_point_mult2(struct ecc_curve *curve, ecc_point *result, ecc_point *g, ecc_point *p, u64 *s, u64 *t)
{
  u64 tx[ECC_MAX_DIGITS];
  u64 ty[ECC_MAX_DIGITS];
  u64 tz[ECC_MAX_DIGITS];
  u64 z[ECC_MAX_DIGITS];
  ecc_point sum;
  u64 *rx;
  u64 *ry;
  int i;

  rx = result->x;
  ry = result->y;

  /* Calculate sum = G + Q. */
  vli_set(sum.x, p->x, curve->ndigits);
  vli_set(sum.y, p->y, curve->ndigits);
  vli_set(tx, g->x, curve->ndigits);
  vli_set(ty, g->y, curve->ndigits);

  vli_mod_sub(z, sum.x, tx, curve->p, curve->ndigits); /* Z = x2 - x1 */
  XYcZ_add(curve, tx, ty, sum.x, sum.y);
  vli_mod_inv(z, z, curve->p, curve->ndigits); /* Z = 1/Z */
  apply_z(curve, sum.x, sum.y, z);

  /* Use Shamir's trick to calculate u1*G + u2*Q */
  ecc_point *points[4] = {NULL, g, p, &sum};
  u32 numBits = max(vli_num_bits(s, curve->ndigits), vli_num_bits(t, curve->ndigits));

  ecc_point *point = points[(!!vli_test_bit(s, numBits-1, curve->ndigits))
        | ((!!vli_test_bit(t, numBits-1, curve->ndigits)) << 1)];
  vli_set(rx, point->x, curve->ndigits);
  vli_set(ry, point->y, curve->ndigits);
  vli_clear(z, curve->ndigits);
  z[0] = 1;

  for(i = numBits - 2; i >= 0; --i){
    ecc_point_double_jacobian(curve, rx, ry, z);

    int index = (!!vli_test_bit(s, i, curve->ndigits))
      | ((!!vli_test_bit(t, i, curve->ndigits)) << 1);
    ecc_point *point = points[index];
    if(point){
      vli_set(tx, point->x, curve->ndigits);
      vli_set(ty, point->y, curve->ndigits);
      apply_z(curve, tx, ty, z);
      vli_mod_sub(tz, rx, tx, curve->p, curve->ndigits); /* Z = x2 - x1 */
      XYcZ_add(curve, tx, ty, rx, ry);
      vli_mod_mult_fast(z, z, tz, curve->p, curve->ndigits);
    }
  }

  vli_mod_inv(z, z, curve->p, curve->ndigits); /* Z = 1/Z */
  apply_z(curve, rx, ry, z);
}

void ecc_point_add(struct ecc_curve *curve, ecc_point *result, ecc_point *left, ecc_point *right)
{
  u64 x1[ECC_MAX_DIGITS];
  u64 y1[ECC_MAX_DIGITS];
  u64 x2[ECC_MAX_DIGITS];
  u64 y2[ECC_MAX_DIGITS];
  u64 z[ECC_MAX_DIGITS];

  vli_set(x1, left->x, curve->ndigits);
  vli_set(y1, left->y, curve->ndigits);
  vli_set(x2, right->x, curve->ndigits);
  vli_set(y2, right->y, curve->ndigits);

  vli_mod_sub(z, x2, x1, curve->p, curve->ndigits); /* Z = x2 - x1 */

  XYcZ_add(curve, x1, y1, x2, y2);
  vli_mod_inv(z, z, curve->p, curve->ndigits); /* Z = 1/Z */
  apply_z(curve, x2,y2, z);

  vli_set(result->x, x2, curve->ndigits);
  vli_set(result->y, y2, curve->ndigits);
}

void ecc_bytes2native(u64 *native, void *bytes, u8 ndigits)
{
  u64 *_bytes = (u64*)bytes;
  unsigned int i;
  unsigned int le_int = 1;
  unsigned char* le_ch = (unsigned char*)(&le_int);

  //little endian
  if(*le_ch)
  {
    for(i = 0; i < ndigits/2; ++i){
      if(native == _bytes){
        u64 temp;
        temp = be64_to_le64(native[i]);
        native[i] = be64_to_le64(_bytes[ndigits - i - 1]);
        _bytes[ndigits - i - 1] = temp;
      }
      else{
        native[i] = be64_to_le64(_bytes[ndigits - i - 1]);
        native[ndigits - i - 1] = be64_to_le64(_bytes[i]);
      }
    }
  }
  //big endian
  else
  {
    for(i = 0; i < ndigits/2; ++i){
      if(native == _bytes){
        u64 temp;
        temp = native[i];
        native[i] = _bytes[ndigits - i - 1];
        _bytes[ndigits - i - 1] = temp;
      }
      else{
        native[i] = _bytes[ndigits - i - 1];
        native[ndigits - i - 1] = _bytes[i];
      }
    }
  }
}

void ecc_native2bytes(void *bytes, u64 *native, u8 ndigits)
{
  u64 *_bytes = (u64*)bytes;
  unsigned int i;
  unsigned int le_int = 1;
  unsigned char* le_ch = (unsigned char*)(&le_int);

  //little endian
  if(*le_ch)
  {
    for(i = 0; i < ndigits/2; ++i){
      if(_bytes == native){
        u64 temp;
        temp = le64_to_be64(_bytes[ndigits - i - 1]);
        _bytes[ndigits - i - 1] = le64_to_be64(native[i]);
        native[i] = temp;
      }
      else{
        _bytes[i] = le64_to_be64(native[ndigits - i - 1]);
        _bytes[ndigits - i - 1] = le64_to_be64(native[i]);
      }
    }
  }
  else
  //big endian
  {
    for(i = 0; i < ndigits/2; ++i){
      if(_bytes == native){
        u64 temp;
        temp = _bytes[ndigits - i - 1];
        _bytes[ndigits - i - 1] = native[i];
        native[i] = temp;
      }
      else{
        _bytes[i] = native[ndigits - i - 1];
        _bytes[ndigits - i - 1] = native[i];
      }
    }
  }
}
