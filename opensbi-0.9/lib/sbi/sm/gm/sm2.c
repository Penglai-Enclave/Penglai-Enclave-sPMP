#include "sm/gm/random.h"
#include "sm/gm/big.h"
#include "sm/gm/ecc.h"
#include "sm/gm/sm2.h"
#include "sm/gm/sm3.h"
#include "sbi/sbi_string.h"

void *memset(void *s, int c, size_t count)
{
  return sbi_memset(s, c, count);
}

static int mem_cmp(char* s1, char* s2, int count)
{
  int i = 0;

  if(!s1 || !s2)
    return -1;

  for(; i< count; ++i)
  {
    if(*(s1 + i) != *(s2 + i))
      return -1;
  }

  return 0;
}

struct ecc_curve sm2_curve = {
  .ndigits = ECC_MAX_DIGITS,
  .g = {
    .x = {
      0x715A4589334C74C7ull, 0x8FE30BBFF2660BE1ull,
      0x5F9904466A39C994ull, 0x32C4AE2C1F198119ull
    },
    .y = {
      0x02DF32E52139F0A0ull, 0xD0A9877CC62A4740ull,
      0x59BDCEE36B692153ull, 0xBC3736A2F4F6779Cull
    },
  },
  .p = {
    0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFF00000000ull,
    0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFEFFFFFFFFull
  },
  .n = {
    0x53BBF40939D54123ull, 0x7203DF6B21C6052Bull,
    0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFEFFFFFFFFull
  },
  .h = {
    0x0000000000000001ull, 0x0000000000000000ull,
    0x0000000000000000ull, 0x0000000000000000ull,
  },
  .a = {
    0xFFFFFFFFFFFFFFFCull, 0xFFFFFFFF00000000ull,
    0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFEFFFFFFFFull
  },
  .b = {
    0xDDBCBD414D940E93ull, 0xF39789F515AB8F92ull,
    0x4D5A9E4BCF6509A7ull, 0x28E9FA9E9D9F5E34ull
  },
};

/*x¯2 = 2w + (x2&(2w − 1))*/
void sm2_w(u64 *result, u64 *x)
{
  result[0] = x[0];
  result[1] = x[1];
  result[1] |= 0x80;
  result[2] = 0;
  result[3] = 0;
}

void sm3_kdf(u8 *Z, u32 zlen, u8 *K, u32 klen)
{
  u32 ct = 0x00000001;
  u8 ct_char[32];
  u8 *hash = K;
  u32 i, t;
  struct sm3_context md[1];

  t = klen/ECC_NUMWORD;
  //s4: K=Ha1||Ha2||...
  for(i = 0; i < t; i++){
    //s2: Hai=Hv(Z||ct)
    sm3_init(md);
    sm3_update(md, Z, zlen);
    put_unaligned_be32(ct, ct_char);
    sm3_update(md, ct_char, 4);
    sm3_final(md, hash);
    hash += 32;
    ct++;
  }

  t = klen % ECC_NUMBITS;
  if(t){
    sm3_init(md);
    sm3_update(md, Z, zlen);
    put_unaligned_be32(ct, ct_char);
    sm3_update(md, ct_char, 4);
    sm3_final(md, ct_char);
    sbi_memcpy(hash, ct_char, t);
  }
}

void sm3_z(u8 *id, u32 idlen, ecc_point *pub, u8 *hash)
{
  u8 a[ECC_NUMWORD];
  u8 b[ECC_NUMWORD];
  u8 x[ECC_NUMWORD];
  u8 y[ECC_NUMWORD];
  u8 idlen_char[2];
  struct sm3_context md[1];

  put_unaligned_be16(idlen<<3, idlen_char);

  ecc_bytes2native((u64*)a, sm2_curve.a, sm2_curve.ndigits);
  ecc_bytes2native((u64*)b, sm2_curve.b, sm2_curve.ndigits);
  ecc_bytes2native((u64*)x, sm2_curve.g.x, sm2_curve.ndigits);
  ecc_bytes2native((u64*)y, sm2_curve.g.y, sm2_curve.ndigits);

  sm3_init(md);
  sm3_update(md, idlen_char, 2);
  sm3_update(md, id, idlen);
  sm3_update(md, a, ECC_NUMWORD);
  sm3_update(md, b, ECC_NUMWORD);
  sm3_update(md, x, ECC_NUMWORD);
  sm3_update(md, y, ECC_NUMWORD);
  sm3_update(md, (u8*)pub->x, ECC_NUMWORD);
  sm3_update(md, (u8*)pub->y, ECC_NUMWORD);
  sm3_final(md, hash);

  return;
}

int sm2_valid_public_key(ecc_point *publicKey)
{
  u64 na[ECC_MAX_DIGITS] = {3}; /* a mod p = (-3) mod p */
  u64 tmp1[ECC_MAX_DIGITS];
  u64 tmp2[ECC_MAX_DIGITS];

  if(ecc_point_is_zero(&sm2_curve, publicKey))
    return 1;

  if(vli_cmp(sm2_curve.p, publicKey->x, sm2_curve.ndigits) != 1 
      || vli_cmp(sm2_curve.p, publicKey->y, sm2_curve.ndigits) != 1)
    return 1;

  /* tmp1 = y^2 */
  vli_mod_square_fast(tmp1, publicKey->y, sm2_curve.p, sm2_curve.ndigits);
  /* tmp2 = x^2 */
  vli_mod_square_fast(tmp2, publicKey->x, sm2_curve.p, sm2_curve.ndigits);
  /* tmp2 = x^2 + a = x^2 - 3 */
  vli_mod_sub(tmp2, tmp2, na, sm2_curve.p, sm2_curve.ndigits);
  /* tmp2 = x^3 + ax */
  vli_mod_mult_fast(tmp2, tmp2, publicKey->x, sm2_curve.p, sm2_curve.ndigits);
  /* tmp2 = x^3 + ax + b */
  vli_mod_add(tmp2, tmp2, sm2_curve.b, sm2_curve.p, sm2_curve.ndigits);

  /* Make sure that y^2 == x^3 + ax + b */
  if(vli_cmp(tmp1, tmp2, sm2_curve.ndigits) != 0)
    return 1;

  return 0;
}

int sm2_make_prikey(u8 *prikey)
{
  u64 pri[ECC_MAX_DIGITS];
  int i = 10;

  do{
    vli_get_random((u8*)pri, ECC_NUMWORD);
    if(vli_cmp(sm2_curve.n, pri, sm2_curve.ndigits) != 1){
      vli_sub(pri, pri, sm2_curve.n, sm2_curve.ndigits);
    }

    /* The private key cannot be 0 (mod p). */
    if(!vli_is_zero(pri, sm2_curve.ndigits)){
      ecc_native2bytes(prikey, pri, sm2_curve.ndigits);
      return 0;
    }
  }while(i--);

  return -1;
}

int sm2_make_pubkey(u8 *prikey, ecc_point *pubkey)
{
  ecc_point pub[1];
  u64 pri[ECC_MAX_DIGITS];

  ecc_bytes2native(pri, prikey, sm2_curve.ndigits);
  ecc_point_mult(&sm2_curve, pub, &sm2_curve.g, pri, NULL);
  ecc_native2bytes(pubkey->x, pub->x, sm2_curve.ndigits);
  ecc_native2bytes(pubkey->y, pub->y, sm2_curve.ndigits);

  return 0;
}

int sm2_make_keypair(u8 *prikey, ecc_point *pubkey)
{
  sm2_make_prikey(prikey);
  sm2_make_pubkey(prikey, pubkey);
  return 0;
}

int sm2_point_mult(ecc_point *G, u8 *k, ecc_point *P)
{
  int rc = 0;

  ecc_point G_[1];
  ecc_point P_[1];
  u64 k_[ECC_MAX_DIGITS];

  ecc_bytes2native(k_, k, sm2_curve.ndigits);
  ecc_bytes2native(G_->x, G->x, sm2_curve.ndigits);
  ecc_bytes2native(G_->y, G->y, sm2_curve.ndigits);

  ecc_point_mult(&sm2_curve, P_, G_, k_, NULL);

  ecc_native2bytes(P->x, P_->x, sm2_curve.ndigits);
  ecc_native2bytes(P->y, P_->y, sm2_curve.ndigits);

  return rc;
}

int sm2_sign(u8 *r_, u8 *s_, u8 *prikey, u8 *hash_)
{
  u64 k[ECC_MAX_DIGITS];
  u64 one[ECC_MAX_DIGITS] = {1};
  u64 random[ECC_MAX_DIGITS];
  u64 pri[ECC_MAX_DIGITS];
  u64 hash[ECC_MAX_DIGITS];
  u64 r[ECC_MAX_DIGITS];
  u64 s[ECC_MAX_DIGITS];

  ecc_point p;

  ecc_bytes2native(pri, prikey, sm2_curve.ndigits);
  ecc_bytes2native(hash, hash_, sm2_curve.ndigits);

  vli_get_random((u8*)random, ECC_NUMWORD);
  if(vli_is_zero(random, sm2_curve.ndigits)){
    /* The random number must not be 0. */
    return 0;
  }

  vli_set(k, random, sm2_curve.ndigits);
  if(vli_cmp(sm2_curve.n, k, sm2_curve.ndigits) != 1){
    vli_sub(k, k, sm2_curve.n, sm2_curve.ndigits);
  }

  /* tmp = k * G */
  ecc_point_mult(&sm2_curve, &p, &sm2_curve.g, k, NULL);

  /* r = x1 + e (mod n) */
  vli_mod_add(r, p.x, hash, sm2_curve.n, sm2_curve.ndigits);
  if(vli_cmp(sm2_curve.n, r, sm2_curve.ndigits) != 1){
    vli_sub(r, r, sm2_curve.n, sm2_curve.ndigits);
  }

  if(vli_is_zero(r, sm2_curve.ndigits)){
    /* If r == 0, fail (need a different random number). */
    return 0;
  }

  /* s = r*d */
  vli_mod_mult(s, r, pri, sm2_curve.n, sm2_curve.ndigits);
  /* k-r*d */
  vli_mod_sub(s, k, s, sm2_curve.n, sm2_curve.ndigits);
  /* 1+d */
  vli_mod_add(pri, pri, one, sm2_curve.n, sm2_curve.ndigits);
  /* (1+d)' */
  vli_mod_inv(pri, pri, sm2_curve.n, sm2_curve.ndigits);
  /* (1+d)'*(k-r*d) */
  vli_mod_mult(s, pri, s, sm2_curve.n, sm2_curve.ndigits);

  ecc_native2bytes(r_, r, sm2_curve.ndigits);
  ecc_native2bytes(s_, s, sm2_curve.ndigits);

  return 1;
}

int sm2_verify(ecc_point *pubkey, u8 *hash_, u8 *r_, u8 *s_)
{
  ecc_point result;
  ecc_point pub[1];
  u64 t[ECC_MAX_DIGITS];
  u64 r[ECC_MAX_DIGITS];
  u64 s[ECC_MAX_DIGITS];
  u64 hash[ECC_MAX_DIGITS];

  ecc_bytes2native(pub->x, pubkey->x, sm2_curve.ndigits);
  ecc_bytes2native(pub->y, pubkey->y, sm2_curve.ndigits);
  ecc_bytes2native(r, r_, sm2_curve.ndigits);
  ecc_bytes2native(s, s_, sm2_curve.ndigits);
  ecc_bytes2native(hash, hash_, sm2_curve.ndigits);

  if(vli_is_zero(r, sm2_curve.ndigits) || vli_is_zero(s, sm2_curve.ndigits)){
    /* r, s must not be 0. */
    return -1;
  }

  if(vli_cmp(sm2_curve.n, r, sm2_curve.ndigits) != 1
      || vli_cmp(sm2_curve.n, s, sm2_curve.ndigits) != 1){
    /* r, s must be < n. */
    return -1;
  }

  vli_mod_add(t, r, s, sm2_curve.n, sm2_curve.ndigits); // r + s
  if(t == 0)
    return -1;

  ecc_point_mult2(&sm2_curve, &result, &sm2_curve.g, pub, s, t);

  /* v = x1 + e (mod n) */
  vli_mod_add(result.x, result.x, hash, sm2_curve.n, sm2_curve.ndigits);

  if(vli_cmp(sm2_curve.n, result.x, sm2_curve.ndigits) != 1){
    vli_sub(result.x, result.x, sm2_curve.n, sm2_curve.ndigits);
  }

  /* Accept only if v == r. */
  return vli_cmp(result.x, r, sm2_curve.ndigits);
}

int sm2_encrypt(ecc_point *pubKey, u8 *M, u32 Mlen, u8 *C, u32 *Clen)
{
  u64 k[ECC_MAX_DIGITS];
  u8 t[SM3_DATA_LEN];
  ecc_point pub[1];
  ecc_point *C1 = (ecc_point *)C;
  u8 *C2 = C + ECC_NUMWORD*2;
  u8 *C3 = C + ECC_NUMWORD*2 + Mlen;

  ecc_point kP;
  u8 *x2 = (u8*)kP.x;
  u8 *y2 = (u8*)kP.y;
  u8 *x2y2 = (u8*)kP.x;
  struct sm3_context md[1];
  int i=0;

  ecc_bytes2native(pub->x, pubKey->x, sm2_curve.ndigits);
  ecc_bytes2native(pub->y, pubKey->y, sm2_curve.ndigits);

  vli_get_random((u8*)k, ECC_NUMWORD);

  /* C1 = k * G */
  ecc_point_mult(&sm2_curve, C1, &sm2_curve.g, k, NULL);
  ecc_native2bytes(C1->x, C1->x, sm2_curve.ndigits);
  ecc_native2bytes(C1->y, C1->y, sm2_curve.ndigits);

  /* S = h * Pb */
  ecc_point S;
  ecc_point_mult(&sm2_curve, &S, pub, sm2_curve.h, NULL);
  if(sm2_valid_public_key(&S) != 0)
    return -1;

  /* kP = k * Pb */
  ecc_point_mult(&sm2_curve, &kP, pub, k, NULL);
  if(vli_is_zero(kP.x, sm2_curve.ndigits)
      | vli_is_zero(kP.y, sm2_curve.ndigits)){
    return 0;
  }
  ecc_native2bytes(kP.x, kP.x, sm2_curve.ndigits);
  ecc_native2bytes(kP.y, kP.y, sm2_curve.ndigits);

  /* t=KDF(x2 ∥ y2, klen) */
  sm3_kdf(x2y2, ECC_NUMWORD*2, t, Mlen);

  /* C2 = M ⊕ t；*/
  for(i = 0; i < Mlen; i++){
    C2[i] = M[i]^t[+i];
  }

  /*C3 = Hash(x2 ∥ M ∥ y2)*/
  sm3_init(md);
  sm3_update(md, x2, ECC_NUMWORD);
  sm3_update(md, M, Mlen);
  sm3_update(md, y2, ECC_NUMWORD);
  sm3_final(md, C3);

  if(Clen)
    *Clen = Mlen + ECC_NUMWORD*2 + SM3_DATA_LEN;

  return 0;
}

int sm2_decrypt(u8 *prikey, u8 *C, u32 Clen, u8 *M, u32 *Mlen)
{
  u8 hash[SM3_DATA_LEN];
  u64 pri[ECC_MAX_DIGITS];
  ecc_point *C1 = (ecc_point *)C;
  u8 *C2 = C + ECC_NUMWORD*2;
  u8 *C3 = C + Clen - SM3_DATA_LEN;
  ecc_point dB;
  u64 *x2 = dB.x;
  u64 *y2 = dB.y;
  u64 *x2y2 = x2;
  struct sm3_context md[1];
  int outlen = Clen - ECC_NUMWORD*2 - SM3_DATA_LEN;
  int i=0;

  ecc_bytes2native(pri, prikey, sm2_curve.ndigits);
  ecc_bytes2native(C1->x, C1->x, sm2_curve.ndigits);
  ecc_bytes2native(C1->y, C1->y, sm2_curve.ndigits);

  if(sm2_valid_public_key(C1) != 0)
    return -1;

  ecc_point S;
  ecc_point_mult(&sm2_curve, &S, C1, sm2_curve.h, NULL);
  if(sm2_valid_public_key(&S) != 0)
    return -1;

  ecc_point_mult(&sm2_curve, &dB, C1, pri, NULL);
  ecc_native2bytes(x2, x2, sm2_curve.ndigits);
  ecc_native2bytes(y2, y2, sm2_curve.ndigits);

  sm3_kdf((u8*)x2y2, ECC_NUMWORD*2, M, outlen);
  if(vli_is_zero(x2, sm2_curve.ndigits)
      | vli_is_zero(y2, sm2_curve.ndigits)){
    return 0;
  }

  for(i = 0; i < outlen; i++)
    M[i]=M[i]^C2[i];

  sm3_init(md);
  sm3_update(md, (u8*)x2, ECC_NUMWORD);
  sm3_update(md, M, outlen);
  sm3_update(md, (u8*)y2, ECC_NUMWORD);
  sm3_final(md, hash);

  *Mlen = outlen;
  if(mem_cmp((void*)hash , (void*)C3, SM3_DATA_LEN) != 0)
    return -1;
  else
    return 0;
}

int sm2_shared_point(u8* selfPriKey,  u8* selfTempPriKey, ecc_point* selfTempPubKey,
    ecc_point *otherPubKey, ecc_point* otherTempPubKey, ecc_point *key)
{
  ecc_point selfTempPub;
  ecc_point otherTempPub;
  ecc_point otherPub;
  ecc_point U[1];

  u64 selfTempPri[ECC_MAX_DIGITS];
  u64 selfPri[ECC_MAX_DIGITS];
  u64 temp1[ECC_MAX_DIGITS];
  u64 temp2[ECC_MAX_DIGITS];
  u64 tA[ECC_MAX_DIGITS];

  ecc_bytes2native(selfTempPri, selfTempPriKey, sm2_curve.ndigits);
  ecc_bytes2native(selfPri, selfPriKey, sm2_curve.ndigits);
  ecc_bytes2native(selfTempPub.x, selfTempPubKey->x, sm2_curve.ndigits);
  ecc_bytes2native(selfTempPub.y, selfTempPubKey->y, sm2_curve.ndigits);
  ecc_bytes2native(otherTempPub.x, otherTempPubKey->x, sm2_curve.ndigits);
  ecc_bytes2native(otherTempPub.y, otherTempPubKey->y, sm2_curve.ndigits);
  ecc_bytes2native(otherPub.x, otherPubKey->x, sm2_curve.ndigits);
  ecc_bytes2native(otherPub.y, otherPubKey->y, sm2_curve.ndigits);

  /***********x1_=2^w+x2 & (2^w-1)*************/
  sm2_w(temp1, selfTempPub.x);
  /***********tA=(dA+x1_*rA)mod n *************/
  vli_mod_mult(temp1, selfTempPri, temp1, sm2_curve.n, sm2_curve.ndigits);
  vli_mod_add(tA, selfPri, temp1, sm2_curve.n, sm2_curve.ndigits);
  /***********x2_=2^w+x2 & (2^w-1)*************/
  if(sm2_valid_public_key(&otherTempPub) != 0)
    return -1;
  sm2_w(temp2, otherTempPub.x);
  /**************U=[h*tA](PB+[x2_]RB)**********/
  /* U=[x2_]RB */
  ecc_point_mult(&sm2_curve, U, &otherTempPub, temp2, NULL);
  /*U=PB+U*/
  ecc_point_add(&sm2_curve, U, &otherPub, U);
  /*tA=tA*h */
  vli_mod_mult(tA, tA, sm2_curve.h, sm2_curve.n, sm2_curve.ndigits);
  ecc_point_mult(&sm2_curve, U, U,tA, NULL);

  ecc_native2bytes(key->x, U->x, sm2_curve.ndigits);
  ecc_native2bytes(key->y, U->y, sm2_curve.ndigits);

  return 0;
}

int sm2_shared_key(ecc_point *point, u8 *ZA, u8 *ZB, u32 keyLen, u8 *key)
{
  u8 Z[ECC_NUMWORD*4];
  sbi_memcpy(Z, point->x, ECC_NUMWORD);
  sbi_memcpy(Z + ECC_NUMWORD, point->y, ECC_NUMWORD);
  sbi_memcpy(Z + ECC_NUMWORD*2, ZA, ECC_NUMWORD);
  sbi_memcpy(Z + ECC_NUMWORD*3, ZB, ECC_NUMWORD);
  sm3_kdf(Z, ECC_NUMWORD*4, key, keyLen);
  
  return 0;
}

/****hash = Hash(Ux||ZA||ZB||x1||y1||x2||y2)****/
int ECC_Key_ex_hash1(u8* x, ecc_point *RA, ecc_point* RB, u8 ZA[],u8 ZB[],u8 *hash)
{
  struct sm3_context md[1];

  sm3_init(md);
  sm3_update(md, x, ECC_NUMWORD);
  sm3_update(md, ZA, ECC_NUMWORD);
  sm3_update(md, ZB, ECC_NUMWORD);
  sm3_update(md, (u8*)RA->x, ECC_NUMWORD);
  sm3_update(md, (u8*)RA->y, ECC_NUMWORD);
  sm3_update(md, (u8*)RB->x, ECC_NUMWORD);
  sm3_update(md, (u8*)RB->y, ECC_NUMWORD);
  sm3_final(md, (u8*)hash);

  return 0;
}

/****SA = Hash(temp||Uy||Hash)****/
int ECC_Key_ex_hash2(u8 temp, u8* y,u8 *hash, u8* SA)
{
  struct sm3_context md[1];

  sm3_init(md);
  sm3_update(md, &temp,1);
  sm3_update(md, y,ECC_NUMWORD);
  sm3_update(md, hash,ECC_NUMWORD);
  sm3_final(md, SA);

  return 0;
}

int ECC_KeyEx_Init_I(u8 *pri, ecc_point *pub)
{
  return sm2_make_pubkey(pri, pub);
}

int ECC_KeyEx_Re_I(u8 *rb, u8 *dB, ecc_point *RA, ecc_point *PA, u8* ZA, u8 *ZB, u8 *K, u32 klen, ecc_point *RB, ecc_point *V, u8* SB)
{
  u8 Z[ECC_NUMWORD*2 + ECC_NUMBITS/4]={0};
  u8 hash[ECC_NUMWORD];
  u8 temp=0x02;

  //--------B2: RB=[rb]G=(x2,y2)--------
  sm2_make_pubkey(rb, RB);
  /********************************************/
  sm2_shared_point(dB,  rb, RB, PA, RA, V);
  //------------B7:KB=KDF(VX,VY,ZA,ZB,KLEN)----------
  sbi_memcpy(Z, V->x, ECC_NUMWORD);
  sbi_memcpy(Z+ECC_NUMWORD, (u8*)V->y, ECC_NUMWORD);
  sbi_memcpy(Z+ECC_NUMWORD*2, ZA,ECC_NUMWORD);
  sbi_memcpy(Z+ECC_NUMWORD*3, ZB,ECC_NUMWORD);
  sm3_kdf(Z,ECC_NUMWORD*4, K, klen);
  //---------------B8:(optional) SB=hash(0x02||Vy||HASH(Vx||ZA||ZB||x1||y1||x2||y2)-------------
  ECC_Key_ex_hash1((u8*)V->x,  RA, RB, ZA, ZB, hash);
  ECC_Key_ex_hash2(temp, (u8*)V->y, hash, SB);

  return 0;
}

int ECC_KeyEx_Init_II(u8* ra, u8* dA, ecc_point* RA, ecc_point* RB, ecc_point* PB, u8
    ZA[],u8 ZB[],u8 SB[],u8 K[], u32 klen,u8 SA[])
{
  u8 Z[ECC_NUMWORD*2 + ECC_NUMWORD*2]={0};
  u8 hash[ECC_NUMWORD],S1[ECC_NUMWORD];
  u8 temp[2]={0x02,0x03};
  ecc_point U[1];

  /********************************************/
  sm2_shared_point(dA, ra, RA, PB, RB, U);
  /************KA=KDF(UX,UY,ZA,ZB,KLEN)**********/
  sbi_memcpy(Z, U->x,ECC_NUMWORD);
  sbi_memcpy(Z+ECC_NUMWORD, U->y,ECC_NUMWORD);
  sbi_memcpy(Z+ECC_NUMWORD*2,ZA,ECC_NUMWORD);
  sbi_memcpy(Z+ECC_NUMWORD*2 +ECC_NUMWORD ,ZB,ECC_NUMWORD);
  sm3_kdf(Z,ECC_NUMWORD*2+ECC_NUMWORD*2, K, klen);
  /****S1 = Hash(0x02||Uy||Hash(Ux||ZA||ZB||x1||y1||x2||y2))****/
  ECC_Key_ex_hash1((u8*)U->x,  RA, RB, ZA, ZB, hash);
  ECC_Key_ex_hash2(temp[0], (u8*)U->y, hash, S1);
  /*test S1=SB?*/
  if(mem_cmp((void*)S1, (void*)SB, ECC_NUMWORD)!=0)
    return -1;
  /*SA = Hash(0x03||yU||Hash(xU||ZA||ZB||x1||y1||x2||y2)) */
  ECC_Key_ex_hash2(temp[1], (u8*)U->y, hash, SA);

  return 0;
}

int ECC_KeyEx_Re_II(ecc_point *V, ecc_point *RA, ecc_point *RB, u8 ZA[], u8 ZB[], u8 SA[])
{
  u8 hash[ECC_NUMWORD];
  u8 S2[ECC_NUMWORD];
  u8 temp=0x03;

  /*S2 = Hash(0x03||Vy||Hash(Vx||ZA||ZB||x1||y1||x2||y2))*/
  ECC_Key_ex_hash1((u8*)V->x,  RA, RB, ZA, ZB, hash);
  ECC_Key_ex_hash2(temp, (u8*)V->y, hash, S2);

  if(mem_cmp((void*)S2, (void*)SA, ECC_NUMWORD)!=0)
    return -1;

  return 0;
}
