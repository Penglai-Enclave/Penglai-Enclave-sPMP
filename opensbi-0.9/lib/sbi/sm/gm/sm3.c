#include "sm/gm/sm3.h"
#include "sbi/sbi_string.h"

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n, b, i)                     \
{                                                 \
  (n) = ( (unsigned long)(b)[(i)] << 24 )         \
  | ( (unsigned long)(b)[(i) + 1] << 16 )         \
  | ( (unsigned long)(b)[(i) + 2] << 8  )         \
  | ( (unsigned long)(b)[(i) + 3]       );        \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n, b, i)                     \
{                                                 \
  (b)[(i)] = (unsigned char)((n) >> 24);          \
  (b)[(i) + 1] = (unsigned char)((n) >> 16);      \
  (b)[(i) + 2] = (unsigned char)((n) >>  8);      \
  (b)[(i) + 3] = (unsigned char)((n));            \
}
#endif

/*
 * SM3 context setup
 */
void sm3_init(struct sm3_context *ctx)
{
  ctx->total[0] = 0;
  ctx->total[1] = 0;

  ctx->state[0] = 0x7380166F;
  ctx->state[1] = 0x4914B2B9;
  ctx->state[2] = 0x172442D7;
  ctx->state[3] = 0xDA8A0600;
  ctx->state[4] = 0xA96F30BC;
  ctx->state[5] = 0x163138AA;
  ctx->state[6] = 0xE38DEE4D;
  ctx->state[7] = 0xB0FB0E4E;
}

static void sm3_process(struct sm3_context *ctx, unsigned char data[64])
{
  unsigned long SS1, SS2, TT1, TT2, W[68], W1[64];
  unsigned long A, B, C, D, E, F, G, H;
  unsigned long T[64];
  unsigned long Temp1, Temp2, Temp3, Temp4, Temp5;
  int j;

  for(j = 0; j < 16; j++)
    T[j] = 0x79CC4519;
  for(j = 16; j < 64; j++)
    T[j] = 0x7A879D8A;

  GET_ULONG_BE(W[ 0], data,  0);
  GET_ULONG_BE(W[ 1], data,  4);
  GET_ULONG_BE(W[ 2], data,  8);
  GET_ULONG_BE(W[ 3], data, 12);
  GET_ULONG_BE(W[ 4], data, 16);
  GET_ULONG_BE(W[ 5], data, 20);
  GET_ULONG_BE(W[ 6], data, 24);
  GET_ULONG_BE(W[ 7], data, 28);
  GET_ULONG_BE(W[ 8], data, 32);
  GET_ULONG_BE(W[ 9], data, 36);
  GET_ULONG_BE(W[10], data, 40);
  GET_ULONG_BE(W[11], data, 44);
  GET_ULONG_BE(W[12], data, 48);
  GET_ULONG_BE(W[13], data, 52);
  GET_ULONG_BE(W[14], data, 56);
  GET_ULONG_BE(W[15], data, 60);

#define FF0(x,y,z) ((x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )

#define SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))

#define P0(x) ((x) ^  ROTL((x),9) ^ ROTL((x),17))
#define P1(x) ((x) ^  ROTL((x),15) ^ ROTL((x),23))

  for(j = 16; j < 68; j++ )
  {
    Temp1 = W[j - 16] ^ W[j - 9];
    Temp2 = ROTL(W[j - 3], 15);
    Temp3 = Temp1 ^ Temp2;
    Temp4 = P1(Temp3);
    Temp5 =  ROTL(W[j - 13], 7 ) ^ W[j - 6];
    W[j] = Temp4 ^ Temp5;
  }

  for(j = 0; j < 64; j++)
  {
    W1[j] = W[j] ^ W[j + 4];
  }

  A = ctx->state[0];
  B = ctx->state[1];
  C = ctx->state[2];
  D = ctx->state[3];
  E = ctx->state[4];
  F = ctx->state[5];
  G = ctx->state[6];
  H = ctx->state[7];

  for(j = 0; j < 16; j++)
  {
    SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
    SS2 = SS1 ^ ROTL(A, 12);
    TT1 = FF0(A, B, C) + D + SS2 + W1[j];
    TT2 = GG0(E, F, G) + H + SS1 + W[j];
    D = C;
    C = ROTL(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = ROTL(F, 19);
    F = E;
    E = P0(TT2);
  }

  for(j = 16; j < 64; j++)
  {
    SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
    SS2 = SS1 ^ ROTL(A, 12);
    TT1 = FF1(A, B, C) + D + SS2 + W1[j];
    TT2 = GG1(E, F, G) + H + SS1 + W[j];
    D = C;
    C = ROTL(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = ROTL(F, 19);
    F = E;
    E = P0(TT2);
  }

  ctx->state[0] ^= A;
  ctx->state[1] ^= B;
  ctx->state[2] ^= C;
  ctx->state[3] ^= D;
  ctx->state[4] ^= E;
  ctx->state[5] ^= F;
  ctx->state[6] ^= G;
  ctx->state[7] ^= H;
}

/*
 * SM3 process buffer
 */
void sm3_update(struct sm3_context *ctx, unsigned char *input, int ilen)
{
  int fill;
  unsigned long left;

  if(ilen <= 0)
    return;

  left = ctx->total[0] & 0x3F;
  fill = 64 - left;

  ctx->total[0] += ilen;
  ctx->total[0] &= 0xFFFFFFFF;

  if(ctx->total[0] < (unsigned long)ilen)
    ctx->total[1]++;

  if(left && ilen >= fill)
  {
    sbi_memcpy((void *)(ctx->buffer + left),
      (void *)input, fill);
    sm3_process(ctx, ctx->buffer);
    input += fill;
    ilen -= fill;
    left = 0;
  }

  while(ilen >= 64)
  {
    sm3_process( ctx, input );
    input += 64;
    ilen  -= 64;
  }

  if(ilen > 0)
  {
    sbi_memcpy((void*)(ctx->buffer + left),
      (void*)input, ilen);
  }
}

static const unsigned char sm3_padding[64] =
{
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * SM3 final digest
 */
void sm3_final(struct sm3_context *ctx, unsigned char output[32])
{
  unsigned long last, padn;
  unsigned long high, low;
  unsigned char msglen[8];

  high = (ctx->total[0] >> 29)
    | (ctx->total[1] << 3);
  low = (ctx->total[0] << 3);

  PUT_ULONG_BE( high, msglen, 0 );
  PUT_ULONG_BE( low,  msglen, 4 );

  last = ctx->total[0] & 0x3F;
  padn = (last < 56) ? (56 - last) : (120 - last);

  sm3_update( ctx, (unsigned char *) sm3_padding, padn );
  sm3_update( ctx, msglen, 8 );

  PUT_ULONG_BE( ctx->state[0], output,  0 );
  PUT_ULONG_BE( ctx->state[1], output,  4 );
  PUT_ULONG_BE( ctx->state[2], output,  8 );
  PUT_ULONG_BE( ctx->state[3], output, 12 );
  PUT_ULONG_BE( ctx->state[4], output, 16 );
  PUT_ULONG_BE( ctx->state[5], output, 20 );
  PUT_ULONG_BE( ctx->state[6], output, 24 );
  PUT_ULONG_BE( ctx->state[7], output, 28 );
}

/*
 * output = SM3( input buffer )
 */
void sm3(unsigned char *input, int ilen,
          unsigned char output[32])
{
  struct sm3_context ctx;

  sm3_init(&ctx);
  sm3_update(&ctx, input, ilen);
  sm3_final(&ctx, output);

  sbi_memset(&ctx, 0, sizeof(struct sm3_context));
}

/*
 * SM3 HMAC context setup
 */
void sm3_hmac_init(struct sm3_context *ctx, unsigned char *key, int keylen)
{
  int i;
  unsigned char sum[32];

  if(keylen > 64)
  {
    sm3(key, keylen, sum);
    keylen = 32;
    //keylen = ( is224 ) ? 28 : 32;
    key = sum;
  }

  sbi_memset(ctx->ipad, 0x36, 64);
  sbi_memset(ctx->opad, 0x5C, 64);

  for(i = 0; i < keylen; i++)
  {
    ctx->ipad[i] = (unsigned char)(ctx->ipad[i] ^ key[i]);
    ctx->opad[i] = (unsigned char)(ctx->opad[i] ^ key[i]);
  }

  sm3_init(ctx);
  sm3_update(ctx, ctx->ipad, 64);

  sbi_memset(sum, 0, sizeof(sum));
}

/*
 * SM3 HMAC process buffer
 */
void sm3_hmac_update(struct sm3_context *ctx, unsigned char *input, int ilen)
{
  sm3_update(ctx, input, ilen);
}

/*
 * SM3 HMAC final digest
 */
void sm3_hmac_final(struct sm3_context *ctx, unsigned char output[32])
{
  int hlen;
  unsigned char tmpbuf[32];

  //is224 = ctx->is224;
  hlen =  32;

  sm3_final(ctx, tmpbuf);
  sm3_init(ctx);
  sm3_update(ctx, ctx->opad, 64);
  sm3_update(ctx, tmpbuf, hlen);
  sm3_final(ctx, output);

  sbi_memset(tmpbuf, 0, sizeof(tmpbuf));
}

/*
 * output = HMAC-SM#( hmac key, input buffer )
 */
void sm3_hmac(unsigned char *key, int keylen,
    unsigned char *input, int ilen,
    unsigned char output[32])
{
  struct sm3_context ctx;

  sm3_hmac_init(&ctx, key, keylen);
  sm3_hmac_update(&ctx, input, ilen);
  sm3_hmac_final(&ctx, output);

  sbi_memset(&ctx, 0, sizeof(struct sm3_context));
}
