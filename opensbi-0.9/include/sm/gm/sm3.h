#ifndef _SM3_H
#define _SM3_H

#include "sm/gm/typedef.h"

#define SM3_DATA_LEN    32

/**
 * \brief          SM3 context structure
 */
struct sm3_context
{
  unsigned long total[2];     /*!< number of bytes processed  */
  unsigned long state[8];     /*!< intermediate digest state  */
  unsigned char buffer[64];   /*!< data block being processed */

  unsigned char ipad[64];     /*!< HMAC: inner padding        */
  unsigned char opad[64];     /*!< HMAC: outer padding        */
};

/**
 * \brief          SM3 context setup
 *
 * \param ctx      context to be initialized
 */
void sm3_init(struct sm3_context *ctx);

/**
 * \brief          SM3 process buffer
 *
 * \param ctx      SM3 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void sm3_update(struct sm3_context *ctx, unsigned char *input, int ilen);

/**
 * \brief          SM3 final digest
 *
 * \param ctx      SM3 context
 */
void sm3_final(struct sm3_context *ctx, unsigned char output[32]);

/**
 * \brief          Output = SM3( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   SM3 checksum result
 */
void sm3(unsigned char *input, int ilen, unsigned char output[32]);

/**
 * \brief          Output = SM3( file contents )
 *
 * \param path     input file name
 * \param output   SM3 checksum result
 *
 * \return         0 if successful, 1 if fopen failed,
 *                 or 2 if fread failed
 */
int sm3_file(char *path, unsigned char output[32]);

/**
 * \brief          SM3 HMAC context setup
 *
 * \param ctx      HMAC context to be initialized
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 */
void sm3_hmac_init(struct sm3_context *ctx, unsigned char *key, int keylen);

/**
 * \brief          SM3 HMAC process buffer
 *
 * \param ctx      HMAC context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void sm3_hmac_update(struct sm3_context *ctx, unsigned char *input, int ilen);

/**
 * \brief          SM3 HMAC final digest
 *
 * \param ctx      HMAC context
 * \param output   SM3 HMAC checksum result
 */
void sm3_hmac_final(struct sm3_context *ctx, unsigned char output[32]);

/**
 * \brief          Output = HMAC-SM3( hmac key, input buffer )
 *
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   HMAC-SM3 result
 */
void sm3_hmac(unsigned char *key, int keylen,
    unsigned char *input, int ilen,
    unsigned char output[32]);

#endif /* _SM3_H */
