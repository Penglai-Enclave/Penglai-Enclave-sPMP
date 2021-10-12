#ifndef __TYPEDEF_H__
#define __TYPEDEF_H__
#include "sbi/sbi_types.h"

typedef	unsigned char    u8;
typedef	unsigned short  u16;
typedef	unsigned int  u32;
typedef	unsigned int  uint;
// typedef	unsigned long long  u64;

typedef	char   s8;
typedef	short  s16;
typedef	int  s32;
// typedef	long long  s64;

#define be64_to_le64(x) ((u64)(				\
	(((u64)(x) & (u64)0x00000000000000ffULL) << 56) |	\
	(((u64)(x) & (u64)0x000000000000ff00ULL) << 40) |	\
	(((u64)(x) & (u64)0x0000000000ff0000ULL) << 24) |	\
	(((u64)(x) & (u64)0x00000000ff000000ULL) <<  8) |	\
	(((u64)(x) & (u64)0x000000ff00000000ULL) >>  8) |	\
	(((u64)(x) & (u64)0x0000ff0000000000ULL) >> 24) |	\
	(((u64)(x) & (u64)0x00ff000000000000ULL) >> 40) |	\
	(((u64)(x) & (u64)0xff00000000000000ULL) >> 56)))

#define le64_to_be64(x) ((u64)(				\
	(((u64)(x) & (u64)0x00000000000000ffULL) << 56) |	\
	(((u64)(x) & (u64)0x000000000000ff00ULL) << 40) |	\
	(((u64)(x) & (u64)0x0000000000ff0000ULL) << 24) |	\
	(((u64)(x) & (u64)0x00000000ff000000ULL) <<  8) |	\
	(((u64)(x) & (u64)0x000000ff00000000ULL) >>  8) |	\
	(((u64)(x) & (u64)0x0000ff0000000000ULL) >> 24) |	\
	(((u64)(x) & (u64)0x00ff000000000000ULL) >> 40) |	\
	(((u64)(x) & (u64)0xff00000000000000ULL) >> 56)))

static inline u16 __get_unaligned_le16(const u8 *p)
{
  return p[0] | p[1] << 8;
}

static inline u32 __get_unaligned_le32(const u8 *p)
{
  return p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24;
}

static inline u64 __get_unaligned_le64(const u8 *p)
{
  return (u64)__get_unaligned_le32(p + 4) << 32 
    | __get_unaligned_le32(p);
}

static inline void __put_unaligned_le16(u16 val, u8 *p)
{
  *p++ = val;
  *p++ = val >> 8;
}

static inline void __put_unaligned_le32(u32 val, u8 *p)
{
  __put_unaligned_le16(val >> 16, p + 2);
  __put_unaligned_le16(val, p);
}

static inline void __put_unaligned_le64(u64 val, u8 *p)
{
  __put_unaligned_le32(val >> 32, p + 4);
  __put_unaligned_le32(val, p);
}

static inline u16 get_unaligned_le16(const void *p)
{
  return __get_unaligned_le16((const u8 *)p);
}

static inline u32 get_unaligned_le32(const void *p)
{
  return __get_unaligned_le32((const u8 *)p);
}

static inline u64 get_unaligned_le64(const void *p)
{
  return __get_unaligned_le64((const u8 *)p);
}

static inline void put_unaligned_le16(u16 val, void *p)
{
  __put_unaligned_le16(val, p);
}

static inline void put_unaligned_le32(u32 val, void *p)
{
  __put_unaligned_le32(val, p);
}

static inline void put_unaligned_le64(u64 val, void *p)
{
  __put_unaligned_le64(val, p);
}

static inline u16 __get_unaligned_be16(const u8 *p)
{
  return p[0] << 8 | p[1];
}

static inline u32 __get_unaligned_be32(const u8 *p)
{
  return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
}

static inline u64 __get_unaligned_be64(const u8 *p)
{
  return (u64)__get_unaligned_be32(p) << 32 
    | __get_unaligned_be32(p + 4);
}

static inline void __put_unaligned_be16(u16 val, u8 *p)
{
  *p++ = val >> 8;
  *p++ = val;
}

static inline void __put_unaligned_be32(u32 val, u8 *p)
{
  __put_unaligned_be16(val >> 16, p);
  __put_unaligned_be16(val, p + 2);
}

static inline void __put_unaligned_be64(u64 val, u8 *p)
{
  __put_unaligned_be32(val >> 32, p);
  __put_unaligned_be32(val, p + 4);
}

static inline u16 get_unaligned_be16(const void *p)
{
  return __get_unaligned_be16((const u8 *)p);
}

static inline u32 get_unaligned_be32(const void *p)
{
  return __get_unaligned_be32((const u8 *)p);
}

static inline u64 get_unaligned_be64(const void *p)
{
  return __get_unaligned_be64((const u8 *)p);
}

static inline void put_unaligned_be16(u16 val, void *p)
{
  __put_unaligned_be16(val, p);
}

static inline void put_unaligned_be32(u32 val, void *p)
{
  __put_unaligned_be32(val, p);
}

static inline void put_unaligned_be64(u64 val, void *p)
{
  __put_unaligned_be64(val, p);
}

#endif
