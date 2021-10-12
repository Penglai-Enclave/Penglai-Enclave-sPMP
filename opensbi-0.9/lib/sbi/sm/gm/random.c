#include "sm/gm/random.h"

int vli_get_random(u8 *data, u32 len)
{
  int ret = 0;

  //TODO: optimize it with real entropy machine
  /*srand(0x11223344);
  int i=0;
  for(i=0; i < sizeof(u32)/sizeof(u8); ++i)
  {
    *data = (u8)rand();
    data += 1;
  }*/
  *(u32*)data = 0x11223344;

  return ret;
}
