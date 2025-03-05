#include <sm/platform/spmp/spmp.h>
#include <sm/ipi.h>
#include <stddef.h>

void set_spmp(int spmp_idx, struct spmp_config_t spmp_cfg_t)
{
#if 0
  uintptr_t spmp_address = 0;
  uintptr_t old_config = 0;
  uintptr_t spmp_config = ((spmp_cfg_t.mode & SPMP_A) | (spmp_cfg_t.perm & (SPMP_R|SPMP_W|SPMP_X)))
    << ((uintptr_t)SPMPCFG_BIT_NUM * (spmp_idx % SPMP_PER_CFG_REG));

  switch(spmp_cfg_t.mode)
  {
    case SPMP_NAPOT:
      if(spmp_cfg_t.paddr == 0 && spmp_cfg_t.size == -1UL)
        spmp_address = -1UL;
      else
        spmp_address = (spmp_cfg_t.paddr | ((spmp_cfg_t.size>>1)-1)) >> 2;
      break;
    case SPMP_TOR:
      spmp_address = spmp_cfg_t.paddr;
    case SPMP_NA4:
      spmp_address = spmp_cfg_t.paddr;
    case SPMP_OFF:
      spmp_address = 0;
    default:
      break;
  }

  switch(spmp_idx)
  {
    case 0:
      old_config = read_spmpcfg(spmpcfg0);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(0%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr0, spmpcfg0, spmp_address, spmp_config);
      break;
    case 1:
      old_config = read_spmpcfg(spmpcfg0);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(1%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr1, spmpcfg0, spmp_address, spmp_config);
     break;
    case 2:
      old_config = read_spmpcfg(spmpcfg0);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(2%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr2, spmpcfg0, spmp_address, spmp_config);
     break;
    case 3:
      old_config = read_spmpcfg(spmpcfg0);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(3%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr3, spmpcfg0, spmp_address, spmp_config);
     break;
    case 4:
      old_config = read_spmpcfg(spmpcfg0);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(4%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr4, spmpcfg0, spmp_address, spmp_config);
     break;
    case 5:
      old_config = read_spmpcfg(spmpcfg0);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(5%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr5, spmpcfg0, spmp_address, spmp_config);
     break;
    case 6:
      old_config = read_spmpcfg(spmpcfg0);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(6%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr6, spmpcfg0, spmp_address, spmp_config);
     break;
    case 7:
      old_config = read_spmpcfg(spmpcfg0);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(7%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr7, spmpcfg0, spmp_address, spmp_config);
     break;
    default:
      break;
  }
#endif
  return;
}

void clear_spmp(int spmp_idx)
{
#if 0
  struct spmp_config_t spmp_cfg;

  spmp_cfg.mode = SPMP_OFF;
  spmp_cfg.perm = SPMP_NO_PERM;
  spmp_cfg.paddr = 0;
  spmp_cfg.size = 0;
  set_spmp(spmp_idx, spmp_cfg);
#endif
  return;
}

struct spmp_config_t get_spmp(int spmp_idx)
{
  struct spmp_config_t spmp={0,};
#if 0
  uintptr_t spmp_address = 0;
  uintptr_t spmp_config = 0;
  unsigned long order = 0;
  unsigned long size = 0;

  switch(spmp_idx)
  {
    case 0:
      SPMP_READ(spmpaddr0, spmpcfg0, spmp_address, spmp_config);
      break;
    case 1:
      SPMP_READ(spmpaddr1, spmpcfg0, spmp_address, spmp_config);
      break;
    case 2:
      SPMP_READ(spmpaddr2, spmpcfg0, spmp_address, spmp_config);
      break;
    case 3:
      SPMP_READ(spmpaddr3, spmpcfg0, spmp_address, spmp_config);
      break;
    case 4:
      SPMP_READ(spmpaddr4, spmpcfg0, spmp_address, spmp_config);
      break;
    case 5:
      SPMP_READ(spmpaddr5, spmpcfg0, spmp_address, spmp_config);
      break;
    case 6:
      SPMP_READ(spmpaddr6, spmpcfg0, spmp_address, spmp_config);
      break;
    case 7:
      SPMP_READ(spmpaddr7, spmpcfg0, spmp_address, spmp_config);
      break;
    default:
      break;
  }

  spmp_config >>= (uintptr_t)SPMPCFG_BIT_NUM * (spmp_idx % SPMP_PER_CFG_REG);
  spmp_config &= SPMPCFG_BITS;
  switch(spmp_config & SPMP_A)
  {
    case SPMP_NAPOT:
      while(spmp_address & 1)
      {
        order += 1;
        spmp_address >>= 1;
      }
      order += 3;
      size = 1 << order;
      spmp_address <<= (order-1);
      break;
    case SPMP_NA4:
      size = 4;
    case SPMP_TOR:
      break;
    case SPMP_OFF:
      spmp_address = 0;
      size = 0;
      break;
  }

  spmp.mode = spmp_config & SPMP_A;
  spmp.perm = spmp_config & (SPMP_R | SPMP_W | SPMP_X);
  spmp.paddr = spmp_address;
  spmp.size = size;
#endif
  return spmp;
}
