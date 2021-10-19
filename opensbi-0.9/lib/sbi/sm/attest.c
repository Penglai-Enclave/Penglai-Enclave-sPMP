#include "sm/attest.h"
#include "sm/gm/sm3.h"
#include "sm/gm/sm2.h"
#include "sbi/riscv_encoding.h"
#include "sbi/sbi_string.h"

static int hash_enclave_mem(struct sm3_context *hash_ctx, pte_t* ptes, int level, uintptr_t va, int hash_va)
{
  uintptr_t pte_per_page = RISCV_PGSIZE/sizeof(pte_t);
  pte_t *pte;
  uintptr_t i = 0;
  int hash_curr_va = hash_va;

  //should never happen
  if(level <= 0)
    return 1;

  for(pte = ptes, i = 0; i < pte_per_page; pte += 1, i += 1)
  {
    if(!(*pte & PTE_V))
    {
      hash_curr_va = 1;
      continue;
    }

    uintptr_t curr_va = 0;
    if(level == ((VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS))
      curr_va = (uintptr_t)(-1UL << VA_BITS) + (i << (VA_BITS - RISCV_PGLEVEL_BITS));
    else
      curr_va = va + (i << ((level-1) * RISCV_PGLEVEL_BITS + RISCV_PGSHIFT));
    uintptr_t pa = (*pte >> PTE_PPN_SHIFT) << RISCV_PGSHIFT;

    //found leaf pte
    if((*pte & PTE_R) || (*pte & PTE_X))
    {
      if(hash_curr_va)
      {
        sm3_update(hash_ctx, (unsigned char*)&curr_va, sizeof(uintptr_t));
        //update hash with  page attribution
        sm3_update(hash_ctx, (unsigned char*)pte+7, 1);
        hash_curr_va = 0;
      }

      //4K page
      if(level == 1)
      {
        sm3_update(hash_ctx, (void*)pa, 1 << RISCV_PGSHIFT);
      }
      //2M page
      else if(level == 2)
      {
        sm3_update(hash_ctx, (void*)pa, 1 << (RISCV_PGSHIFT + RISCV_PGLEVEL_BITS));
      }
    }
    else
    {
      hash_curr_va = hash_enclave_mem(hash_ctx, (pte_t*)pa, level - 1, curr_va, hash_curr_va);
    }
  }

  return hash_curr_va;
}

void hash_enclave(struct enclave_t *enclave, void* hash, uintptr_t nonce_arg)
{
  struct sm3_context hash_ctx;
  uintptr_t nonce = nonce_arg;

  sm3_init(&hash_ctx);

  sm3_update(&hash_ctx, (unsigned char*)(&(enclave->entry_point)), sizeof(unsigned long));

  hash_enclave_mem(&hash_ctx, (pte_t*)(enclave->thread_context.encl_ptbr << RISCV_PGSHIFT),
      (VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS, 0, 1);

  sm3_update(&hash_ctx, (unsigned char*)(&nonce), sizeof(uintptr_t));

  sm3_final(&hash_ctx, hash);
}

void update_enclave_hash(char *output, void* hash, uintptr_t nonce_arg)
{
  struct sm3_context hash_ctx;
  uintptr_t nonce = nonce_arg;

  sm3_init(&hash_ctx);

  sm3_update(&hash_ctx, (unsigned char*)(hash), HASH_SIZE);

  sm3_update(&hash_ctx, (unsigned char*)(&nonce), sizeof(uintptr_t));

  sm3_final(&hash_ctx, hash);

  sbi_memcpy(output, hash, HASH_SIZE);
}

void sign_enclave(void* signature_arg, void* hash)
{
  struct signature_t *signature = (struct signature_t*)signature_arg;
  sm2_sign((void*)(signature->r), (void*)(signature->s), (void*)SM_PRI_KEY, hash);
}

int verify_enclave(void* signature_arg, void* hash)
{
  int ret = 0;
  struct signature_t *signature = (struct signature_t*)signature_arg;

  ret = sm2_verify((void*)SM_PUB_KEY, hash, (void*)(signature->r), (void*)(signature->s));

  return ret;
}