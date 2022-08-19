#include <sm/attest.h>
#include <sm/gm/SM3.h>
#include <sm/gm/SM2_sv.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_string.h>
#include <sm/print.h>

static int hash_enclave_mem(SM3_STATE *hash_ctx, pte_t* ptes, int level,
        uintptr_t va, int hash_va)
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
            curr_va = (uintptr_t)(-1UL << VA_BITS) +
                (i << (VA_BITS - RISCV_PGLEVEL_BITS));
        else
            curr_va = va +
                (i << ((level-1) * RISCV_PGLEVEL_BITS + RISCV_PGSHIFT));
        uintptr_t pa = (*pte >> PTE_PPN_SHIFT) << RISCV_PGSHIFT;

        //found leaf pte
        if((*pte & PTE_R) || (*pte & PTE_X))
        {
            if(hash_curr_va)
            {
                SM3_process(hash_ctx, (unsigned char*)&curr_va,
                    sizeof(uintptr_t));
                //update hash with  page attribution
                SM3_process(hash_ctx, (unsigned char*)pte+7, 1);
                hash_curr_va = 0;
            }

            //4K page
            if(level == 1)
            {
                SM3_process(hash_ctx, (void*)pa, 1 << RISCV_PGSHIFT);
            }
            //2M page
            else if(level == 2)
            {
                SM3_process(hash_ctx, (void*)pa,
                    1 << (RISCV_PGSHIFT + RISCV_PGLEVEL_BITS));
            }
        }
        else
        {
            hash_curr_va = hash_enclave_mem(hash_ctx, (pte_t*)pa, level - 1,
                curr_va, hash_curr_va);
        }
    }

    return hash_curr_va;
}

void hash_enclave(struct enclave_t *enclave, void* hash, uintptr_t nonce_arg)
{
    SM3_STATE hash_ctx;
    uintptr_t nonce = nonce_arg;

    SM3_init(&hash_ctx);
    
    SM3_process(&hash_ctx, (unsigned char*)(&(enclave->entry_point)),
        sizeof(unsigned long));
    hash_enclave_mem(
        &hash_ctx,
        (pte_t*)(enclave->thread_context.encl_ptbr << RISCV_PGSHIFT),
        (VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS, 0, 1
    );
    SM3_process(&hash_ctx, (unsigned char*)(&nonce), sizeof(uintptr_t));
    SM3_done(&hash_ctx, hash);
}

void update_enclave_hash(char *output, void* hash, uintptr_t nonce_arg)
{
    SM3_STATE hash_ctx;
    uintptr_t nonce = nonce_arg;

    SM3_init(&hash_ctx);
    SM3_process(&hash_ctx, (unsigned char*)(hash), HASH_SIZE);
    SM3_process(&hash_ctx, (unsigned char*)(&nonce), sizeof(uintptr_t));
    SM3_done(&hash_ctx, hash);

    sbi_memcpy(output, hash, HASH_SIZE);
}

// initailize Secure Monitor's private key and public key.
void attest_init()
{
    int i;
    struct prikey_t *sm_prikey = (struct prikey_t *)SM_PRI_KEY;
    struct pubkey_t *sm_pubkey = (struct pubkey_t *)SM_PUB_KEY;
    
    i = SM2_Init();
    if(i)
        printm("SM2_Init failed with ret value: %d\n", i);

    i = SM2_KeyGeneration(sm_prikey->dA, sm_pubkey->xA, sm_pubkey->yA);
    if(i)
        printm("SM2_KeyGeneration failed with ret value: %d\n", i);
}

void sign_enclave(void* signature_arg, unsigned char *message, int len)
{
    struct signature_t *signature = (struct signature_t*)signature_arg;
    struct prikey_t *sm_prikey = (struct prikey_t *)SM_PRI_KEY;
    
    SM2_Sign(message, len, sm_prikey->dA, (unsigned char *)(signature->r),
        (unsigned char *)(signature->s));
}

int verify_enclave(void* signature_arg, unsigned char *message, int len)
{
    int ret = 0;
    struct signature_t *signature = (struct signature_t*)signature_arg;
    struct pubkey_t *sm_pubkey = (struct pubkey_t *)SM_PUB_KEY;
    ret = SM2_Verify(message, len, sm_pubkey->xA, sm_pubkey->yA,
        (unsigned char *)(signature->r), (unsigned char *)(signature->s));
    return ret;
}
