#ifndef __THREAD_H__
#define __THREAD_H__

#include <stdint.h>

//default layout of enclave
//#####################
//#   reserved for    #
//#       s mode      #
//##################### 0xffffffe000000000
//#       hole        #
//##################### 0x0000004000000000
//#       stack       #
//#                   #
//#       heap        #
//##################### 0x0000002000000000
//#  untrusted memory #
//#  shared with host #
//##################### 0x0000001000000000
//#     code & data   #
//##################### 0x0000000000001000
//#       hole        #
//##################### 0x0

#define ENCLAVE_DEFAULT_STACK 0x0000004000000000;

#define N_GENERAL_REGISTERS 32

struct general_registers_t
{
  uintptr_t slot;
  uintptr_t ra;
  uintptr_t sp;
  uintptr_t gp;
  uintptr_t tp;
  uintptr_t t0;
  uintptr_t t1;
  uintptr_t t2;
  uintptr_t s0;
  uintptr_t s1;
  uintptr_t a0;
  uintptr_t a1;
  uintptr_t a2;
  uintptr_t a3;
  uintptr_t a4;
  uintptr_t a5;
  uintptr_t a6;
  uintptr_t a7;
  uintptr_t s2;
  uintptr_t s3;
  uintptr_t s4;
  uintptr_t s5;
  uintptr_t s6;
  uintptr_t s7;
  uintptr_t s8;
  uintptr_t s9;
  uintptr_t s10;
  uintptr_t s11;
  uintptr_t t3;
  uintptr_t t4;
  uintptr_t t5;
  uintptr_t t6;
};

/* enclave thread state */
struct thread_state_t
{
  uintptr_t encl_ptbr;
  uintptr_t prev_stvec;
  uintptr_t prev_mie;
  uintptr_t prev_mideleg;
  uintptr_t prev_medeleg;
  uintptr_t prev_mepc;
  uintptr_t prev_cache_binding;
  struct general_registers_t prev_state;
};

/* swap previous and current thread states */
void swap_prev_state(struct thread_state_t* state, uintptr_t* regs);
void swap_prev_mepc(struct thread_state_t* state, uintptr_t mepc);
void swap_prev_stvec(struct thread_state_t* state, uintptr_t stvec);
void swap_prev_cache_binding(struct thread_state_t* state, uintptr_t cache_binding);
void swap_prev_mie(struct thread_state_t* state, uintptr_t mie);
void swap_prev_mideleg(struct thread_state_t* state, uintptr_t mideleg);
void swap_prev_medeleg(struct thread_state_t* state, uintptr_t medeleg);
#endif /* thread */
