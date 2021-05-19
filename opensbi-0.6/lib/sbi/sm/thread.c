#include <sm/thread.h>
//#include <sm/mtrap.h>
#include <sm/encoding.h>

void swap_prev_state(struct thread_state_t* thread, uintptr_t* regs)
{
  int i;

  uintptr_t* prev = (uintptr_t*) &thread->prev_state;
  for(i = 1; i < N_GENERAL_REGISTERS; ++i)
  {
    /* swap general registers */
    uintptr_t tmp = prev[i];
    prev[i] = regs[i];
    regs[i] = tmp;
  }

  return;
}

void swap_prev_mepc(struct thread_state_t* thread, uintptr_t current_mepc)
{
  uintptr_t tmp = thread->prev_mepc;
  thread->prev_mepc = current_mepc;
  write_csr(mepc, tmp);
}

void swap_prev_stvec(struct thread_state_t* thread, uintptr_t current_stvec)
{
  uintptr_t tmp = thread->prev_stvec;
  thread->prev_stvec = current_stvec;
  write_csr(stvec, tmp);
}

void swap_prev_cache_binding(struct thread_state_t* thread, uintptr_t current_cache_binding)
{
  uintptr_t tmp = thread->prev_cache_binding;
  thread->prev_cache_binding = current_cache_binding;
  //TODO
}

void swap_prev_mie(struct thread_state_t* thread, uintptr_t current_mie)
{
  uintptr_t tmp = thread->prev_mie;
  thread->prev_mie = current_mie;
  write_csr(mie, tmp);
}

void swap_prev_mideleg(struct thread_state_t* thread, uintptr_t current_mideleg)
{
  uintptr_t tmp = thread->prev_mideleg;
  thread->prev_mideleg = current_mideleg;
  write_csr(mideleg, tmp);
}

void swap_prev_medeleg(struct thread_state_t* thread, uintptr_t current_medeleg)
{
  uintptr_t tmp = thread->prev_medeleg;
  thread->prev_medeleg = current_medeleg;
  write_csr(medeleg, tmp);
}
