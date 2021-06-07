#ifndef _PLATFORM_THREAD_H
#define _PLATFORM_THREAD_H

#include <sm/thread.h>

void platform_enter_enclave_world();

void platform_exit_enclave_world();

int platform_check_in_enclave_world();

int platform_check_enclave_authentication();

void platform_switch_to_enclave_ptbr(struct thread_state_t* thread, uintptr_t ptbr);

void platform_switch_to_host_ptbr(struct thread_state_t* thread, uintptr_t ptbr);

#endif /* _PLATFORM_THREAD_H */
