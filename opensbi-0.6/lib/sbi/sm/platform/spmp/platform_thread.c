void platform_enter_enclave_world()
{
  //TODO: add register to indicate whether in encalve world or not
  return;
}

void platform_exit_enclave_world()
{
  //TODO: add register to indicate whether in encalve world or not
  return;
}

int platform_check_in_enclave_world()
{
  //TODO: add register to indicate whether in encalve world or not
  return 0;
}

int platform_check_enclave_authentication(struct enclave_t* enclave)
{
  if(enclave->thread_context.encl_ptbr != csr_read(CSR_SATP))
    return -1;
  return 0;
}

void platform_switch_to_enclave_ptbr(struct thread_state_t* thread, uintptr_t enclave_ptbr)
{
  csr_write(CSR_SATP, enclave_ptbr);
}

void platform_switch_to_host_ptbr(struct thread_state_t* thread, uintptr_t host_ptbr)
{
  csr_write(CSR_SATP, host_ptbr);
}
