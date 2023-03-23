#ifndef PTRACE_INJECT_H
#define PTRACE_INJECT_H

#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <cstddef>
#include <iostream>
#include <sstream>

#include "android_log.h"
#include "utils.h"

#define TAG_PTRACE "PtraceInject"
#define CPSR_T_MASK (1u << 5)

bool ptrace_attach(pid_t pid);
bool ptrace_detach(pid_t pid);
bool ptrace_getregs(pid_t pid, struct pt_regs& regs);
bool ptrace_setregs(pid_t pid, struct pt_regs& regs);
bool ptrace_call(pid_t pid, size_t execute_addr, size_t parameters[],
                 size_t num_params, struct pt_regs& regs);
bool ptrace_continue(pid_t pid);
size_t ptrace_getret(struct pt_regs& regs);
bool ptrace_read(pid_t pid, u_int8_t* p_read_addr, u_int8_t* p_read_data,
                 size_t size);
bool ptrace_write(pid_t pid, uint8_t* p_write_addr, uint8_t* p_write_data,
                  size_t size);
size_t get_remote_func_addr(pid_t pid, const char* module_name,
                            void* local_func_addr);
void log_context(pt_regs& regs);

#endif  // INJECT_H