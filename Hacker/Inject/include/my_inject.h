#ifndef MY_INJECT_H
#define MY_INJECT_H
#include <sys/types.h>

#include "ptrace_inject.h"

bool PtraceInjectRemoteProcess(pid_t pid, const char* lib_path);
bool PtraceInjectRemoteProcessByShellcode(int pid, const char* lib_path);

#endif  // MY_INJECT_H