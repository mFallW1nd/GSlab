#include "my_inject.h"

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "android_log.h"
#include "ptrace_inject.h"
#include "utils.h"

bool PtraceInjectRemoteProcess(pid_t pid, const char* lib_path) {
  // attach to the remote process
  if (ptrace_attach(pid) == false) {
    return false;
  }

  // get the remote process's context
  struct pt_regs current_regs;
  if (ptrace_getregs(pid, current_regs) == false) {
    ptrace_detach(pid);
    return false;
  }

  // log the remote process's context
  log_context(current_regs);

  // save the remote process's context
  struct pt_regs original_regs;
  memcpy(&original_regs, &current_regs, sizeof(struct pt_regs));

  // get mmap's address in remote process
  char libc_path[] = "libc.so";
  size_t mmap_addr = get_remote_func_addr(pid, libc_path, (void*)mmap);
  if ((void*)mmap_addr == NULL) {
    LOGE(TAG_PTRACE, "[x] Get remote address failed on module: %s", libc_path);
    ptrace_detach(pid);
    return false;
  }

  // configure the mmap's arguments
  // void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t
  // offsize);
  size_t param_mmap[6];
  param_mmap[0] = 0;
  param_mmap[1] = 0x100;
  param_mmap[2] = PROT_READ | PROT_WRITE | PROT_EXEC;
  param_mmap[3] = MAP_ANONYMOUS | MAP_PRIVATE;
  param_mmap[4] = 0;
  param_mmap[5] = 0;

  // invoke the mmap function
  size_t remote_map_addr;
  if (ptrace_call(pid, mmap_addr, param_mmap,
                  sizeof(param_mmap) / sizeof(size_t), current_regs) == false) {
    LOGE(TAG_PTRACE, "[x] Ptrace call failed, on module: %s", libc_path);
    ptrace_detach(pid);
    return false;
  } else {
    // get the ret value (map addr in remote proccess)
    LOGD(TAG_PTRACE, "[+] Ptrace call mmap success");
    log_context(current_regs);
    remote_map_addr = ptrace_getret(current_regs);
    LOGD(TAG_PTRACE, "[+] Remote process's map address: 0x%zx",
         remote_map_addr);
  }

  // get dlopen/dlsym/dlclose's address
  char libdl_path[] = "libdl.so";
  size_t dlopen_addr = get_remote_func_addr(pid, libdl_path, (void*)dlopen);
  size_t dlsym_addr = get_remote_func_addr(pid, libdl_path, (void*)dlsym);
  size_t dlclose_addr = get_remote_func_addr(pid, libdl_path, (void*)dlclose);
  size_t dlerror_addr = get_remote_func_addr(pid, libdl_path, (void*)dlerror);

  // configure the dlopen's arguments
  // void *dlopen(const char *filename, int flag);
  size_t param_dlopen[2];
  if (ptrace_write(pid, (uint8_t*)remote_map_addr, (uint8_t*)lib_path,
                   strlen(lib_path) + 1) == false) {
    LOGE(TAG_PTRACE, "[x] Write remote process's map addr failed, addr: 0x%zx",
         remote_map_addr);
    ptrace_detach(pid);
    return false;
  }
  param_dlopen[0] = remote_map_addr;
  param_dlopen[1] = RTLD_NOW | RTLD_GLOBAL;

  // invoke the dlopen function
  size_t hacker_module_handle;
  if (ptrace_call(pid, dlopen_addr, param_dlopen,
                  sizeof(param_dlopen) / sizeof(size_t),
                  current_regs) == false) {
    LOGE(TAG_PTRACE, "[x] Dlopen call failed, on module: %s", libdl_path);
    ptrace_detach(pid);
    return false;
  } else {
    // get the ret value (hacker moudle's base address in remote proccess)
    hacker_module_handle = ptrace_getret(current_regs);

    // check the return value of dlopen
    if ((void*)hacker_module_handle == NULL) {
      if (ptrace_call(pid, dlerror_addr, NULL, 0, current_regs) == false) {
        LOGE(TAG_PTRACE, "[x] Dlerror call failed");
        ptrace_detach(pid);
        return false;
      } else {
        log_context(current_regs);
        size_t error_addr = ptrace_getret(current_regs);
        char error_msg[CSTR_SHORT];
        if (ptrace_read(pid, (uint8_t*)error_addr, (uint8_t*)error_msg,
                        sizeof(error_msg)) == false) {
          LOGE(TAG_PTRACE, "[x] Read remote process's error msg failed");
          ptrace_detach(pid);
          return false;
        } else {
          LOGE(TAG_PTRACE, "[x] Dlopen failed, error msg: %s", error_msg);
          ptrace_detach(pid);
          return false;
        }
      }
    }

    LOGD(TAG_PTRACE, "[+] Ptrace call dlopen success");
    log_context(current_regs);
    LOGD(TAG_PTRACE, "[+] Injected module's handle: 0x%zx, name: %s",
         hacker_module_handle, lib_path);
  }

  // configure the dlsym's arguments
  // void *dlsym(void *handle, const char *symbol);
  char sym_hello_hacker[] = "hello_hacker";
  if (ptrace_write(pid, (uint8_t*)remote_map_addr, (uint8_t*)sym_hello_hacker,
                   strlen(sym_hello_hacker) + 1) == false) {
    LOGE(TAG_PTRACE, "[x] Write remote process's map addr failed, addr: 0x%zx",
         remote_map_addr);
    ptrace_detach(pid);
    return false;
  }

  size_t param_dlsym[2];
  param_dlsym[0] = hacker_module_handle;
  param_dlsym[1] = remote_map_addr;
  if (ptrace_call(pid, dlsym_addr, param_dlsym,
                  sizeof(param_dlsym) / sizeof(size_t),
                  current_regs) == false) {
    LOGE(TAG_PTRACE, "[x] Dlsym call failed, on module: %s", libdl_path);
    ptrace_detach(pid);
    return false;
  } else {
    // get the ret value (hacker moudle's base address in remote proccess)
    size_t hello_hacker_addr = ptrace_getret(current_regs);
    LOGD(TAG_PTRACE, "[+] Ptrace call dlsym success");
    log_context(current_regs);
    LOGD(TAG_PTRACE, "[+] Injected module's hello_hacker addr: 0x%zx",
         hello_hacker_addr);
  }

  // restore the remote process's context
  if (ptrace_setregs(pid, original_regs) == false) {
    LOGE(TAG_PTRACE, "[x] Set remote process's regs failed");
    ptrace_detach(pid);
    return false;
  } else if (ptrace_detach(pid) == false) {
    LOGE(TAG_PTRACE, "[x] Ptrace detach failed");
    ptrace_detach(pid);
    return false;
  }

  return true;
}