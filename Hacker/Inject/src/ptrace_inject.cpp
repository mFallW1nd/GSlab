#include "ptrace_inject.h"

#include <linux/ptrace.h>
#include <sys/types.h>

#include <cstddef>

#include "android_log.h"

bool ptrace_attach(pid_t pid) {
  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
    LOGE(TAG_PTRACE, "[x] Ptrace attach failed, pid: %d", pid);
    return false;
  }

  LOGD(TAG_PTRACE, "[+] Attach process success, pid: %d", pid);
  int status = 0;
  waitpid(pid, &status, WUNTRACED);

  return true;
}

bool ptrace_detach(pid_t pid) {
  if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
    LOGE(TAG_PTRACE, "[x] Ptrace detach failed, pid: %d", pid);
    return false;
  } else {
    LOGD(TAG_PTRACE, "[+] Detach process success, pid: %d", pid);
  }
  return true;
}

bool ptrace_getregs(pid_t pid, struct pt_regs& regs) {
  if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
    LOGE(TAG_PTRACE, "[x] Ptrace getregs failed, pid: %d", pid);
    return false;
  }
  return true;
}

bool ptrace_setregs(pid_t pid, struct pt_regs& regs) {
  if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
    LOGE(TAG_PTRACE, "[x] Ptrace setregs failed, pid: %d", pid);
    return false;
  }
  return true;
}

bool ptrace_read(pid_t pid, u_int8_t* p_read_addr, u_int8_t* p_read_data,
                 size_t size) {
  size_t read_count = size / sizeof(size_t);
  size_t read_remain = size % sizeof(size_t);
  ssize_t buf = 0;

  uint8_t *p_cur_addr = p_read_addr, *p_cur_data = p_read_data;
  for (int idx = 0; idx < read_count; idx++) {
    buf = ptrace(PTRACE_PEEKTEXT, pid, p_cur_addr, NULL);
    if (buf < 0) {
      LOGE(TAG_PTRACE, "[x] Read remote memory failed (count), addr: %p",
           p_cur_addr);
      return false;
    } else {
      LOGD(TAG_PTRACE, "[+] Read remote memory success, addr: %p, data: 0x%zx",
           p_cur_addr, buf);
      memcpy(p_cur_data, &buf, sizeof(size_t));
      p_cur_addr += sizeof(size_t);
      p_cur_data += sizeof(size_t);
    }
  }

  if (read_remain > 0) {
    buf = ptrace(PTRACE_PEEKTEXT, pid, p_cur_addr, NULL);
    if (buf < 0) {
      LOGE(TAG_PTRACE, "[x] Read remote memory failed (remain), addr: %p",
           p_cur_addr);
      return false;
    } else {
      memcpy(p_cur_data, &buf, read_remain);
      LOGD(TAG_PTRACE, "[+] Read remote memory success, addr: %p, data: 0x%zx",
           p_cur_addr, buf);
    }
  }

  return true;
}
bool ptrace_write(pid_t pid, uint8_t* p_write_addr, uint8_t* p_write_data,
                  size_t size) {
  size_t write_count = size / sizeof(size_t);
  size_t write_remain = size % sizeof(size_t);
  size_t buf = 0;

  uint8_t *p_cur_addr = p_write_addr, *p_cur_data = p_write_data;
  for (int idx = 0; idx < write_count; idx++) {
    memcpy(&buf, p_cur_data, sizeof(size_t));
    if (ptrace(PTRACE_POKETEXT, pid, p_cur_addr, buf) < 0) {
      LOGE(TAG_PTRACE, "[x] Write remote memory failed (count), addr: %p",
           p_cur_addr);
      std::cout << errno << std::endl;
      return false;
    }
    LOGD(TAG_PTRACE, "[+] Write remote memory, addr: %p, size: %d, data: 0x%zx",
         p_cur_addr, sizeof(size_t), buf);
    p_cur_addr += sizeof(size_t);
    p_cur_data += sizeof(size_t);
  }

  if (write_remain > 0) {
    buf = ptrace(PTRACE_PEEKTEXT, pid, p_cur_addr, NULL);
    memcpy(&buf, p_cur_data, write_remain);
    LOGD(TAG_PTRACE, "[+] Write remote memory, addr: %p, size: %d, data: 0x%zx",
         p_cur_addr, write_remain, buf);
    if (ptrace(PTRACE_POKETEXT, pid, p_cur_addr, buf) < 0) {
      LOGE(TAG_PTRACE, "[x] Write remote memory failed (remain), addr: %p",
           p_cur_addr);
      return false;
    }
  }

  return true;
}

bool ptrace_call(pid_t pid, size_t execute_addr, size_t parameters[],
                 size_t num_params, struct pt_regs& regs) {
  struct pt_regs ori_regs = regs;

  for (int idx = 0; idx < 4; idx++) {
    if (idx >= num_params) break;
    regs.uregs[idx] = parameters[idx];
  }

  if (num_params > 4) {
    regs.ARM_sp -= (num_params - 4) * sizeof(size_t);
    if (ptrace_write(pid, (uint8_t*)regs.ARM_sp, (uint8_t*)&parameters[4],
                     (num_params - 4) * sizeof(size_t)) == false) {
      return false;
    }
  }

  regs.ARM_pc = execute_addr;
  if (regs.ARM_pc & 1) {
    // thumb
    regs.ARM_pc &= (~1u);
    regs.ARM_cpsr |= CPSR_T_MASK;
  } else {
    regs.ARM_cpsr &= ~CPSR_T_MASK;
  }
  regs.ARM_lr = 0;

  if (ptrace_setregs(pid, regs) == false || ptrace_continue(pid) == false) {
    return false;
  }

  int stat = 0;
  waitpid(pid, &stat, WUNTRACED);
  LOGD(TAG_PTRACE, "[+] Ptrace call return status is 0x%x", stat);

  while (stat != ((SIGSEGV << 8) | 0x7f)) {
    if (ptrace_continue(pid) == false) {
      return false;
    }
    waitpid(pid, &stat, WUNTRACED);
  }

  if (ptrace_getregs(pid, regs) == false) {
    LOGE(TAG_PTRACE, "[x] Getregs after call failed");
    return false;
  } else {
    ori_regs.ARM_r0 = regs.ARM_r0;
    regs = ori_regs;
    if (ptrace_setregs(pid, regs) == false) {
      LOGE(TAG_PTRACE, "[x] Setregs after call failed");
      return false;
    }
  }

  return true;
}

bool ptrace_continue(pid_t pid) {
  if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
    LOGE(TAG_PTRACE, "[x] Ptrace continue failed, pid: %d", pid);
    return false;
  } else {
    LOGD(TAG_PTRACE, "[+] Continue process success, pid: %d", pid);
  }
  return true;
}

size_t ptrace_getret(struct pt_regs& regs) { return regs.ARM_r0; }

void* get_module_base_addr(pid_t pid, const char* module_name) {
  void* base_addr = 0;

  char filename[CSTR_SHORT];
  if (pid == PID_SELF) {
    snprintf(filename, sizeof(filename), "/proc/self/maps");
  } else {
    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
  }

  char map_file_line[PATH_MAX];
  FILE* fp = fopen(filename, "r");
  if (fp != NULL) {
    LOGD(TAG_PTRACE, "[+] Open map file: %s", filename);
    while (fgets(map_file_line, sizeof(map_file_line), fp)) {
      LOGV(TAG_PTRACE, "=> %s", map_file_line);
      if (strstr(map_file_line, module_name)) {
        char* addr = strtok(map_file_line, "-");
        base_addr = (void*)strtoul(addr, NULL, 16);
        break;
      }
    }
  }
  fclose(fp);

  return base_addr;
}

size_t get_remote_func_addr(pid_t pid, const char* module_name,
                            void* local_func_addr) {
  void *local_module_addr, *remote_module_addr, *remote_func_addr;
  local_module_addr = get_module_base_addr(PID_SELF, module_name);
  remote_module_addr = get_module_base_addr(pid, module_name);

  size_t offset = (size_t)local_func_addr - (size_t)local_module_addr;
  remote_func_addr = (void*)((size_t)remote_module_addr + offset);

  return (size_t)remote_func_addr;
}

void log_context(pt_regs& regs) {
  std::stringstream context_stream;
  for (size_t idx = 0; idx < 16; idx++) {
    context_stream << "ARM_R" << std::dec << idx;
    switch (idx) {
      case 10:
        context_stream << " (SL)";
        break;
      case 11:
        context_stream << " (FP)";
        break;
      case 12:
        context_stream << " (IP)";
        break;
      case 13:
        context_stream << " (SP)";
        break;
      case 14:
        context_stream << " (LR)";
        break;
      case 15:
        context_stream << " (PC)";
        break;
      default:
        break;
    }
    context_stream << " -> 0x" << std::hex << regs.uregs[idx] << std::endl;
  }
  LOGD(TAG_PTRACE, "%s", context_stream.str().c_str());
}