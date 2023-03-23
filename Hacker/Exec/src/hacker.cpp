#include <sched.h>

#include <__tuple>
#include <cstdlib>
#include <iostream>
#include <string>

#include "android_log.h"
#include "hook.h"
#include "my_inject.h"
#include "utils.h"

#define TAG_HACKER "Hacker"

int main() {
  std::cout << "[+] I'm in hacker's main" << std::endl;
  LOGD(TAG_HACKER, "[+] I'm in hacker's main");

  pid_t pid = PID_NONE;
  pid = GetPIDByName("Victim");
  if (pid == PID_NONE) {
    LOGE(TAG_HACKER, "[x] Failed to get pid of [Victim]");
    return EXIT_FAILURE;
  } else {
    LOGD(TAG_HACKER, "[+] Get pid of [Victim]: %d", pid);
    PtraceInjectRemoteProcess(pid, "./libhacker.so");
  }

  std::stringstream maps = TraverseProcessMaps(pid);
  std::string line;
  std::getline(maps, line);
  LOGD(TAG_HACKER, "%s", line.c_str());
  while (std::getline(maps, line)) {
    LOGV(TAG_HACKER, "%s", line.c_str());
  }

  return EXIT_SUCCESS;
}