#include "utils.h"

#include <sys/types.h>

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>

pid_t GetPIDByName(std::string process_name) {
  pid_t pid = PID_NONE;

  std::string cmd = "ps -A | grep " + process_name;
  FILE* fp = popen(cmd.c_str(), "r");
  if (fp != NULL) {
    char buf[CSTR_MEDIUM];
    while (fgets(buf, sizeof(buf), fp)) {
      if (strstr(buf, "root")) {
        strtok(buf, " ");
        pid = strtol(strtok(NULL, " "), NULL, 10);
        break;
      }
    }
  }

  return pid;
}

std::stringstream TraverseProcessMaps(pid_t pid) {
  char filename[CSTR_SHORT];
  if (pid == PID_SELF) {
    snprintf(filename, sizeof(filename), "/proc/self/maps");
  } else {
    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
  }

  std::stringstream output;
  char map_file_line[PATH_MAX];
  FILE* fp = fopen(filename, "r");
  if (fp != NULL) {
    output << "[+] Open map file: " << filename << std::endl;
    while (fgets(map_file_line, sizeof(map_file_line), fp)) {
      output << "=> " << map_file_line;
    }
  }
  fclose(fp);

  return output;
}