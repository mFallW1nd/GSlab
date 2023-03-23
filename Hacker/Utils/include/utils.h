#ifndef UTILS_H
#define UTILS_H

#include <sys/types.h>

#include <sstream>
#include <string>

#define CSTR_SHORT 0x64
#define CSTR_MEDIUM 0x128
#define CSTR_LONG 0x256
#define PID_SELF -1
#define PID_NONE -2

pid_t GetPIDByName(std::string process_name);
std::stringstream TraverseProcessMaps(pid_t pid);
void TraverseModules(int pid);

#endif  // UTILS_H