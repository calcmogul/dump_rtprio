// Copyright (c) Tyler Veness

// This is a utility program that prints out real-time priorities for processes
// on a system. It is useful both because the standard tools don't format that
// information very well and the roboRIO's busybox ones don't seem to do it at
// all.
//
// The output format is the following comma-separated columns:
// exe,name,cpumask,policy,nice,priority,tid,pid,ppid,sid,cpu

#include <sched.h>
#include <stdint.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

template <typename T>
void CHECK_EQ(T val1, T val2) {
  if (val1 != val2) {
    throw std::runtime_error("CHECK_EQ() failed");
  }
}

template <typename T>
void PCHECK(T val) {
  if (val != 0) {
    throw std::runtime_error("PCHECK() failed");
  }
}

enum LogLevel { FATAL, WARNING };

template <typename T, typename... Ts>
void LOG(LogLevel level, T val, Ts&&... vals) {
  if (level == FATAL) {
    std::cerr << "FATAL: ";
  } else if (level == WARNING) {
    std::cerr << "WARNING: ";
  }

  std::fprintf(stderr, val, vals...);
  std::cerr << "\n";

  if (level == FATAL) {
    std::exit(1);
  }
}

template <typename T, typename... Ts>
void PLOG(LogLevel level, T val, Ts&&... vals) {
  LOG(level, val, vals...);
}

const char* policy_string(uint32_t policy) {
  switch (policy) {
    case SCHED_OTHER:
      return "OTHER";
    case SCHED_BATCH:
      return "BATCH";
    case SCHED_IDLE:
      return "IDLE";
    case SCHED_FIFO:
      return "FIFO";
    case SCHED_RR:
      return "RR";
#ifdef SCHED_DEADLINE
    case SCHED_DEADLINE:
      return "DEADLINE";
#endif
    default:
      return "???";
  }
}

std::string_view strip(std::string_view str) {
  // Left strip
  while (str.front() == ' ' || str.front() == '\t' || str.front() == '\n') {
    str.remove_prefix(1);
  }

  // Right strip
  while (str.back() == ' ' || str.back() == '\t' || str.back() == '\n') {
    str.remove_suffix(1);
  }

  return str;
}

int find_pid_max() {
  std::FILE* pid_max_file = std::fopen("/proc/sys/kernel/pid_max", "r");
  if (pid_max_file == nullptr) {
    PLOG(FATAL, "fopen(\"/proc/sys/kernel/pid_max\")");
  }

  int r;
  CHECK_EQ(1, std::fscanf(pid_max_file, "%d", &r));

  PCHECK(std::fclose(pid_max_file));

  return r;
}

cpu_set_t find_all_cpus() {
  int16_t nproc = sysconf(_SC_NPROCESSORS_CONF);
  if (nproc == -1) {
    PLOG(FATAL, "sysconf(_SC_NPROCESSORS_CONF)");
  }

  cpu_set_t r;
  CPU_ZERO(&r);
  for (int16_t i = 0; i < nproc; ++i) {
    CPU_SET(i, &r);
  }

  return r;
}

cpu_set_t find_cpu_mask(int process, bool* not_there) {
  cpu_set_t r;
  const int result = sched_getaffinity(process, sizeof(r), &r);

  if (result == -1 && errno == ESRCH) {
    *not_there = true;
    return cpu_set_t();
  }
  if (result != 0) {
    PLOG(FATAL, "sched_getaffinity(%d, %zu, %p)", process, sizeof(r), &r);
  }

  return r;
}

sched_param find_sched_param(int process, bool* not_there) {
  sched_param r;
  const int result = sched_getparam(process, &r);

  if (result == -1 && errno == ESRCH) {
    *not_there = true;
    return sched_param();
  }
  if (result != 0) {
    PLOG(FATAL, "sched_getparam(%d)", process);
  }

  return r;
}

int find_scheduler(int process, bool* not_there) {
  int scheduler = sched_getscheduler(process);

  if (scheduler == -1 && errno == ESRCH) {
    *not_there = true;
    return 0;
  }
  if (scheduler == -1) {
    PLOG(FATAL, "sched_getscheduler(%d)", process);
  }

  return scheduler;
}

std::string find_exe(int process, bool* not_there) {
  std::string exe_filename = "/proc/" + std::to_string(process) + "/exe";
  char exe_buffer[1024];
  ssize_t exe_size =
      readlink(exe_filename.c_str(), exe_buffer, sizeof(exe_buffer));

  if (exe_size == -1) {
    if (errno == ENOENT) {
      return "ENOENT";
    }
    if (errno == ESRCH) {
      *not_there = true;
      return "";
    }
    PLOG(FATAL, "readlink(%s, %p, %zu)", exe_filename.c_str(), exe_buffer,
         sizeof(exe_buffer));
  }

  return std::string(exe_buffer, exe_size);
}

int find_nice_value(int process, bool* not_there) {
  errno = 0;
  int nice_value = getpriority(PRIO_PROCESS, process);

  if (errno == ESRCH) {
    *not_there = true;
    return 0;
  }
  if (errno != 0) {
    PLOG(FATAL, "getpriority(PRIO_PROCESS, %d)", process);
  }

  return nice_value;
}

void read_stat(int process, int* ppid, int* sid, bool* not_there) {
  std::string stat_filename = "/proc/" + std::to_string(process) + "/stat";
  std::FILE* stat = std::fopen(stat_filename.c_str(), "r");

  if (stat == nullptr && errno == ENOENT) {
    *not_there = true;
    return;
  }
  if (stat == nullptr) {
    PLOG(FATAL, "fopen(%s, \"r\")", stat_filename.c_str());
  }

  char buffer[2048];
  if (std::fgets(buffer, sizeof(buffer), stat) == nullptr) {
    if (std::ferror(stat)) {
      if (errno == ESRCH) {
        *not_there = true;
        return;
      }
      PLOG(FATAL, "fgets(%p, %zu, %p)", buffer, sizeof(buffer), stat);
    }
  }

  int pid = 0;

  int field = 0;
  size_t field_start = 0;
  int parens = 0;
  for (size_t i = 0; i < sizeof(buffer); ++i) {
    if (buffer[i] == '\0') {
      break;
    }
    if (buffer[i] == '(') {
      ++parens;
    }
    if (parens > 0) {
      if (buffer[i] == ')') {
        --parens;
      }
    } else if (buffer[i] == ' ') {
      std::string_view field_string{buffer + field_start, i - field_start};
      switch (field) {
        case 0:
          pid = std::stoi(std::string{field_string});
          break;
        case 3:
          *ppid = std::stoi(std::string{field_string});
          break;
        case 4:
          *sid = std::stoi(std::string{field_string});
          break;
        default:
          break;
      }
      ++field;
      field_start = i + 1;
    }
  }
  PCHECK(std::fclose(stat));

  if (field < 4) {
    LOG(FATAL, "couldn't get fields from /proc/%d/stat\n", process);
  }
  CHECK_EQ(pid, process);
}

void read_status(int process, int ppid, int* pgrp, std::string* name,
                 bool* not_there) {
  std::string status_filename = "/proc/" + std::to_string(process) + "/status";
  std::FILE* status = std::fopen(status_filename.c_str(), "r");

  if (status == nullptr && errno == ENOENT) {
    *not_there = true;
    return;
  }
  if (status == nullptr) {
    PLOG(FATAL, "fopen(%s, \"r\")", status_filename.c_str());
  }

  int pid = 0;
  int status_ppid = 0;
  while (true) {
    char buffer[1024];
    if (std::fgets(buffer, sizeof(buffer), status) == nullptr) {
      if (std::ferror(status)) {
        PLOG(FATAL, "fgets(%p, %zu, %p)", buffer, sizeof(buffer), status);
      } else {
        break;
      }
    }
    std::string_view line{buffer};
    if (line.starts_with("Name:")) {
      line.remove_prefix(sizeof("Name:"));
      *name = strip(line);
    } else if (line.starts_with("Pid:")) {
      line.remove_prefix(sizeof("Pid:"));
      pid = std::stoi(std::string{strip(line)});
    } else if (line.starts_with("PPid:")) {
      line.remove_prefix(sizeof("PPid:"));
      status_ppid = std::stoi(std::string{strip(line)});
    } else if (line.starts_with("Tgid:")) {
      line.remove_prefix(sizeof("Tgid:"));
      *pgrp = std::stoi(std::string{strip(line)});
    }
  }

  PCHECK(std::fclose(status));
  CHECK_EQ(pid, process);
  CHECK_EQ(status_ppid, ppid);
}

}  // namespace

int main() {
  std::printf("exe,name,cpumask,policy,nice,priority,tid,pid,ppid,sid,cpu\n");

  const int pid_max = find_pid_max();
  const cpu_set_t all_cpus = find_all_cpus();

  for (int i = 0; i < pid_max; ++i) {
    bool not_there = false;

    const cpu_set_t cpu_mask = find_cpu_mask(i, &not_there);
    const sched_param param = find_sched_param(i, &not_there);
    const int scheduler = find_scheduler(i, &not_there);
    const std::string exe = find_exe(i, &not_there);
    const int nice_value = find_nice_value(i, &not_there);

    int ppid = 0, sid = 0;
    read_stat(i, &ppid, &sid, &not_there);

    int pgrp = 0;
    std::string name;
    read_status(i, ppid, &pgrp, &name, &not_there);

    if (not_there) {
      continue;
    }

    const char* cpu_mask_string =
        CPU_EQUAL(&cpu_mask, &all_cpus) ? "all" : "???";

    std::printf("%s,%s,%s,%s,%d,%d,%d,%d,%d,%d\n", exe.c_str(), name.c_str(),
                cpu_mask_string, policy_string(scheduler), nice_value,
                param.sched_priority, i, pgrp, ppid, sid);
  }
}
