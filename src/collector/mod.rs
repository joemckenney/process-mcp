// Collector modules will land alongside the first tool that uses each one:
//
//   proc          /proc/<pid>/{stat,status,cmdline,comm}
//   smaps         /proc/<pid>/smaps_rollup (RSS/PSS/USS)
//   fd            /proc/<pid>/fd
//   cgroup_link   /proc/<pid>/cgroup -> normalized cgroup path
//   walk          iterate /proc/<pid> directories safely
//   rate          CPU rate over a sample window
//   io            /proc/<pid>/io
