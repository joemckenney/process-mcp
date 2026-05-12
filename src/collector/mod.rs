pub mod cgroup_link;
pub mod proc;
pub mod walk;

// Additional collector modules will land alongside the tools that need them:
//
//   smaps         /proc/<pid>/smaps_rollup (RSS/PSS/USS), for process_info
//   fd            /proc/<pid>/fd, fd count
//   rate          CPU rate over a sample window, for top_processes(sort=cpu)
//   io            /proc/<pid>/io when readable
