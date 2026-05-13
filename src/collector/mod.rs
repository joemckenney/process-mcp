pub mod cgroup_link;
pub mod fd;
pub mod io;
pub mod proc;
pub mod smaps;
pub mod walk;

// Additional collector modules will land alongside the tools that need them:
//
//   rate          CPU rate over a sample window, for top_processes(sort=cpu)
