use process_mcp::mcp::server::ProcessServer;
use process_mcp::mcp::tools::pids_in_cgroup::PidsInCgroupParams;
use rmcp::handler::server::wrapper::Parameters;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

#[tokio::test]
async fn tool_list_snapshot() {
    // Locks the public tool surface (names, descriptions, schemas) against
    // unintentional drift. Tool descriptions are how the LLM picks tools,
    // so any change should be a deliberate, reviewable diff.
    let server = ProcessServer::new(PathBuf::from("/proc"));
    let mut tools = server.list_tools();
    tools.sort_by(|a, b| a.name.cmp(&b.name));

    let summary: Vec<_> = tools
        .iter()
        .map(|t| {
            serde_json::json!({
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
                "output_schema": t.output_schema,
            })
        })
        .collect();
    insta::assert_yaml_snapshot!(summary);
}

// ---- pids_in_cgroup ----

/// Programmatically build a `/proc`-shaped directory tree for tests.
/// Each `ProcSpec` becomes a `/proc/<pid>` directory with realistic
/// `comm`, `status`, `cmdline`, and `cgroup` files.
struct ProcSpec {
    comm: &'static str,
    /// `cmdline` as a list of args; the helper joins with NUL bytes.
    cmdline: Vec<&'static str>,
    state: char,
    ppid: u32,
    /// `None` means write no `VmRSS:` line, simulating a kernel thread.
    rss_kb: Option<u64>,
    /// Normalized cgroup path (no leading slash). The helper wraps it as
    /// `0::/<value>` in the cgroup file.
    cgroup: &'static str,
}

fn synthetic_proc_tree(entries: &[(u32, ProcSpec)]) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (pid, spec) in entries {
        let pid_dir = dir.path().join(pid.to_string());
        fs::create_dir_all(&pid_dir).unwrap();

        fs::write(pid_dir.join("cgroup"), format!("0::/{}\n", spec.cgroup)).unwrap();
        fs::write(pid_dir.join("comm"), format!("{}\n", spec.comm)).unwrap();

        let mut status = format!(
            "Name:\t{}\nState:\t{} (running)\nPPid:\t{}\n",
            spec.comm, spec.state, spec.ppid
        );
        if let Some(kb) = spec.rss_kb {
            status.push_str(&format!("VmRSS:\t{kb} kB\n"));
        }
        fs::write(pid_dir.join("status"), status).unwrap();

        let cmdline = spec.cmdline.join("\0");
        // Real /proc/<pid>/cmdline has a trailing NUL after the last arg.
        let cmdline = if spec.cmdline.is_empty() {
            String::new()
        } else {
            format!("{cmdline}\0")
        };
        fs::write(pid_dir.join("cmdline"), cmdline).unwrap();
    }
    dir
}

fn nginx_worker() -> ProcSpec {
    ProcSpec {
        comm: "nginx",
        cmdline: vec!["nginx", "worker process"],
        state: 'S',
        ppid: 100,
        rss_kb: Some(10_240),
        cgroup: "system.slice/nginx.service",
    }
}

fn nginx_master() -> ProcSpec {
    ProcSpec {
        comm: "nginx",
        cmdline: vec!["nginx", "master process"],
        state: 'S',
        ppid: 1,
        rss_kb: Some(5_120),
        cgroup: "system.slice/nginx.service",
    }
}

fn unrelated_dbus() -> ProcSpec {
    ProcSpec {
        comm: "dbus-broker",
        cmdline: vec!["dbus-broker-launch"],
        state: 'S',
        ppid: 1,
        rss_kb: Some(2_048),
        cgroup: "system.slice/dbus-broker.service",
    }
}

#[tokio::test]
async fn pids_in_cgroup_filters_and_sorts_by_rss_desc() {
    let dir = synthetic_proc_tree(&[
        (100, nginx_master()),
        (101, nginx_worker()),
        (200, unrelated_dbus()),
    ]);
    let server = ProcessServer::new(dir.path().to_path_buf());
    let resp = server
        .pids_in_cgroup(Parameters(PidsInCgroupParams {
            cgroup_path: "system.slice/nginx.service".into(),
            redact_args: None,
        }))
        .await
        .expect("call should succeed")
        .0;

    assert_eq!(resp.cgroup_path, "system.slice/nginx.service");
    assert_eq!(resp.skipped, 0);

    // Heaviest first; unrelated dbus excluded.
    let pids: Vec<u32> = resp.results.iter().map(|p| p.pid).collect();
    assert_eq!(pids, vec![101, 100]);
    assert_eq!(resp.results[0].rss_bytes, Some(10_240 * 1024));
    assert_eq!(resp.results[1].rss_bytes, Some(5_120 * 1024));
    assert_eq!(resp.results[0].comm, "nginx");
    assert_eq!(resp.results[0].state, "S");
    assert_eq!(resp.results[0].ppid, 100);
}

#[tokio::test]
async fn pids_in_cgroup_returns_empty_for_unused_cgroup() {
    let dir = synthetic_proc_tree(&[(100, nginx_master())]);
    let server = ProcessServer::new(dir.path().to_path_buf());
    let resp = server
        .pids_in_cgroup(Parameters(PidsInCgroupParams {
            cgroup_path: "user.slice/user-1000.slice/session-1.scope".into(),
            redact_args: None,
        }))
        .await
        .expect("ok")
        .0;
    assert!(resp.results.is_empty());
    assert_eq!(resp.skipped, 0);
}

#[tokio::test]
async fn pids_in_cgroup_handles_kernel_threads_with_null_rss() {
    let kthreadd = ProcSpec {
        comm: "kthreadd",
        cmdline: vec![], // kernel threads have empty cmdline
        state: 'I',
        ppid: 0,
        rss_kb: None, // no VmRSS line
        cgroup: "",   // root cgroup
    };
    let dir = synthetic_proc_tree(&[(2, kthreadd)]);
    let server = ProcessServer::new(dir.path().to_path_buf());
    let resp = server
        .pids_in_cgroup(Parameters(PidsInCgroupParams {
            cgroup_path: String::new(),
            redact_args: None,
        }))
        .await
        .expect("ok")
        .0;
    assert_eq!(resp.results.len(), 1);
    assert_eq!(resp.results[0].pid, 2);
    assert!(resp.results[0].rss_bytes.is_none());
    assert_eq!(resp.results[0].cmdline, "");
    assert_eq!(resp.results[0].state, "I");
}

#[tokio::test]
async fn pids_in_cgroup_redacts_cmdline_args_by_default() {
    let leaky = ProcSpec {
        comm: "myapp",
        cmdline: vec!["myapp", "--api-key=hunter2", "--port=8080"],
        state: 'R',
        ppid: 1,
        rss_kb: Some(1_024),
        cgroup: "system.slice/myapp.service",
    };
    let dir = synthetic_proc_tree(&[(500, leaky)]);
    let server = ProcessServer::new(dir.path().to_path_buf());
    let resp = server
        .pids_in_cgroup(Parameters(PidsInCgroupParams {
            cgroup_path: "system.slice/myapp.service".into(),
            redact_args: None, // default → redact
        }))
        .await
        .expect("ok")
        .0;
    assert_eq!(
        resp.results[0].cmdline,
        "myapp --api-key=REDACTED --port=8080"
    );
}

#[tokio::test]
async fn pids_in_cgroup_returns_verbatim_cmdline_when_redact_disabled() {
    let leaky = ProcSpec {
        comm: "myapp",
        cmdline: vec!["myapp", "--api-key=hunter2"],
        state: 'R',
        ppid: 1,
        rss_kb: Some(1_024),
        cgroup: "system.slice/myapp.service",
    };
    let dir = synthetic_proc_tree(&[(500, leaky)]);
    let server = ProcessServer::new(dir.path().to_path_buf());
    let resp = server
        .pids_in_cgroup(Parameters(PidsInCgroupParams {
            cgroup_path: "system.slice/myapp.service".into(),
            redact_args: Some(false),
        }))
        .await
        .expect("ok")
        .0;
    assert_eq!(resp.results[0].cmdline, "myapp --api-key=hunter2");
}

#[tokio::test]
async fn pids_in_cgroup_rejects_absolute_path() {
    let dir = tempfile::tempdir().unwrap();
    let server = ProcessServer::new(dir.path().to_path_buf());
    let err = server
        .pids_in_cgroup(Parameters(PidsInCgroupParams {
            cgroup_path: "/etc/passwd".into(),
            redact_args: None,
        }))
        .await
        .err()
        .expect("absolute should fail");
    assert!(format!("{err}").contains("relative"), "got: {err}");
}

#[tokio::test]
async fn pids_in_cgroup_rejects_dotdot_traversal() {
    let dir = tempfile::tempdir().unwrap();
    let server = ProcessServer::new(dir.path().to_path_buf());
    let err = server
        .pids_in_cgroup(Parameters(PidsInCgroupParams {
            cgroup_path: "system.slice/..".into(),
            redact_args: None,
        }))
        .await
        .err()
        .expect("dotdot should fail");
    assert!(format!("{err}").contains(".."), "got: {err}");
}

#[tokio::test]
async fn pids_in_cgroup_counts_skipped_for_unreadable_pid_dirs() {
    // One healthy PID, one bare PID directory missing the cgroup file.
    let dir = synthetic_proc_tree(&[(100, nginx_master())]);
    fs::create_dir(dir.path().join("999")).unwrap();
    // No files inside 999/, so reading it will fail at the cgroup step.

    let server = ProcessServer::new(dir.path().to_path_buf());
    let resp = server
        .pids_in_cgroup(Parameters(PidsInCgroupParams {
            cgroup_path: "system.slice/nginx.service".into(),
            redact_args: None,
        }))
        .await
        .expect("call should still succeed despite a bad PID dir")
        .0;
    assert_eq!(resp.results.len(), 1);
    assert_eq!(resp.results[0].pid, 100);
    assert_eq!(resp.skipped, 1);
}

#[tokio::test]
async fn pids_in_cgroup_ignores_non_numeric_proc_entries() {
    // /proc on real systems has cpuinfo, meminfo, sys/, etc. The walker
    // must skip these entries and only consider numeric PID directories.
    let dir = synthetic_proc_tree(&[(100, nginx_master())]);
    fs::write(dir.path().join("cpuinfo"), "processor: 0\n").unwrap();
    fs::create_dir(dir.path().join("sys")).unwrap();
    fs::write(dir.path().join("uptime"), "12345.67 9876.54\n").unwrap();

    let server = ProcessServer::new(dir.path().to_path_buf());
    let resp = server
        .pids_in_cgroup(Parameters(PidsInCgroupParams {
            cgroup_path: "system.slice/nginx.service".into(),
            redact_args: None,
        }))
        .await
        .expect("ok")
        .0;
    // Only the real PID should appear; non-numeric entries should not even
    // be counted as skipped.
    assert_eq!(resp.results.len(), 1);
    assert_eq!(resp.skipped, 0);
}
