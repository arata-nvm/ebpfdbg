use std::{path::PathBuf, process::Command};

use ebpfdbg::debugger::{Debugger, StopReason, WatchKind};
use gdbstub::target::ext::base::singlethread::SingleThreadSingleStep;

fn nm_symbol_addr(bin: &PathBuf, sym: &str) -> u64 {
    let out = Command::new("nm")
        .arg("-n")
        .arg(bin)
        .output()
        .expect("failed to run nm");
    assert!(
        out.status.success(),
        "`nm -n` failed with status {:?}",
        out.status
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let mut it = line.split_whitespace();
        let Some(addr_hex) = it.next() else { continue };
        let Some(_typ) = it.next() else { continue };
        let Some(name) = it.next() else { continue };
        if name == sym {
            return u64::from_str_radix(addr_hex, 16)
                .unwrap_or_else(|_| panic!("failed to parse nm address: {addr_hex}"));
        }
    }
    panic!("symbol {sym:?} not found in {bin:?}");
}

fn launch_testprog_debugger() -> (PathBuf, Debugger) {
    let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("testdata")
        .join("testprog");

    assert!(
        bin.exists(),
        "test binary not found at {bin:?}. Build it first: `make -C testdata`",
    );

    let mut dbg = Debugger::launch(&bin, Vec::new()).expect("failed to launch testprog");
    dbg.continue_to_start()
        .expect("failed to continue to start of test program");

    (bin, dbg)
}

#[test]
fn debugger_continue_exec() {
    let (_, mut dbg) = launch_testprog_debugger();

    let stop = dbg.continue_exec().expect("continue_exec failed");
    assert!(matches!(stop, StopReason::Exited(0)), "got {stop:?}");
}

#[test]
fn debugger_add_sw_breakpoint() {
    let (bin, mut dbg) = launch_testprog_debugger();

    dbg.add_sw_breakpoint(&bin, "inner_function")
        .expect("failed to set software breakpoint on inner_function");

    let stop = dbg.continue_exec().expect("continue_exec failed");
    assert!(matches!(stop, StopReason::SwBreak), "got {stop:?}");
}

#[test]
fn debugger_add_remove_sw_breakpoint_at() {
    let (bin, mut dbg) = launch_testprog_debugger();
    let inner_addr = nm_symbol_addr(&bin, "inner_function");

    dbg.add_sw_breakpoint_at(inner_addr)
        .expect("add_sw_breakpoint_at failed");
    let stop = dbg.continue_exec().expect("continue_exec failed");
    assert!(matches!(stop, StopReason::SwBreak), "got {stop:?}");

    dbg.remove_sw_breakpoint_at(inner_addr)
        .expect("remove_sw_breakpoint_at failed");
    let stop = dbg.continue_exec().expect("continue_exec failed");
    assert!(matches!(stop, StopReason::Exited(0)), "got {stop:?}");
}

#[test]
fn debugger_add_remove_hw_breakpoint_at() {
    let (bin, mut dbg) = launch_testprog_debugger();
    let inner_addr = nm_symbol_addr(&bin, "inner_function");

    dbg.add_hw_breakpoint_at(inner_addr)
        .expect("add_hw_breakpoint_at failed");
    let stop = dbg.continue_exec().expect("continue_exec failed");
    assert!(matches!(stop, StopReason::HwBreak), "got {stop:?}");

    dbg.remove_hw_breakpoint_at(inner_addr)
        .expect("remove_hw_breakpoint_at failed");
    let stop = dbg.continue_exec().expect("continue_exec failed");
    assert!(matches!(stop, StopReason::Exited(0)), "got {stop:?}");
}

#[test]
fn debugger_read_write_memory_and_read_u64() {
    let (bin, mut dbg) = launch_testprog_debugger();
    let watched_addr = nm_symbol_addr(&bin, "watched_u64");

    let before = dbg.read_u64(watched_addr).expect("read_u64 failed");
    assert_eq!(before, 0);

    let new_val: u64 = before.wrapping_add(0x1234);
    dbg.write_memory(watched_addr, &new_val.to_le_bytes())
        .expect("write_memory failed");
    let after = dbg.read_u64(watched_addr).expect("read_u64 failed");
    assert_eq!(after, new_val);
}

#[test]
fn debugger_add_remove_hw_watchpoint_at() {
    let (bin, mut dbg) = launch_testprog_debugger();
    let watched_addr = nm_symbol_addr(&bin, "watched_u64");

    dbg.add_hw_watchpoint_at(watched_addr, 8, WatchKind::Write)
        .expect("add_hw_watchpoint_at failed");
    let stop = dbg.continue_exec().expect("continue_exec failed");
    assert!(
        matches!(
            stop,
            StopReason::Watch {
                kind: WatchKind::Write,
                addr,
            } if addr == watched_addr
        ),
        "got {stop:?}",
    );

    dbg.remove_hw_watchpoint_at(watched_addr, 8, WatchKind::Write)
        .expect("remove_hw_watchpoint_at failed");
    let stop = dbg.continue_exec().expect("continue_exec failed");
    assert!(matches!(stop, StopReason::Exited(0)), "got {stop:?}");
}

#[test]
fn debugger_step() {
    let (_, mut dbg) = launch_testprog_debugger();

    dbg.step(None).expect("step failed");
    let stop = dbg.continue_exec().expect("continue_exec failed");
    assert!(matches!(stop, StopReason::SwBreak), "got {stop:?}");
}

#[test]
fn debugger_enable_disable_catch_syscall() {
    let (_, mut dbg) = launch_testprog_debugger();

    dbg.enable_syscall_catch(None)
        .expect("enable_syscall_catch failed");
    let stop = dbg.continue_exec().expect("continue_exec failed");
    assert!(
        matches!(stop, StopReason::SyscallExit(num) if num != 0),
        "got {stop:?}"
    );

    dbg.disable_syscall_catch()
        .expect("disable_syscall_catch failed");
    let stop = dbg.continue_exec().expect("continue_exec failed");
    assert!(matches!(stop, StopReason::Exited(0)), "got {stop:?}");
}
