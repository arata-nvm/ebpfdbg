#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::pt_regs,
    helpers::{
        bpf_get_current_pid_tgid, bpf_probe_read_kernel,
        generated::{
            bpf_get_current_task, bpf_get_current_task_btf, bpf_send_signal, bpf_task_pt_regs,
        },
    },
    macros::{map, perf_event, tracepoint, uprobe},
    maps::HashMap,
    programs::{PerfEventContext, ProbeContext, TracePointContext},
};
use ebpfdbg_common::{RegisterState, syscall_type};
use ebpfdbg_ebpf::vmlinux::{task_struct, thread_struct};

#[map]
static REGISTER_STATES: HashMap<u32, RegisterState> = HashMap::with_max_entries(1024, 0);

#[unsafe(no_mangle)]
static TARGET_PID: u32 = 0;

const SIGSTOP: u32 = 19;

#[uprobe]
pub fn uprobe_handler(ctx: ProbeContext) -> u32 {
    match try_uprobe_handler(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_uprobe_handler(_ctx: ProbeContext) -> Result<u32, u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let state = collect_register_stage(get_pt_regs())?;
    REGISTER_STATES.insert(&pid, state, 0).map_err(|_| 1u32)?;

    unsafe {
        bpf_send_signal(SIGSTOP);
    }

    Ok(0)
}

#[perf_event]
pub fn perf_event_handler(ctx: PerfEventContext) -> u32 {
    match try_perf_event_handler(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_perf_event_handler(ctx: PerfEventContext) -> Result<u32, u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let target_pid = unsafe { core::ptr::read_volatile(&TARGET_PID) };
    if pid != target_pid {
        return Ok(0);
    }

    let perf_event_addr = unsafe { (*ctx.ctx).addr };
    let mut state = collect_register_stage(get_pt_regs())?;
    state.perf_event_addr = perf_event_addr;
    REGISTER_STATES.insert(&pid, state, 0).map_err(|_| 1u32)?;

    unsafe {
        bpf_send_signal(SIGSTOP);
    }

    Ok(0)
}

#[tracepoint]
pub fn sys_exit_execve_handler(ctx: TracePointContext) -> u32 {
    match try_sys_exit_execve_handler(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_exit_execve_handler(_ctx: TracePointContext) -> Result<u32, u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let target_pid = unsafe { core::ptr::read_volatile(&TARGET_PID) };
    if pid != target_pid {
        return Ok(0);
    }

    let mut state = collect_register_stage(get_pt_regs())?;
    state.syscall_type = syscall_type::NONE;
    REGISTER_STATES.insert(&pid, state, 0).map_err(|_| 1u32)?;

    unsafe {
        bpf_send_signal(SIGSTOP);
    }

    Ok(0)
}

#[tracepoint]
pub fn sys_enter_handler(ctx: TracePointContext) -> u32 {
    match try_sys_enter_handler(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_handler(_ctx: TracePointContext) -> Result<u32, u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let target_pid = unsafe { core::ptr::read_volatile(&TARGET_PID) };
    if pid != target_pid {
        return Ok(0);
    }

    let mut state = collect_register_stage(get_pt_regs())?;
    state.syscall_type = syscall_type::ENTRY;
    REGISTER_STATES.insert(&pid, state, 0).map_err(|_| 1u32)?;

    unsafe {
        bpf_send_signal(SIGSTOP);
    }

    Ok(0)
}

#[tracepoint]
pub fn sys_exit_handler(ctx: TracePointContext) -> u32 {
    match try_sys_exit_handler(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_exit_handler(_ctx: TracePointContext) -> Result<u32, u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let target_pid = unsafe { core::ptr::read_volatile(&TARGET_PID) };
    if pid != target_pid {
        return Ok(0);
    }

    let mut state = collect_register_stage(get_pt_regs())?;
    state.syscall_type = syscall_type::EXIT;
    REGISTER_STATES.insert(&pid, state, 0).map_err(|_| 1u32)?;

    unsafe {
        bpf_send_signal(SIGSTOP);
    }

    Ok(0)
}

fn collect_register_stage(regs: *const pt_regs) -> Result<RegisterState, u32> {
    let task = unsafe { bpf_get_current_task() } as *const task_struct;
    let thread = unsafe { &(*task).thread } as *const thread_struct;
    let es = unsafe { bpf_probe_read_kernel(&(*thread).es) }.map_err(|e| e as u32)?;
    let ds = unsafe { bpf_probe_read_kernel(&(*thread).ds) }.map_err(|e| e as u32)?;
    let fsbase = unsafe { bpf_probe_read_kernel(&(*thread).fsbase) }.map_err(|e| e as u32)?;
    let gsbase = unsafe { bpf_probe_read_kernel(&(*thread).gsbase) }.map_err(|e| e as u32)?;

    let regs = unsafe { *regs };
    let state = RegisterState {
        r15: regs.r15,
        r14: regs.r14,
        r13: regs.r13,
        r12: regs.r12,
        rbp: regs.rbp,
        rbx: regs.rbx,
        r11: regs.r11,
        r10: regs.r10,
        r9: regs.r9,
        r8: regs.r8,
        rax: regs.rax,
        rcx: regs.rcx,
        rdx: regs.rdx,
        rsi: regs.rsi,
        rdi: regs.rdi,
        orig_rax: regs.orig_rax,
        rip: regs.rip,
        cs: regs.cs,
        eflags: regs.eflags,
        rsp: regs.rsp,
        ss: regs.ss,
        es,
        ds,
        fsbase,
        gsbase,
        syscall_type: syscall_type::NONE,
        perf_event_addr: 0,
    };
    Ok(state)
}

fn get_pt_regs() -> *const pt_regs {
    let task = unsafe { bpf_get_current_task_btf() };
    let regs = unsafe { bpf_task_pt_regs(task) } as *const pt_regs;
    regs
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
