#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_probe_read_kernel,
        generated::{bpf_get_current_task, bpf_send_signal},
    },
    macros::{map, uprobe},
    maps::HashMap,
    programs::ProbeContext,
};
use ebpfdbg_common::RegisterState;
use ebpfdbg_ebpf::vmlinux::{task_struct, thread_struct};

#[map]
static REGISTER_STATES: HashMap<u32, RegisterState> = HashMap::with_max_entries(1024, 0);

const SIGSTOP: u32 = 19;

#[uprobe]
pub fn uprobe_handler(ctx: ProbeContext) -> u32 {
    match try_uprobe_handler(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_uprobe_handler(ctx: ProbeContext) -> Result<u32, u32> {
    let task: *const task_struct = unsafe { bpf_get_current_task() } as *const task_struct;
    let thread = unsafe { &(*task).thread } as *const thread_struct;
    let es = unsafe { bpf_probe_read_kernel(&(*thread).es) }.map_err(|e| e as u32)?;
    let ds = unsafe { bpf_probe_read_kernel(&(*thread).ds) }.map_err(|e| e as u32)?;
    let fsbase = unsafe { bpf_probe_read_kernel(&(*thread).fsbase) }.map_err(|e| e as u32)?;
    let gsbase = unsafe { bpf_probe_read_kernel(&(*thread).gsbase) }.map_err(|e| e as u32)?;
    let regs = unsafe { *ctx.regs };
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
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    REGISTER_STATES.insert(&pid, state, 0).map_err(|_| 1u32)?;

    unsafe {
        bpf_send_signal(SIGSTOP);
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
