#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, generated::bpf_send_signal},
    macros::{map, uprobe},
    maps::HashMap,
    programs::ProbeContext,
};
use aya_log_ebpf::info;
use ebpfdbg_common::RegisterState;

#[map]
static REGISTER_STATES: HashMap<u32, RegisterState> = HashMap::with_max_entries(1024, 0);

const SIGSTOP: u32 = 19;

#[uprobe]
pub fn ebpfdbg(ctx: ProbeContext) -> u32 {
    match try_ebpfdbg(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ebpfdbg(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function called");
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
