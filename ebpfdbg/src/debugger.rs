pub mod auxv;
pub mod base_ops;
pub mod breakpoints;
pub mod catch_syscalls;
pub mod exec_file;
pub mod extended_mode;
pub mod host_io;
pub mod target;

use std::{
    collections::{HashMap, HashSet},
    ffi::{CString, c_uint},
    io::{IoSlice, IoSliceMut},
    os::unix::ffi::OsStrExt,
    path::Path,
};

use capstone::{
    Capstone,
    arch::{
        BuildsCapstone,
        x86::{ArchMode, X86InsnGroup},
    },
};
use ebpfdbg_common::RegisterState;
use log::debug;
use nix::{
    sys::{
        signal::{self, Signal},
        uio::{self, RemoteIoVec},
        wait::{self, WaitPidFlag, WaitStatus},
    },
    unistd::{self, ForkResult, Pid},
};

use crate::{
    ebpf::{EbpfProgram, PerfEventLinkId, TracePointLinkId, UProbeLinkId},
    proc,
};

#[derive(Debug)]
pub struct Debugger {
    exec_file: String,
    pid: Pid,
    ebpf: EbpfProgram,

    last_register_state: RegisterState,
    sw_breakpoints: HashMap<u64, UProbeLinkId>,
    pending_sw_detach: HashMap<u64, UProbeLinkId>,
    tmp_breakpoints: Vec<(u64, UProbeLinkId)>,
    hw_breakpoints: HashMap<u64, PerfEventLinkId>,
    hw_watchpoints: HashMap<WatchpointKey, PerfEventLinkId>,
    syscall_catch: Option<SyscallCatchState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct WatchpointKey {
    addr: u64,
    len: u64,
    kind: WatchKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WatchKind {
    Write,
    Read,
    ReadWrite,
}

impl From<gdbstub::target::ext::breakpoints::WatchKind> for WatchKind {
    fn from(kind: gdbstub::target::ext::breakpoints::WatchKind) -> Self {
        match kind {
            gdbstub::target::ext::breakpoints::WatchKind::Write => WatchKind::Write,
            gdbstub::target::ext::breakpoints::WatchKind::Read => WatchKind::Read,
            gdbstub::target::ext::breakpoints::WatchKind::ReadWrite => WatchKind::ReadWrite,
        }
    }
}

impl From<WatchKind> for gdbstub::target::ext::breakpoints::WatchKind {
    fn from(kind: WatchKind) -> Self {
        match kind {
            WatchKind::Write => gdbstub::target::ext::breakpoints::WatchKind::Write,
            WatchKind::Read => gdbstub::target::ext::breakpoints::WatchKind::Read,
            WatchKind::ReadWrite => gdbstub::target::ext::breakpoints::WatchKind::ReadWrite,
        }
    }
}

#[derive(Debug)]
pub struct SyscallCatchState {
    sys_enter_link: TracePointLinkId,
    sys_exit_link: TracePointLinkId,
    syscall_filter: Option<std::collections::HashSet<u64>>,
}

#[derive(Debug)]
pub enum StopReason {
    Exited(u8),
    Signaled(Signal),
    SwBreak,
    HwBreak,
    Watch { kind: WatchKind, addr: u64 },
    SyscallEntry(u64),
    SyscallExit(u64),
}

impl Debugger {
    pub fn launch(exec_file: impl AsRef<Path>, args: Vec<String>) -> anyhow::Result<Self> {
        let exec_file = exec_file.as_ref();
        match unsafe { unistd::fork() }? {
            ForkResult::Child => {
                signal::kill(Pid::this(), Signal::SIGSTOP)?;

                let program = CString::new(exec_file.as_os_str().as_bytes())?;
                let mut args: Vec<CString> = args
                    .into_iter()
                    .map(CString::new)
                    .collect::<Result<_, _>>()?;
                args.insert(0, program.clone());
                unistd::execv(&program, &args)?;

                unreachable!();
            }
            ForkResult::Parent { child } => Self::new(exec_file, child),
        }
    }

    fn new(exec_file: impl AsRef<Path>, pid: Pid) -> anyhow::Result<Self> {
        let exec_file = exec_file
            .as_ref()
            .canonicalize()?
            .into_os_string()
            .into_string()
            .map_err(|path| {
                anyhow::anyhow!("failed to convert exec_file path to string: {:?}", path)
            })?;

        Ok(Self {
            exec_file,
            pid,
            ebpf: EbpfProgram::load(pid.as_raw())?,
            last_register_state: Default::default(),
            sw_breakpoints: HashMap::new(),
            pending_sw_detach: HashMap::new(),
            hw_breakpoints: HashMap::new(),
            tmp_breakpoints: Vec::new(),
            hw_watchpoints: HashMap::new(),
            syscall_catch: None,
        })
    }

    pub fn continue_to_start(&mut self) -> anyhow::Result<()> {
        let link_id = self.ebpf.attach_sys_exit_execve()?;
        self.continue_exec()?;
        self.ebpf.detach_sys_exit_execve(link_id)?;
        Ok(())
    }

    pub fn add_sw_breakpoint_at(&mut self, addr: u64) -> anyhow::Result<()> {
        if self.sw_breakpoints.contains_key(&addr) {
            return Err(anyhow::anyhow!(
                "breakpoint already set at address {addr:#x}"
            ));
        }

        let link_id = if let Some(link_id) = self.pending_sw_detach.remove(&addr) {
            link_id
        } else {
            let pid = self.pid_raw();
            let (target, offset) = proc::find_target_and_offset(self.pid, addr)?;
            self.ebpf.attach_uprobe_at(target, offset, pid)?
        };

        self.ebpf.insert_active_sw_breakpoint(addr)?;
        self.sw_breakpoints.insert(addr, link_id);
        Ok(())
    }

    pub fn add_tmp_sw_breakpoint_at(&mut self, addr: u64) -> anyhow::Result<()> {
        let pid = self.pid_raw();
        let (target, offset) = proc::find_target_and_offset(self.pid, addr)?;
        let link_id = self.ebpf.attach_uprobe_at(target, offset, pid)?;
        self.ebpf.insert_active_sw_breakpoint(addr)?;
        self.tmp_breakpoints.push((addr, link_id));
        Ok(())
    }

    pub fn remove_sw_breakpoint_at(&mut self, addr: u64) -> anyhow::Result<()> {
        let link_id = self
            .sw_breakpoints
            .remove(&addr)
            .ok_or_else(|| anyhow::anyhow!("no breakpoint set at address {addr:#x}"))?;
        self.ebpf.remove_active_sw_breakpoint(addr)?;
        self.pending_sw_detach.insert(addr, link_id);
        Ok(())
    }

    pub fn add_hw_breakpoint_at(&mut self, addr: u64) -> anyhow::Result<()> {
        if self.hw_breakpoints.contains_key(&addr) {
            return Err(anyhow::anyhow!(
                "hardware breakpoint already set at address {addr:#x}"
            ));
        }

        let pid = self.pid_raw();
        let link_id = self.ebpf.attach_perf_event(addr, pid)?;
        self.hw_breakpoints.insert(addr, link_id);
        Ok(())
    }

    pub fn add_hw_watchpoint_at(
        &mut self,
        addr: u64,
        len: u64,
        kind: WatchKind,
    ) -> anyhow::Result<()> {
        let key = WatchpointKey {
            addr,
            len,
            kind: kind,
        };
        if self.hw_watchpoints.contains_key(&key) {
            return Err(anyhow::anyhow!(
                "hardware watchpoint already set at address {addr:#x} len {len} kind {kind:?}"
            ));
        }

        let pid = self.pid_raw();
        let link_id = self.ebpf.attach_watchpoint(addr, len, kind.into(), pid)?;
        self.hw_watchpoints.insert(key, link_id);
        Ok(())
    }

    pub fn remove_hw_watchpoint_at(
        &mut self,
        addr: u64,
        len: u64,
        kind: WatchKind,
    ) -> anyhow::Result<()> {
        let key = WatchpointKey {
            addr,
            len,
            kind: kind.into(),
        };
        let link_id = self
            .hw_watchpoints
            .remove(&key)
            .ok_or_else(|| anyhow::anyhow!("no hardware watchpoint set at {addr:#x}"))?;
        self.ebpf.detach_perf_event(link_id)?;
        Ok(())
    }

    pub fn remove_hw_breakpoint_at(&mut self, addr: u64) -> anyhow::Result<()> {
        let link_id = self
            .hw_breakpoints
            .remove(&addr)
            .ok_or_else(|| anyhow::anyhow!("no hardware breakpoint set at address {addr:#x}"))?;
        self.ebpf.detach_perf_event(link_id)?;
        Ok(())
    }

    pub fn remove_tmp_breakpoints(&mut self) -> anyhow::Result<()> {
        for (addr, link_id) in self.tmp_breakpoints.drain(..) {
            self.ebpf.remove_active_sw_breakpoint(addr)?;
            self.ebpf.detach_uprobe(link_id)?;
        }
        Ok(())
    }

    pub fn enable_syscall_catch(
        &mut self,
        syscall_filter: Option<HashSet<u64>>,
    ) -> anyhow::Result<()> {
        if let Some(catch_state) = self.syscall_catch.take() {
            self.ebpf.detach_sys_enter(catch_state.sys_enter_link)?;
            self.ebpf.detach_sys_exit(catch_state.sys_exit_link)?;
        }

        let sys_enter_link = self.ebpf.attach_sys_enter()?;
        let sys_exit_link = self.ebpf.attach_sys_exit()?;

        self.syscall_catch = Some(SyscallCatchState {
            sys_enter_link,
            sys_exit_link,
            syscall_filter,
        });

        Ok(())
    }

    pub fn disable_syscall_catch(&mut self) -> anyhow::Result<()> {
        if let Some(catch_state) = self.syscall_catch.take() {
            self.ebpf.detach_sys_enter(catch_state.sys_enter_link)?;
            self.ebpf.detach_sys_exit(catch_state.sys_exit_link)?;
        }

        Ok(())
    }

    pub fn continue_exec(&mut self) -> anyhow::Result<StopReason> {
        debug!("continue_exec()");
        signal::kill(self.pid, Signal::SIGCONT)?;
        let status = wait::waitpid(self.pid, Some(WaitPidFlag::WUNTRACED))?;
        self.remove_tmp_breakpoints()?;

        match status {
            WaitStatus::Exited(_, status) => Ok(StopReason::Exited(status as u8)),
            WaitStatus::Signaled(_, signal, _) => Ok(StopReason::Signaled(signal)),
            WaitStatus::Stopped(_, _) => {
                self.save_register_state()?;
                let pc = self.last_register_state.rip;
                let perf_event_addr = self.last_register_state.perf_event_addr;

                if let Some(ref catch_state) = self.syscall_catch {
                    let syscall_num = self.last_register_state.orig_rax;
                    let should_catch = catch_state
                        .syscall_filter
                        .as_ref()
                        .map(|filter| filter.contains(&syscall_num))
                        .unwrap_or(true);

                    if should_catch {
                        if self.is_syscall_entry() {
                            return Ok(StopReason::SyscallEntry(syscall_num));
                        }
                        if self.is_syscall_exit() {
                            return Ok(StopReason::SyscallExit(syscall_num));
                        }
                    }
                }
                if self.hw_breakpoints.contains_key(&pc) {
                    return Ok(StopReason::HwBreak);
                }
                if let Some((kind, addr)) = self
                    .hw_watchpoints
                    .iter()
                    .filter_map(|(key, _)| {
                        let start_addr = key.addr;
                        let end_addr = start_addr.saturating_add(key.len);
                        let in_range = start_addr <= perf_event_addr && perf_event_addr < end_addr;
                        in_range.then_some((key.kind, perf_event_addr))
                    })
                    .max_by_key(|(kind, _)| match kind {
                        WatchKind::ReadWrite => 3,
                        WatchKind::Write => 2,
                        WatchKind::Read => 1,
                    })
                {
                    return Ok(StopReason::Watch { kind, addr });
                }
                if self.sw_breakpoints.contains_key(&pc) {
                    return Ok(StopReason::SwBreak);
                }
                Ok(StopReason::SwBreak)
            }
            _ => unimplemented!("{status:?}"),
        }
    }

    pub fn save_register_state(&mut self) -> anyhow::Result<()> {
        let pid = self.pid_raw();
        self.last_register_state = self.ebpf.take_register_state(pid)?;
        debug!("Saved register state: {:?}", self.last_register_state);
        Ok(())
    }

    pub fn read_memory(&self, start_addr: u64, data: &mut [u8]) -> anyhow::Result<usize> {
        let remote_iov = RemoteIoVec {
            base: start_addr as usize,
            len: data.len(),
        };
        let local_iov = IoSliceMut::new(data);
        let nread = uio::process_vm_readv(self.pid, &mut [local_iov], &[remote_iov])?;

        Ok(nread)
    }

    pub fn read_u64(&self, addr: u64) -> anyhow::Result<u64> {
        let mut buf = [0u8; 8];
        self.read_memory(addr, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    pub fn write_memory(&mut self, start_addr: u64, data: &[u8]) -> anyhow::Result<usize> {
        let remote_iov = RemoteIoVec {
            base: start_addr as usize,
            len: data.len(),
        };
        let local_iov = IoSlice::new(data);
        let nwrite = uio::process_vm_writev(self.pid, &[local_iov], &[remote_iov])?;

        Ok(nwrite)
    }

    fn pid_raw(&self) -> u32 {
        self.pid.as_raw() as u32
    }

    fn predict_next_pc(&self) -> anyhow::Result<u64> {
        let pc = self.last_register_state.rip;
        let mut code = [0u8; 16];
        self.read_memory(pc, &mut code)?;

        let cs = Capstone::new()
            .x86()
            .mode(ArchMode::Mode64)
            .detail(true)
            .build()?;
        let insns = cs.disasm_count(&code, pc, 1)?;
        let insn = insns
            .first()
            .ok_or_else(|| anyhow::anyhow!("no instruction at pc"))?;

        let detail = cs.insn_detail(insn)?;
        let arch_detail = detail.arch_detail();
        let operands = arch_detail.operands();
        let mnemonic = insn
            .mnemonic()
            .ok_or_else(|| anyhow::anyhow!("no mnemonic"))?;

        debug!("insn: {insn}");
        debug!("detail: {detail:?}");
        debug!("arch_detail: {arch_detail:?}");
        debug!("operands: {operands:?}");

        let fallthrough_pc = pc + insn.len() as u64;

        let is_member_of =
            |group: c_uint| -> bool { detail.groups().iter().any(|grp| grp.0 == group as u8) };
        if is_member_of(X86InsnGroup::X86_GRP_RET) {
            let sp = self.last_register_state.rsp;
            self.read_u64(sp)
        } else if is_member_of(X86InsnGroup::X86_GRP_CALL) {
            common::resolve_call_jump_target(operands, self, fallthrough_pc)
        } else if is_member_of(X86InsnGroup::X86_GRP_JUMP) {
            if common::check_jump_condition(mnemonic, &self.last_register_state) {
                let target_pc = common::resolve_call_jump_target(operands, self, fallthrough_pc)?;
                Ok(target_pc)
            } else {
                Ok(fallthrough_pc)
            }
        } else {
            Ok(fallthrough_pc)
        }
    }

    fn is_syscall_entry(&self) -> bool {
        self.last_register_state.syscall_type == ebpfdbg_common::syscall_type::ENTRY
    }

    fn is_syscall_exit(&self) -> bool {
        self.last_register_state.syscall_type == ebpfdbg_common::syscall_type::EXIT
    }
}

mod common {
    use capstone::{
        RegId,
        arch::{
            ArchOperand,
            x86::{X86OperandType, X86Reg},
        },
    };
    use ebpfdbg_common::RegisterState;

    use crate::debugger::Debugger;

    pub fn resolve_call_jump_target(
        operands: Vec<ArchOperand>,
        debugger: &Debugger,
        fallthrough_pc: u64,
    ) -> anyhow::Result<u64> {
        let ArchOperand::X86Operand(operand) = operands
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("call/jump must have operand"))?;

        let regs = &debugger.last_register_state;
        match operand.op_type {
            X86OperandType::Reg(reg) => Ok(get_reg_value(reg, regs, fallthrough_pc)),
            X86OperandType::Imm(imm) => Ok(imm as u64),
            X86OperandType::Mem(mem) => {
                let base = get_reg_value(mem.base(), regs, fallthrough_pc);
                let index = get_reg_value(mem.index(), regs, fallthrough_pc);

                let addr = base
                    .wrapping_add(mem.disp() as u64)
                    .wrapping_add(index.wrapping_mul(mem.scale() as u64));
                debugger.read_u64(addr)
            }
            typ => unimplemented!("{typ:?}"),
        }
    }

    pub fn get_reg_value(reg_id: RegId, regs: &RegisterState, fallthrough_pc: u64) -> u64 {
        match reg_id.0 as u32 {
            X86Reg::X86_REG_INVALID => 0,
            X86Reg::X86_REG_RAX => regs.rax,
            X86Reg::X86_REG_RBP => regs.rbp,
            X86Reg::X86_REG_RBX => regs.rbx,
            X86Reg::X86_REG_RCX => regs.rcx,
            X86Reg::X86_REG_RDI => regs.rdi,
            X86Reg::X86_REG_RDX => regs.rdx,
            X86Reg::X86_REG_RIP => fallthrough_pc,
            X86Reg::X86_REG_RSI => regs.rsi,
            X86Reg::X86_REG_RSP => regs.rsp,
            X86Reg::X86_REG_R8 => regs.r8,
            X86Reg::X86_REG_R9 => regs.r9,
            X86Reg::X86_REG_R10 => regs.r10,
            X86Reg::X86_REG_R11 => regs.r11,
            X86Reg::X86_REG_R12 => regs.r12,
            X86Reg::X86_REG_R13 => regs.r13,
            X86Reg::X86_REG_R14 => regs.r14,
            X86Reg::X86_REG_R15 => regs.r15,
            reg => unimplemented!("{:?}", reg),
        }
    }

    pub fn check_jump_condition(mnemonic: &str, regs: &RegisterState) -> bool {
        let eflags = regs.eflags;
        let cf = (eflags & 0x0001) != 0;
        let pf = (eflags & 0x0004) != 0;
        let zf = (eflags & 0x0040) != 0;
        let sf = (eflags & 0x0080) != 0;
        let of = (eflags & 0x0800) != 0;

        match mnemonic {
            "jmp" | "ljmp" => true,
            "jo" => of,
            "jno" => !of,
            "js" => sf,
            "jns" => !sf,
            "je" | "jz" => zf,
            "jne" | "jnz" => !zf,
            "jb" | "jnae" | "jc" => cf,
            "jnb" | "jae" | "jnc" => !cf,
            "jbe" | "jna" => cf || zf,
            "ja" | "jnbe" => !cf && !zf,
            "jl" | "jnge" => sf != of,
            "jge" | "jnl" => sf == of,
            "jle" | "jng" => zf || (sf != of),
            "jg" | "jnle" => !zf && (sf == of),
            "jp" | "jpe" => pf,
            "jnp" | "jpo" => !pf,
            "jrcxz" => regs.rcx == 0,
            mnemonic => unimplemented!("{mnemonic}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::common;
    use ebpfdbg_common::RegisterState;

    fn regs_with_flags(eflags: u64) -> RegisterState {
        RegisterState {
            eflags,
            ..Default::default()
        }
    }

    #[test]
    fn check_jump_condition_unconditional() {
        let regs = regs_with_flags(0);
        assert!(common::check_jump_condition("jmp", &regs));
        assert!(common::check_jump_condition("ljmp", &regs));
    }

    #[test]
    fn check_jump_condition_with_zf() {
        // ZF set
        let regs_zf_set = regs_with_flags(0x0040);
        assert!(common::check_jump_condition("je", &regs_zf_set));
        assert!(common::check_jump_condition("jz", &regs_zf_set));
        assert!(!common::check_jump_condition("jne", &regs_zf_set));
        assert!(!common::check_jump_condition("jnz", &regs_zf_set));

        // !ZF
        let regs_zf_clear = regs_with_flags(0);
        assert!(!common::check_jump_condition("je", &regs_zf_clear));
        assert!(!common::check_jump_condition("jz", &regs_zf_clear));
        assert!(common::check_jump_condition("jne", &regs_zf_clear));
        assert!(common::check_jump_condition("jnz", &regs_zf_clear));
    }

    #[test]
    fn check_jump_condition_with_cf() {
        // CF
        let regs_cf_set = regs_with_flags(0x0001);
        assert!(common::check_jump_condition("jb", &regs_cf_set));
        assert!(common::check_jump_condition("jnae", &regs_cf_set));
        assert!(common::check_jump_condition("jc", &regs_cf_set));
        assert!(!common::check_jump_condition("jnb", &regs_cf_set));
        assert!(!common::check_jump_condition("jae", &regs_cf_set));
        assert!(!common::check_jump_condition("jnc", &regs_cf_set));

        // !CF
        let regs_cf_clear = regs_with_flags(0);
        assert!(!common::check_jump_condition("jb", &regs_cf_clear));
        assert!(!common::check_jump_condition("jnae", &regs_cf_clear));
        assert!(!common::check_jump_condition("jc", &regs_cf_clear));
        assert!(common::check_jump_condition("jnb", &regs_cf_clear));
        assert!(common::check_jump_condition("jae", &regs_cf_clear));
        assert!(common::check_jump_condition("jnc", &regs_cf_clear));
    }

    #[test]
    fn check_jump_condition_with_zf_sf_of() {
        // ZF and SF = OF: greater-than
        let regs_gt = regs_with_flags(0x0000);
        assert!(common::check_jump_condition("jg", &regs_gt));
        assert!(common::check_jump_condition("jnle", &regs_gt));
        assert!(!common::check_jump_condition("jle", &regs_gt));
        assert!(!common::check_jump_condition("jng", &regs_gt));

        // ZF: equal / less-or-equal
        let regs_eq = regs_with_flags(0x0040);
        assert!(common::check_jump_condition("jle", &regs_eq));
        assert!(common::check_jump_condition("jng", &regs_eq));
        assert!(!common::check_jump_condition("jg", &regs_eq));
        assert!(!common::check_jump_condition("jnle", &regs_eq));

        // SF != OF: less-than
        let regs_lt = regs_with_flags(0x0080); // SF set, OF clear
        assert!(common::check_jump_condition("jl", &regs_lt));
        assert!(common::check_jump_condition("jnge", &regs_lt));
        assert!(!common::check_jump_condition("jge", &regs_lt));
        assert!(!common::check_jump_condition("jnl", &regs_lt));
    }

    #[test]
    fn check_jump_condition_with_pf() {
        // PF
        let regs_pf_set = regs_with_flags(0x0004);
        assert!(common::check_jump_condition("jp", &regs_pf_set));
        assert!(common::check_jump_condition("jpe", &regs_pf_set));
        assert!(!common::check_jump_condition("jnp", &regs_pf_set));
        assert!(!common::check_jump_condition("jpo", &regs_pf_set));

        // !PF
        let regs_pf_clear = regs_with_flags(0);
        assert!(!common::check_jump_condition("jp", &regs_pf_clear));
        assert!(!common::check_jump_condition("jpe", &regs_pf_clear));
        assert!(common::check_jump_condition("jnp", &regs_pf_clear));
        assert!(common::check_jump_condition("jpo", &regs_pf_clear));
    }

    #[test]
    fn check_jump_condition_with_of() {
        // OF
        let regs_of_set = regs_with_flags(0x0800);
        assert!(common::check_jump_condition("jo", &regs_of_set));
        assert!(!common::check_jump_condition("jno", &regs_of_set));

        // !OF
        let regs_of_clear = regs_with_flags(0);
        assert!(!common::check_jump_condition("jo", &regs_of_clear));
        assert!(common::check_jump_condition("jno", &regs_of_clear));
    }

    #[test]
    fn check_jump_condition_with_rcx() {
        let mut regs = regs_with_flags(0);
        regs.rcx = 0;
        assert!(common::check_jump_condition("jrcxz", &regs));

        regs.rcx = 1;
        assert!(!common::check_jump_condition("jrcxz", &regs));
    }
}
