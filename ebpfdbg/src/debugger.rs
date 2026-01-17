pub mod auxv;
pub mod base_ops;
pub mod breakpoints;
pub mod exec_file;
pub mod extended_mode;
pub mod host_io;
pub mod section_offsets;
pub mod target;

use std::{
    collections::HashMap,
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
    ebpf::{EbpfProgram, UProbeLinkId},
    proc,
};

#[derive(Debug)]
pub struct Debugger {
    exec_file: String,
    pid: Pid,
    ebpf: EbpfProgram,

    last_register_state: RegisterState,
    breakpoints: HashMap<u64, UProbeLinkId>,
    tmp_breakpoints: Vec<UProbeLinkId>,
}

#[derive(Debug)]
pub enum StopReason {
    Exited(u8),
    Signaled(Signal),
    Stopped(Signal),
}

impl Debugger {
    pub fn new(exec_file: impl AsRef<Path>, pid: Pid) -> anyhow::Result<Self> {
        let exec_file = exec_file
            .as_ref()
            .canonicalize()?
            .into_os_string()
            .into_string()
            .map_err(|path| {
                anyhow::anyhow!("failed to convert exec_file path to string: {:?}", path)
            })?;

        let ebpf = EbpfProgram::load()?;

        Ok(Self {
            exec_file,
            pid,
            ebpf,
            last_register_state: Default::default(),
            breakpoints: HashMap::new(),
            tmp_breakpoints: Vec::new(),
        })
    }

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

    pub fn add_breakpoint(&mut self, target: impl AsRef<Path>, func: &str) -> anyhow::Result<()> {
        let pid = self.pid_raw();
        self.ebpf.attach_uprobe(target, func, pid)?;
        Ok(())
    }

    pub fn add_breakpoint_at(&mut self, addr: u64) -> anyhow::Result<()> {
        if self.breakpoints.contains_key(&addr) {
            return Err(anyhow::anyhow!(
                "breakpoint already set at address {addr:#x}"
            ));
        }

        let pid = self.pid_raw();
        let (target, offset) = proc::find_target_and_offset(self.pid, addr)?;
        let link_id = self.ebpf.attach_uprobe_at(target, offset, pid)?;
        self.breakpoints.insert(addr, link_id);
        Ok(())
    }

    pub fn add_tmp_breakpoint_at(&mut self, addr: u64) -> anyhow::Result<()> {
        let pid = self.pid_raw();
        let (target, offset) = proc::find_target_and_offset(self.pid, addr)?;
        let link_id = self.ebpf.attach_uprobe_at(target, offset, pid)?;
        self.tmp_breakpoints.push(link_id);
        Ok(())
    }

    pub fn remove_breakpoint_at(&mut self, addr: u64) -> anyhow::Result<()> {
        let link_id = self
            .breakpoints
            .remove(&addr)
            .ok_or_else(|| anyhow::anyhow!("no breakpoint set at address {addr:#x}"))?;
        self.ebpf.detach_uprobe(link_id)?;
        Ok(())
    }

    pub fn remove_tmp_breakpoints(&mut self) -> anyhow::Result<()> {
        for link_id in self.tmp_breakpoints.drain(..) {
            self.ebpf.detach_uprobe(link_id)?;
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
            WaitStatus::Stopped(_, signal) => {
                self.save_register_state()?;
                Ok(StopReason::Stopped(signal))
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
            .get(0)
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
            |group: c_uint| -> bool { detail.groups().into_iter().any(|grp| grp.0 == group as u8) };
        if is_member_of(X86InsnGroup::X86_GRP_RET) {
            let sp = self.last_register_state.rsp;
            return self.read_u64(sp);
        } else if is_member_of(X86InsnGroup::X86_GRP_CALL) {
            common::resolve_call_jump_target(operands, &self, fallthrough_pc)
        } else if is_member_of(X86InsnGroup::X86_GRP_JUMP) {
            if common::check_jump_condition(mnemonic, &self.last_register_state) {
                let target_pc = common::resolve_call_jump_target(operands, &self, fallthrough_pc)?;
                Ok(target_pc)
            } else {
                Ok(fallthrough_pc)
            }
        } else {
            Ok(fallthrough_pc)
        }
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
            .ok_or_else(|| anyhow::anyhow!("call/jump must have operand"))?
        else {
            return Err(anyhow::anyhow!("call/jump must have operand"));
        };

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
