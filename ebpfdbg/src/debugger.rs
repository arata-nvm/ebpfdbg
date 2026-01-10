use std::{
    ffi::CString,
    io::IoSliceMut,
    os::fd::{BorrowedFd, IntoRawFd},
    path::Path,
};

use aya::{maps::HashMap, programs::UProbe};
use ebpfdbg_common::RegisterState;
use gdbstub::{
    arch::Arch,
    target::{
        Target, TargetError, TargetResult,
        ext::{
            base::{
                BaseOps,
                single_register_access::{SingleRegisterAccess, SingleRegisterAccessOps},
                singlethread::{SingleThreadBase, SingleThreadResume, SingleThreadResumeOps},
            },
            extended_mode::{
                Args, AttachKind, CurrentActivePid, CurrentActivePidOps, ExtendedMode,
                ExtendedModeOps, ShouldTerminate,
            },
            host_io::{
                HostIo, HostIoClose, HostIoCloseOps, HostIoErrno, HostIoError, HostIoOpen,
                HostIoOpenFlags, HostIoOpenMode, HostIoOpenOps, HostIoOps, HostIoPread,
                HostIoPreadOps, HostIoReadlink, HostIoReadlinkOps, HostIoResult,
            },
        },
    },
};
use gdbstub_arch::x86::reg::id::{X86_64CoreRegId, X86SegmentRegId};
use log::debug;
use nix::{
    fcntl::{self, OFlag},
    sys::{
        signal::{self, Signal},
        stat::Mode,
        uio::{self, RemoteIoVec},
        wait::{self, WaitPidFlag, WaitStatus},
    },
    unistd::{self, ForkResult, Pid},
};

use crate::arch::{X86_64_SSE_Segments, X86_64_SSE_SegmentsRegId, X86_64SegmentsRegId};

#[derive(Debug)]
pub struct Debugger {
    pid: Pid,
    ebpf: aya::Ebpf,

    last_register_state: RegisterState,
}

#[derive(Debug)]
pub enum StopReason {
    Exited(u8),
    Signaled(Signal),
    Stopped(Signal),
}

impl Debugger {
    pub fn new(pid: Pid) -> anyhow::Result<Self> {
        let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/ebpfdbg"
        )))?;

        let uprobe: &mut UProbe = ebpf.program_mut("ebpfdbg").unwrap().try_into()?;
        uprobe.load()?;

        Ok(Self {
            pid,
            ebpf,
            last_register_state: Default::default(),
        })
    }

    pub fn launch(program: String, args: Vec<String>) -> anyhow::Result<Self> {
        match unsafe { unistd::fork() }? {
            ForkResult::Child => {
                signal::kill(Pid::this(), Signal::SIGSTOP)?;

                let program = CString::new(program)?;
                let mut args: Vec<CString> = args
                    .into_iter()
                    .map(CString::new)
                    .collect::<Result<_, _>>()?;
                args.insert(0, program.clone());
                unistd::execv(&program, &args)?;

                unreachable!();
            }
            ForkResult::Parent { child } => Self::new(child),
        }
    }

    fn pid_raw(&self) -> u32 {
        self.pid.as_raw() as u32
    }

    pub fn add_breakpoint(&mut self, target: impl AsRef<Path>, func: &str) -> anyhow::Result<()> {
        let pid = self.pid_raw();
        let uprobe: &mut UProbe = self.ebpf.program_mut("ebpfdbg").unwrap().try_into()?;
        uprobe.attach(func, target, Some(pid))?;
        Ok(())
    }

    pub fn continue_exec(&mut self) -> anyhow::Result<StopReason> {
        signal::kill(self.pid, Signal::SIGCONT)?;
        let status = wait::waitpid(self.pid, Some(WaitPidFlag::WUNTRACED))?;

        self.save_register_state()?;

        match status {
            WaitStatus::Exited(_, status) => Ok(StopReason::Exited(status as u8)),
            WaitStatus::Signaled(_, signal, _) => Ok(StopReason::Signaled(signal)),
            WaitStatus::Stopped(_, signal) => Ok(StopReason::Stopped(signal)),
            _ => unimplemented!("{status:?}"),
        }
    }

    pub fn save_register_state(&mut self) -> anyhow::Result<()> {
        let pid = self.pid_raw();
        let mut register_states: HashMap<_, u32, RegisterState> =
            HashMap::try_from(self.ebpf.map_mut("REGISTER_STATES").unwrap())?;
        self.last_register_state = register_states.get(&pid, 0)?;
        let _ = register_states.remove(&pid)?;
        debug!("Saved register state: {:?}", self.last_register_state);
        Ok(())
    }
}

impl Target for Debugger {
    type Arch = X86_64_SSE_Segments;
    type Error = anyhow::Error;

    fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }

    fn support_extended_mode(&mut self) -> Option<ExtendedModeOps<'_, Self>> {
        Some(self)
    }

    fn support_host_io(&mut self) -> Option<HostIoOps<'_, Self>> {
        Some(self)
    }

    fn guard_rail_implicit_sw_breakpoints(&self) -> bool {
        true
    }
}

impl SingleThreadBase for Debugger {
    fn read_registers(
        &mut self,
        regs: &mut <Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        regs.core.regs[0] = self.last_register_state.rax;
        regs.core.regs[1] = self.last_register_state.rbx;
        regs.core.regs[2] = self.last_register_state.rcx;
        regs.core.regs[3] = self.last_register_state.rdx;
        regs.core.regs[4] = self.last_register_state.rsi;
        regs.core.regs[5] = self.last_register_state.rdi;
        regs.core.regs[6] = self.last_register_state.rbp;
        regs.core.regs[7] = self.last_register_state.rsp;
        regs.core.regs[8] = self.last_register_state.r8;
        regs.core.regs[9] = self.last_register_state.r9;
        regs.core.regs[10] = self.last_register_state.r10;
        regs.core.regs[11] = self.last_register_state.r11;
        regs.core.regs[12] = self.last_register_state.r12;
        regs.core.regs[13] = self.last_register_state.r13;
        regs.core.regs[14] = self.last_register_state.r14;
        regs.core.regs[15] = self.last_register_state.r15;

        regs.core.eflags = self.last_register_state.eflags as u32;
        regs.core.rip = self.last_register_state.rip;
        regs.core.segments.cs = self.last_register_state.cs as u32;
        regs.core.segments.ss = self.last_register_state.ss as u32;
        regs.core.segments.ds = self.last_register_state.ds as u32;
        regs.core.segments.es = self.last_register_state.es as u32;

        regs.segments.fs_base = self.last_register_state.fsbase;
        regs.segments.gs_base = self.last_register_state.gsbase;

        Ok(())
    }

    fn write_registers(
        &mut self,
        _regs: &<Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        unimplemented!();
    }

    fn support_single_register_access(&mut self) -> Option<SingleRegisterAccessOps<'_, (), Self>> {
        Some(self)
    }

    fn read_addrs(
        &mut self,
        start_addr: <Self::Arch as Arch>::Usize,
        data: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let remote_iov = RemoteIoVec {
            base: start_addr as usize,
            len: data.len(),
        };
        let local_iov = IoSliceMut::new(data);
        let nread = uio::process_vm_readv(self.pid, &mut [local_iov], &[remote_iov])
            .map_err(|e| TargetError::Errno(e as u8))?;

        Ok(nread)
    }

    fn write_addrs(
        &mut self,
        _start_addr: <Self::Arch as Arch>::Usize,
        _data: &[u8],
    ) -> TargetResult<(), Self> {
        unimplemented!();
    }

    fn support_resume(&mut self) -> Option<SingleThreadResumeOps<'_, Self>> {
        Some(self)
    }
}

impl SingleRegisterAccess<()> for Debugger {
    fn read_register(
        &mut self,
        _tid: (),
        reg_id: <Self::Arch as Arch>::RegId,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let value = match reg_id {
            X86_64_SSE_SegmentsRegId::Core(X86_64CoreRegId::Gpr(id)) => match id {
                0 => self.last_register_state.rax,
                1 => self.last_register_state.rbx,
                2 => self.last_register_state.rcx,
                3 => self.last_register_state.rdx,
                4 => self.last_register_state.rsi,
                5 => self.last_register_state.rdi,
                6 => self.last_register_state.rbp,
                7 => self.last_register_state.rsp,
                8 => self.last_register_state.r8,
                9 => self.last_register_state.r9,
                10 => self.last_register_state.r10,
                11 => self.last_register_state.r11,
                12 => self.last_register_state.r12,
                13 => self.last_register_state.r13,
                14 => self.last_register_state.r14,
                15 => self.last_register_state.r15,
                _ => unreachable!(),
            },
            X86_64_SSE_SegmentsRegId::Core(X86_64CoreRegId::Rip) => self.last_register_state.rip,
            X86_64_SSE_SegmentsRegId::Core(X86_64CoreRegId::Eflags) => {
                self.last_register_state.eflags
            }
            X86_64_SSE_SegmentsRegId::Core(X86_64CoreRegId::Segment(id)) => match id {
                X86SegmentRegId::CS => self.last_register_state.cs,
                X86SegmentRegId::SS => self.last_register_state.ss,
                X86SegmentRegId::DS => self.last_register_state.ds as u64,
                X86SegmentRegId::ES => self.last_register_state.es as u64,
                _ => unimplemented!(),
            },
            X86_64_SSE_SegmentsRegId::Segments(segments) => match segments {
                X86_64SegmentsRegId::FsBase => self.last_register_state.fsbase,
                X86_64SegmentsRegId::GsBase => self.last_register_state.gsbase,
            },
            _ => unimplemented!(),
        };
        let value_bytes = value.to_le_bytes();
        let len = buf.len().min(value_bytes.len());
        buf[..len].copy_from_slice(&value_bytes[..len]);
        Ok(len)
    }

    fn write_register(
        &mut self,
        _tid: (),
        _reg_id: <Self::Arch as Arch>::RegId,
        _val: &[u8],
    ) -> TargetResult<(), Self> {
        unimplemented!();
    }
}

impl SingleThreadResume for Debugger {
    fn resume(&mut self, _signal: Option<gdbstub::common::Signal>) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl ExtendedMode for Debugger {
    fn run(
        &mut self,
        _filename: Option<&[u8]>,
        _args: Args<'_, '_>,
    ) -> TargetResult<gdbstub::common::Pid, Self> {
        unimplemented!();
    }

    fn attach(&mut self, _pid: gdbstub::common::Pid) -> TargetResult<(), Self> {
        unimplemented!();
    }

    fn query_if_attached(&mut self, _pid: gdbstub::common::Pid) -> TargetResult<AttachKind, Self> {
        Ok(AttachKind::Attach)
    }

    fn kill(&mut self, _pid: Option<gdbstub::common::Pid>) -> TargetResult<ShouldTerminate, Self> {
        unimplemented!();
    }

    fn restart(&mut self) -> Result<(), Self::Error> {
        unimplemented!();
    }

    fn support_current_active_pid(&mut self) -> Option<CurrentActivePidOps<'_, Self>> {
        Some(self)
    }
}

impl CurrentActivePid for Debugger {
    fn current_active_pid(&mut self) -> Result<gdbstub::common::Pid, Self::Error> {
        gdbstub::common::Pid::new(self.pid.as_raw() as usize)
            .ok_or_else(|| anyhow::anyhow!("invalid pid"))
    }
}

impl HostIo for Debugger {
    fn support_open(&mut self) -> Option<HostIoOpenOps<'_, Self>> {
        Some(self)
    }

    fn support_readlink(&mut self) -> Option<HostIoReadlinkOps<'_, Self>> {
        Some(self)
    }

    fn support_pread(&mut self) -> Option<HostIoPreadOps<'_, Self>> {
        Some(self)
    }

    fn support_close(&mut self) -> Option<HostIoCloseOps<'_, Self>> {
        Some(self)
    }
}

impl HostIoOpen for Debugger {
    fn open(
        &mut self,
        filename: &[u8],
        flags: HostIoOpenFlags,
        mode: HostIoOpenMode,
    ) -> HostIoResult<u32, Self> {
        let flags = OFlag::from_bits(flags.bits() as i32).expect("invalid flags");
        let mode = Mode::from_bits(mode.bits() as u32).expect("invalid mode");
        let fd =
            fcntl::open(filename, flags, mode).map_err(|e| HostIoError::Errno(map_errno(e)))?;
        let fd = fd.into_raw_fd();
        Ok(fd as u32)
    }
}

impl HostIoReadlink for Debugger {
    fn readlink(&mut self, filename: &[u8], buf: &mut [u8]) -> HostIoResult<usize, Self> {
        let path = fcntl::readlink(filename).map_err(|e| HostIoError::Errno(map_errno(e)))?;
        let path_bytes = path.as_encoded_bytes();
        let len = buf.len().min(path_bytes.len());
        buf[..len].copy_from_slice(&path_bytes[..len]);
        Ok(len)
    }
}

impl HostIoPread for Debugger {
    fn pread(
        &mut self,
        fd: u32,
        count: usize,
        offset: u64,
        buf: &mut [u8],
    ) -> HostIoResult<usize, Self> {
        let fd = unsafe { BorrowedFd::borrow_raw(fd as i32) };
        let nread = uio::pread(fd, &mut buf[..count], offset as i64)
            .map_err(|e| HostIoError::Errno(map_errno(e)))?;
        Ok(nread)
    }
}

impl HostIoClose for Debugger {
    fn close(&mut self, fd: u32) -> HostIoResult<(), Self> {
        unistd::close(fd as i32).map_err(|e| HostIoError::Errno(map_errno(e)))?;
        Ok(())
    }
}

fn map_errno(e: nix::errno::Errno) -> HostIoErrno {
    unsafe { std::mem::transmute::<_, HostIoErrno>(e as u16) }
}
