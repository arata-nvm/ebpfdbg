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
    ffi::CString,
    io::{IoSlice, IoSliceMut},
    os::unix::ffi::OsStrExt,
    path::Path,
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

    pub fn read_memory(&mut self, start_addr: u64, data: &mut [u8]) -> anyhow::Result<usize> {
        let remote_iov = RemoteIoVec {
            base: start_addr as usize,
            len: data.len(),
        };
        let local_iov = IoSliceMut::new(data);
        let nread = uio::process_vm_readv(self.pid, &mut [local_iov], &[remote_iov])?;

        Ok(nread)
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
}
