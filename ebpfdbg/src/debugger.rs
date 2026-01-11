pub mod auxv;
pub mod base_ops;
pub mod breakpoints;
pub mod exec_file;
pub mod extended_mode;
pub mod host_io;
pub mod section_offsets;
pub mod target;

use std::{collections::HashMap, ffi::CString, os::unix::ffi::OsStrExt, path::Path};

use aya::{
    maps,
    programs::{UProbe, uprobe::UProbeLinkId},
};
use ebpfdbg_common::RegisterState;
use log::debug;
use nix::{
    sys::{
        signal::{self, Signal},
        wait::{self, WaitPidFlag, WaitStatus},
    },
    unistd::{self, ForkResult, Pid},
};

use crate::proc::find_target_and_offset;

#[derive(Debug)]
pub struct Debugger {
    exec_file: String,
    pid: Pid,
    ebpf: aya::Ebpf,

    last_register_state: RegisterState,
    breakpoints: HashMap<u64, UProbeLinkId>,
}

#[derive(Debug)]
pub enum StopReason {
    Exited(u8),
    Signaled(Signal),
    Stopped(Signal),
}

impl Debugger {
    pub fn new(exec_file: impl AsRef<Path>, pid: Pid) -> anyhow::Result<Self> {
        let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/ebpfdbg"
        )))?;

        let uprobe: &mut UProbe = ebpf.program_mut("ebpfdbg").unwrap().try_into()?;
        uprobe.load()?;

        let exec_file = exec_file.as_ref().canonicalize()?;
        Ok(Self {
            exec_file: exec_file.into_os_string().into_string().map_err(|path| {
                anyhow::anyhow!("failed to convert exec_file path to string: {:?}", path)
            })?,
            pid,
            ebpf,
            last_register_state: Default::default(),
            breakpoints: HashMap::new(),
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

    fn pid_raw(&self) -> u32 {
        self.pid.as_raw() as u32
    }

    pub fn add_breakpoint(&mut self, target: impl AsRef<Path>, func: &str) -> anyhow::Result<()> {
        let pid = self.pid_raw();
        let uprobe: &mut UProbe = self.ebpf.program_mut("ebpfdbg").unwrap().try_into()?;
        uprobe.attach(func, target, Some(pid))?;
        Ok(())
    }

    pub fn add_breakpoint_at(&mut self, addr: u64) -> anyhow::Result<()> {
        let pid = self.pid_raw();
        let (target, offset) = find_target_and_offset(self.pid, addr)?;
        let uprobe: &mut UProbe = self.ebpf.program_mut("ebpfdbg").unwrap().try_into()?;
        let link_id = uprobe.attach(offset, target, Some(pid))?;
        if self.breakpoints.contains_key(&addr) {
            return Err(anyhow::anyhow!(
                "breakpoint already set at address {addr:#x}"
            ));
        }
        self.breakpoints.insert(addr, link_id);
        Ok(())
    }

    pub fn remove_breakpoint_at(&mut self, addr: u64) -> anyhow::Result<()> {
        let link_id = self
            .breakpoints
            .remove(&addr)
            .ok_or_else(|| anyhow::anyhow!("no breakpoint set at address {addr:#x}"))?;
        let uprobe: &mut UProbe = self.ebpf.program_mut("ebpfdbg").unwrap().try_into()?;
        uprobe.detach(link_id)?;
        Ok(())
    }

    pub fn continue_exec(&mut self) -> anyhow::Result<StopReason> {
        debug!("continue_exec()");
        signal::kill(self.pid, Signal::SIGCONT)?;
        let status = wait::waitpid(self.pid, Some(WaitPidFlag::WUNTRACED))?;

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
        let mut register_states: maps::HashMap<_, u32, RegisterState> =
            maps::HashMap::try_from(self.ebpf.map_mut("REGISTER_STATES").unwrap())?;
        self.last_register_state = register_states.get(&pid, 0)?;
        let _ = register_states.remove(&pid)?;
        debug!("Saved register state: {:?}", self.last_register_state);
        Ok(())
    }
}
