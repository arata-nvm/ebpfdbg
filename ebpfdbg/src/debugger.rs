use std::{ffi::CString, path::Path};

use aya::{maps::HashMap, programs::UProbe};
use ebpfdbg_common::RegisterState;
use nix::{
    sys::{
        signal::{self, Signal},
        wait::{self, WaitPidFlag, WaitStatus},
    },
    unistd::{self, ForkResult, Pid},
};

pub struct Debugger {
    pid: Pid,
    ebpf: aya::Ebpf,
}

impl Debugger {
    pub fn new(pid: Pid) -> anyhow::Result<Self> {
        let ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/ebpfdbg"
        )))?;

        Ok(Self { pid, ebpf })
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
                unistd::execvp(&program, &args)?;

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
        uprobe.load()?;
        uprobe.attach(func, target, Some(pid))?;
        Ok(())
    }

    pub fn continue_exec(&mut self) -> anyhow::Result<WaitStatus> {
        signal::kill(self.pid, Signal::SIGCONT)?;
        let status = wait::waitpid(self.pid, Some(WaitPidFlag::WUNTRACED))?;
        Ok(status)
    }

    pub fn take_register_state(&mut self) -> anyhow::Result<RegisterState> {
        let pid = self.pid_raw();
        let mut register_states: HashMap<_, u32, RegisterState> =
            HashMap::try_from(self.ebpf.map_mut("REGISTER_STATES").unwrap())?;
        let reg_state = register_states.get(&pid, 0)?;
        let _ = register_states.remove(&pid);
        Ok(reg_state)
    }
}
