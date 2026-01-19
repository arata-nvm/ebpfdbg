use std::path::Path;

use aya::{
    Ebpf, EbpfLoader,
    maps::HashMap,
    programs::{
        PerfEvent, TracePoint, UProbe,
        perf_event::{
            BreakpointConfig, PerfBreakpointLength, PerfBreakpointType, PerfEventConfig,
            PerfEventScope, SamplePolicy,
        },
    },
};
use ebpfdbg_common::RegisterState;

use crate::debugger::WatchKind;

#[derive(Debug)]
pub struct EbpfProgram(Ebpf);

#[derive(Debug)]
pub struct UProbeLinkId(aya::programs::uprobe::UProbeLinkId);

#[derive(Debug)]
pub struct PerfEventLinkId(aya::programs::perf_event::PerfEventLinkId);

#[derive(Debug)]
pub struct TracePointLinkId(aya::programs::trace_point::TracePointLinkId);

const PROGRAM_UPROBE_HANDLER: &str = "uprobe_handler";
const PROGRAM_PERF_EVENT_HANDLER: &str = "perf_event_handler";
const PROGRAM_SYS_EXIT_EXECVE_HANDLER: &str = "sys_exit_execve_handler";
const PROGRAM_SYS_ENTER_HANDLER: &str = "sys_enter_handler";
const PROGRAM_SYS_EXIT_HANDLER: &str = "sys_exit_handler";
const MAP_REGISTER_STATES: &str = "REGISTER_STATES";
const GLOBAL_TARGET_PID: &str = "TARGET_PID";

impl EbpfProgram {
    pub fn load(target_pid: i32) -> anyhow::Result<Self> {
        let ebpf = EbpfLoader::new()
            .override_global(GLOBAL_TARGET_PID, &target_pid, true)
            .load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/ebpfdbg"
            )))?;

        let mut this = EbpfProgram(ebpf);
        this.get_uprobe_handler()?.load()?;
        this.get_perf_event_handler()?.load()?;
        this.get_sys_exit_execve_handler()?.load()?;
        this.get_sys_enter_handler()?.load()?;
        this.get_sys_exit_handler()?.load()?;
        Ok(this)
    }

    pub fn attach_uprobe(
        &mut self,
        target: impl AsRef<Path>,
        func: &str,
        pid: u32,
    ) -> anyhow::Result<UProbeLinkId> {
        let uprobe = self.get_uprobe_handler()?;
        let link_id = uprobe.attach(func, target, Some(pid))?;
        Ok(UProbeLinkId(link_id))
    }

    pub fn attach_perf_event(&mut self, addr: u64, pid: u32) -> anyhow::Result<PerfEventLinkId> {
        let perf = self.get_perf_event_handler()?;
        let link_id = perf.attach(
            PerfEventConfig::Breakpoint(BreakpointConfig::Instruction { address: addr }),
            PerfEventScope::OneProcess { pid, cpu: None },
            SamplePolicy::Period(1),
            false,
        )?;
        Ok(PerfEventLinkId(link_id))
    }

    pub fn attach_watchpoint(
        &mut self,
        addr: u64,
        len: u64,
        kind: WatchKind,
        pid: u32,
    ) -> anyhow::Result<PerfEventLinkId> {
        let perf = self.get_perf_event_handler()?;

        let r#type = match kind {
            WatchKind::Write => PerfBreakpointType::Write,
            WatchKind::Read => PerfBreakpointType::Read,
            WatchKind::ReadWrite => PerfBreakpointType::ReadWrite,
        };

        let length = match len {
            1 => PerfBreakpointLength::Len1,
            2 => PerfBreakpointLength::Len2,
            4 => PerfBreakpointLength::Len4,
            8 => PerfBreakpointLength::Len8,
            _ => {
                return Err(anyhow::anyhow!(
                    "unsupported watchpoint length {len} (supported: 1,2,4,8)"
                ));
            }
        };

        let link_id = perf.attach(
            PerfEventConfig::Breakpoint(BreakpointConfig::Data {
                r#type,
                address: addr,
                length,
            }),
            PerfEventScope::OneProcess { pid, cpu: None },
            SamplePolicy::Period(1),
            false,
        )?;
        Ok(PerfEventLinkId(link_id))
    }

    pub fn detach_perf_event(&mut self, link_id: PerfEventLinkId) -> anyhow::Result<()> {
        let perf = self.get_perf_event_handler()?;
        perf.detach(link_id.0)?;
        Ok(())
    }

    pub fn attach_uprobe_at(
        &mut self,
        target: impl AsRef<Path>,
        offset: u64,
        pid: u32,
    ) -> anyhow::Result<UProbeLinkId> {
        let uprobe = self.get_uprobe_handler()?;
        let link_id = uprobe.attach(offset, target, Some(pid))?;
        Ok(UProbeLinkId(link_id))
    }

    pub fn detach_uprobe(&mut self, link_id: UProbeLinkId) -> anyhow::Result<()> {
        let uprobe = self.get_uprobe_handler()?;
        uprobe.detach(link_id.0)?;
        Ok(())
    }

    fn get_uprobe_handler(&mut self) -> anyhow::Result<&mut UProbe> {
        Ok(self
            .0
            .program_mut(PROGRAM_UPROBE_HANDLER)
            .unwrap()
            .try_into()?)
    }

    fn get_perf_event_handler(&mut self) -> anyhow::Result<&mut PerfEvent> {
        Ok(self
            .0
            .program_mut(PROGRAM_PERF_EVENT_HANDLER)
            .unwrap()
            .try_into()?)
    }

    pub fn attach_sys_exit_execve(&mut self) -> anyhow::Result<TracePointLinkId> {
        let tracepoint = self.get_sys_exit_execve_handler()?;
        let link_id = tracepoint.attach("syscalls", "sys_exit_execve")?;
        Ok(TracePointLinkId(link_id))
    }

    pub fn detach_sys_exit_execve(&mut self, link_id: TracePointLinkId) -> anyhow::Result<()> {
        let tracepoint = self.get_sys_exit_execve_handler()?;
        tracepoint.detach(link_id.0)?;
        Ok(())
    }

    fn get_sys_exit_execve_handler(&mut self) -> anyhow::Result<&mut TracePoint> {
        Ok(self
            .0
            .program_mut(PROGRAM_SYS_EXIT_EXECVE_HANDLER)
            .unwrap()
            .try_into()?)
    }

    pub fn attach_sys_enter(&mut self) -> anyhow::Result<TracePointLinkId> {
        let tracepoint = self.get_sys_enter_handler()?;
        let link_id = tracepoint.attach("raw_syscalls", "sys_enter")?;
        Ok(TracePointLinkId(link_id))
    }

    pub fn detach_sys_enter(&mut self, link_id: TracePointLinkId) -> anyhow::Result<()> {
        let tracepoint = self.get_sys_enter_handler()?;
        tracepoint.detach(link_id.0)?;
        Ok(())
    }

    fn get_sys_enter_handler(&mut self) -> anyhow::Result<&mut TracePoint> {
        Ok(self
            .0
            .program_mut(PROGRAM_SYS_ENTER_HANDLER)
            .unwrap()
            .try_into()?)
    }

    pub fn attach_sys_exit(&mut self) -> anyhow::Result<TracePointLinkId> {
        let tracepoint = self.get_sys_exit_handler()?;
        let link_id = tracepoint.attach("raw_syscalls", "sys_exit")?;
        Ok(TracePointLinkId(link_id))
    }

    pub fn detach_sys_exit(&mut self, link_id: TracePointLinkId) -> anyhow::Result<()> {
        let tracepoint = self.get_sys_exit_handler()?;
        tracepoint.detach(link_id.0)?;
        Ok(())
    }

    fn get_sys_exit_handler(&mut self) -> anyhow::Result<&mut TracePoint> {
        Ok(self
            .0
            .program_mut(PROGRAM_SYS_EXIT_HANDLER)
            .unwrap()
            .try_into()?)
    }

    pub fn take_register_state(&mut self, pid: u32) -> anyhow::Result<RegisterState> {
        let mut register_states: HashMap<_, u32, RegisterState> =
            HashMap::try_from(self.0.map_mut(MAP_REGISTER_STATES).unwrap())?;
        let last_register_state = register_states.get(&pid, 0)?;
        register_states.remove(&pid)?;
        Ok(last_register_state)
    }
}
