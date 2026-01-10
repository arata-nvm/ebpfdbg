use gdbstub::target::{
    TargetResult,
    ext::extended_mode::{
        Args, AttachKind, CurrentActivePid, CurrentActivePidOps, ExtendedMode, ShouldTerminate,
    },
};

use crate::debugger::Debugger;

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
