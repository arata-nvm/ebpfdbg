use gdbstub::{
    arch::Arch,
    target::{
        TargetError, TargetResult,
        ext::breakpoints::{Breakpoints, SwBreakpoint, SwBreakpointOps},
    },
};
use log::{debug, warn};

use crate::debugger::Debugger;

impl Breakpoints for Debugger {
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<'_, Self>> {
        Some(self)
    }
}

impl SwBreakpoint for Debugger {
    fn add_sw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        debug!("add_sw_breakpoint(addr: {:x})", addr);
        match self.add_breakpoint_at(addr) {
            Ok(_) => Ok(true),
            Err(err) => {
                warn!("failed to add sw breakpoint at {:#x}: {:?}", addr, err);
                Err(TargetError::NonFatal)
            }
        }
    }

    fn remove_sw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        debug!("remove_sw_breakpoint(addr: {:x})", addr);
        match self.remove_breakpoint_at(addr) {
            Ok(_) => Ok(true),
            Err(err) => {
                warn!("failed to remove sw breakpoint at {:#x}: {:?}", addr, err);
                Err(TargetError::NonFatal)
            }
        }
    }
}
