use gdbstub::{
    arch::Arch,
    target::{
        TargetError, TargetResult,
        ext::breakpoints::{
            Breakpoints, HwBreakpoint, HwBreakpointOps, HwWatchpoint, HwWatchpointOps,
            SwBreakpoint, SwBreakpointOps, WatchKind,
        },
    },
};
use log::{debug, warn};

use crate::debugger::Debugger;

impl Breakpoints for Debugger {
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<'_, Self>> {
        Some(self)
    }

    fn support_hw_breakpoint(&mut self) -> Option<HwBreakpointOps<'_, Self>> {
        Some(self)
    }

    fn support_hw_watchpoint(&mut self) -> Option<HwWatchpointOps<'_, Self>> {
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
        match self.add_sw_breakpoint_at(addr) {
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
        match self.remove_sw_breakpoint_at(addr) {
            Ok(_) => Ok(true),
            Err(err) => {
                warn!("failed to remove sw breakpoint at {:#x}: {:?}", addr, err);
                Err(TargetError::NonFatal)
            }
        }
    }
}

impl HwBreakpoint for Debugger {
    fn add_hw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        debug!("add_hw_breakpoint(addr: {:x})", addr);
        match self.add_hw_breakpoint_at(addr) {
            Ok(_) => Ok(true),
            Err(err) => {
                warn!("failed to add hw breakpoint at {:#x}: {:?}", addr, err);
                Err(TargetError::NonFatal)
            }
        }
    }

    fn remove_hw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        debug!("remove_hw_breakpoint(addr: {:x})", addr);
        match self.remove_hw_breakpoint_at(addr) {
            Ok(_) => Ok(true),
            Err(err) => {
                warn!("failed to remove hw breakpoint at {:#x}: {:?}", addr, err);
                Err(TargetError::NonFatal)
            }
        }
    }
}

impl HwWatchpoint for Debugger {
    fn add_hw_watchpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        len: <Self::Arch as Arch>::Usize,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        debug!(
            "add_hw_watchpoint(addr: {:x}, len: {}, kind: {:?})",
            addr, len, kind
        );
        match self.add_hw_watchpoint_at(addr, len, kind.into()) {
            Ok(_) => Ok(true),
            Err(err) => {
                warn!(
                    "failed to add hw watchpoint at {:#x} len {} kind {:?}: {:?}",
                    addr, len, kind, err
                );
                Err(TargetError::NonFatal)
            }
        }
    }

    fn remove_hw_watchpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        len: <Self::Arch as Arch>::Usize,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        debug!(
            "remove_hw_watchpoint(addr: {:x}, len: {}, kind: {:?})",
            addr, len, kind
        );
        match self.remove_hw_watchpoint_at(addr, len, kind.into()) {
            Ok(_) => Ok(true),
            Err(err) => {
                warn!(
                    "failed to remove hw watchpoint at {:#x} len {} kind {:?}: {:?}",
                    addr, len, kind, err
                );
                Err(TargetError::NonFatal)
            }
        }
    }
}
