use gdbstub::target::{
    Target,
    ext::{base::BaseOps, extended_mode::ExtendedModeOps, host_io::HostIoOps},
};

use crate::{arch::X86_64_SSE_Segments, debugger::Debugger};

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
