use gdbstub::target::{
    Target,
    ext::{auxv::AuxvOps, base::BaseOps, exec_file::ExecFileOps, extended_mode::ExtendedModeOps, host_io::HostIoOps, section_offsets::SectionOffsetsOps},
};

use crate::{arch::X86_64_SSE_Segments, debugger::Debugger};

impl Target for Debugger {
    type Arch = X86_64_SSE_Segments;
    type Error = anyhow::Error;

    fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }

    fn support_auxv(&mut self) -> Option<AuxvOps<'_, Self>> {
        Some(self)
    }

    fn support_exec_file(&mut self) -> Option<ExecFileOps<'_, Self>> {
        Some(self)
    }

    fn support_extended_mode(&mut self) -> Option<ExtendedModeOps<'_, Self>> {
        Some(self)
    }

    fn support_host_io(&mut self) -> Option<HostIoOps<'_, Self>> {
        Some(self)
    }

    fn support_section_offsets(&mut self) -> Option<SectionOffsetsOps<'_, Self>> {
        Some(self)
    }

    fn guard_rail_implicit_sw_breakpoints(&self) -> bool {
        true
    }
}
