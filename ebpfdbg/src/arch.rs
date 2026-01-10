use std::num::NonZeroUsize;

use gdbstub::arch::{Arch, RegId, Registers};
use gdbstub_arch::x86::{
    X86_64_SSE,
    reg::{X86_64CoreRegs, id::X86_64CoreRegId},
};

#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub enum X86_64_SSE_Segments {}

impl Arch for X86_64_SSE_Segments {
    type Usize = <X86_64_SSE as Arch>::Usize;
    type Registers = X86_64_SSE_SegmentsRegs;
    type RegId = X86_64_SSE_SegmentsRegId;
    type BreakpointKind = <X86_64_SSE as Arch>::BreakpointKind;

    fn target_description_xml() -> Option<&'static str> {
        Some(
            r#"<target version="1.0">
              <architecture>i386:x86-64</architecture>
              <feature name="org.gnu.gdb.i386.sse"></feature>
              <feature name="org.gnu.gdb.i386.segments"></feature>
            </target>"#,
        )
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub struct X86_64_SSE_SegmentsRegs {
    pub core: X86_64CoreRegs,
    pub segments: X86_64SegmentsRegs,
}

impl Registers for X86_64_SSE_SegmentsRegs {
    type ProgramCounter = <X86_64CoreRegs as Registers>::ProgramCounter;

    fn pc(&self) -> Self::ProgramCounter {
        self.core.pc()
    }

    fn gdb_serialize(&self, mut write_byte: impl FnMut(Option<u8>)) {
        macro_rules! write_bytes {
            ($bytes:expr) => {
                for b in $bytes {
                    write_byte(Some(*b))
                }
            };
        }

        self.core.gdb_serialize(&mut write_byte);
        write_bytes!(&0u64.to_le_bytes());
        self.segments.gdb_serialize(&mut write_byte);
    }

    fn gdb_deserialize(&mut self, bytes: &[u8]) -> Result<(), ()> {
        let core_size = 0x218;
        self.core.gdb_deserialize(&bytes[..core_size])?;
        self.segments.gdb_deserialize(&bytes[(core_size + 8)..])?;

        Ok(())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct X86_64SegmentsRegs {
    pub fs_base: u64,
    pub gs_base: u64,
}

impl Registers for X86_64SegmentsRegs {
    type ProgramCounter = <X86_64CoreRegs as Registers>::ProgramCounter;

    // HACK: this struct is never used as an architecture's main register file, so
    // using a dummy value here is fine.
    fn pc(&self) -> Self::ProgramCounter {
        0
    }

    fn gdb_serialize(&self, mut write_byte: impl FnMut(Option<u8>)) {
        macro_rules! write_bytes {
            ($bytes:expr) => {
                for b in $bytes {
                    write_byte(Some(*b))
                }
            };
        }

        write_bytes!(&self.fs_base.to_le_bytes());
        write_bytes!(&self.gs_base.to_le_bytes());
    }

    fn gdb_deserialize(&mut self, bytes: &[u8]) -> Result<(), ()> {
        if bytes.len() < core::mem::size_of::<u64>() * 2 {
            return Err(());
        }

        let mut regs = bytes
            .chunks_exact(8)
            .map(|x| u64::from_le_bytes(x.try_into().unwrap()));

        self.fs_base = regs.next().ok_or(())?;
        self.gs_base = regs.next().ok_or(())?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub enum X86_64_SSE_SegmentsRegId {
    Core(X86_64CoreRegId),
    Segments(X86_64SegmentsRegId),
}

impl RegId for X86_64_SSE_SegmentsRegId {
    fn from_raw_id(id: usize) -> Option<(Self, Option<std::num::NonZeroUsize>)> {
        match id {
            id if id <= 56 => {
                X86_64CoreRegId::from_raw_id(id).map(|(reg, ext)| (Self::Core(reg), ext))
            }
            58 => Some((
                Self::Segments(X86_64SegmentsRegId::FsBase),
                Some(NonZeroUsize::new(8)?),
            )),
            59 => Some((
                Self::Segments(X86_64SegmentsRegId::GsBase),
                Some(NonZeroUsize::new(8)?),
            )),
            _ => return None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum X86_64SegmentsRegId {
    FsBase,
    GsBase,
}
