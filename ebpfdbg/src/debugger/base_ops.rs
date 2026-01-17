use gdbstub::{
    arch::Arch,
    common::Signal,
    target::{
        TargetError, TargetResult,
        ext::base::{
            single_register_access::{SingleRegisterAccess, SingleRegisterAccessOps},
            singlethread::{
                SingleThreadBase, SingleThreadResume, SingleThreadResumeOps,
                SingleThreadSingleStep, SingleThreadSingleStepOps,
            },
        },
    },
};
use gdbstub_arch::x86::reg::id::{X86_64CoreRegId, X86SegmentRegId};
use log::{debug, warn};

use crate::{
    arch::{X86_64_SSE_SegmentsRegId, X86_64SegmentsRegId},
    debugger::Debugger,
    util,
};

impl SingleThreadBase for Debugger {
    fn read_registers(
        &mut self,
        regs: &mut <Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        debug!("read_registers()");

        regs.core.regs[0] = self.last_register_state.rax;
        regs.core.regs[1] = self.last_register_state.rbx;
        regs.core.regs[2] = self.last_register_state.rcx;
        regs.core.regs[3] = self.last_register_state.rdx;
        regs.core.regs[4] = self.last_register_state.rsi;
        regs.core.regs[5] = self.last_register_state.rdi;
        regs.core.regs[6] = self.last_register_state.rbp;
        regs.core.regs[7] = self.last_register_state.rsp;
        regs.core.regs[8] = self.last_register_state.r8;
        regs.core.regs[9] = self.last_register_state.r9;
        regs.core.regs[10] = self.last_register_state.r10;
        regs.core.regs[11] = self.last_register_state.r11;
        regs.core.regs[12] = self.last_register_state.r12;
        regs.core.regs[13] = self.last_register_state.r13;
        regs.core.regs[14] = self.last_register_state.r14;
        regs.core.regs[15] = self.last_register_state.r15;

        regs.core.eflags = self.last_register_state.eflags as u32;
        regs.core.rip = self.last_register_state.rip;
        regs.core.segments.cs = self.last_register_state.cs as u32;
        regs.core.segments.ss = self.last_register_state.ss as u32;
        regs.core.segments.ds = self.last_register_state.ds as u32;
        regs.core.segments.es = self.last_register_state.es as u32;

        regs.segments.fs_base = self.last_register_state.fsbase;
        regs.segments.gs_base = self.last_register_state.gsbase;

        Ok(())
    }

    fn write_registers(
        &mut self,
        _regs: &<Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        debug!("write_registers()");

        unimplemented!();
    }

    fn support_single_register_access(&mut self) -> Option<SingleRegisterAccessOps<'_, (), Self>> {
        Some(self)
    }

    fn read_addrs(
        &mut self,
        start_addr: <Self::Arch as Arch>::Usize,
        data: &mut [u8],
    ) -> TargetResult<usize, Self> {
        debug!(
            "read_addrs(start_addr: {:x}, size: {:x})",
            start_addr,
            data.len()
        );

        self.read_memory(start_addr, data).map_err(|e| {
            warn!("failed to read memory at {:x}: {:?}", start_addr, e);
            TargetError::NonFatal
        })
    }

    fn write_addrs(
        &mut self,
        start_addr: <Self::Arch as Arch>::Usize,
        data: &[u8],
    ) -> TargetResult<(), Self> {
        debug!(
            "write_addrs(start_addr: {:x}, data: {:x?})",
            start_addr, data
        );

        self.write_memory(start_addr, data).map_err(|e| {
            warn!("failed to write memory at {:x}: {:?}", start_addr, e);
            TargetError::NonFatal
        })?;

        Ok(())
    }

    fn support_resume(&mut self) -> Option<SingleThreadResumeOps<'_, Self>> {
        Some(self)
    }
}

impl SingleRegisterAccess<()> for Debugger {
    fn read_register(
        &mut self,
        _tid: (),
        reg_id: <Self::Arch as Arch>::RegId,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        debug!("read_register(reg_id: {:?})", reg_id);

        let value = match reg_id {
            X86_64_SSE_SegmentsRegId::Core(X86_64CoreRegId::Gpr(id)) => match id {
                0 => self.last_register_state.rax,
                1 => self.last_register_state.rbx,
                2 => self.last_register_state.rcx,
                3 => self.last_register_state.rdx,
                4 => self.last_register_state.rsi,
                5 => self.last_register_state.rdi,
                6 => self.last_register_state.rbp,
                7 => self.last_register_state.rsp,
                8 => self.last_register_state.r8,
                9 => self.last_register_state.r9,
                10 => self.last_register_state.r10,
                11 => self.last_register_state.r11,
                12 => self.last_register_state.r12,
                13 => self.last_register_state.r13,
                14 => self.last_register_state.r14,
                15 => self.last_register_state.r15,
                _ => unreachable!(),
            },
            X86_64_SSE_SegmentsRegId::Core(X86_64CoreRegId::Rip) => self.last_register_state.rip,
            X86_64_SSE_SegmentsRegId::Core(X86_64CoreRegId::Eflags) => {
                self.last_register_state.eflags
            }
            X86_64_SSE_SegmentsRegId::Core(X86_64CoreRegId::Segment(id)) => match id {
                X86SegmentRegId::CS => self.last_register_state.cs,
                X86SegmentRegId::SS => self.last_register_state.ss,
                X86SegmentRegId::DS => self.last_register_state.ds as u64,
                X86SegmentRegId::ES => self.last_register_state.es as u64,
                _ => unimplemented!(),
            },
            X86_64_SSE_SegmentsRegId::Segments(segments) => match segments {
                X86_64SegmentsRegId::FsBase => self.last_register_state.fsbase,
                X86_64SegmentsRegId::GsBase => self.last_register_state.gsbase,
            },
            _ => unimplemented!(),
        };
        let value_bytes = value.to_le_bytes();
        let len = buf.len().min(value_bytes.len());
        buf[..len].copy_from_slice(&value_bytes[..len]);
        Ok(len)
    }

    fn write_register(
        &mut self,
        _tid: (),
        reg_id: <Self::Arch as Arch>::RegId,
        val: &[u8],
    ) -> TargetResult<(), Self> {
        debug!("write_register(reg_id: {:?}, val: {:x?})", reg_id, val);

        unimplemented!();
    }
}

impl SingleThreadResume for Debugger {
    fn resume(&mut self, _signal: Option<Signal>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn support_single_step(&mut self) -> Option<SingleThreadSingleStepOps<'_, Self>> {
        Some(self)
    }
}

impl SingleThreadSingleStep for Debugger {
    fn step(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
        debug!("step(signal: {signal:?})");

        let pc = self.last_register_state.rip;
        let mut code = [0u8; 16];
        self.read_memory(pc, &mut code)?;

        let next_pc = util::predict_next_pc(pc, &code)?;
        self.add_tmp_breakpoint_at(next_pc)?;

        Ok(())
    }
}
