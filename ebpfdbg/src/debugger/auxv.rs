use gdbstub::target::{TargetResult, ext::auxv::Auxv};

use crate::debugger::Debugger;

impl Auxv for Debugger {
    fn get_auxv(&self, offset: u64, length: usize, buf: &mut [u8]) -> TargetResult<usize, Self> {
        let pid = self.pid_raw();
        let auvx = std::fs::read(format!("/proc/{pid}/auxv"))?;

        let offset = offset as usize;
        if offset >= auvx.len() {
            return Ok(0);
        }

        let len = std::cmp::min(length, auvx.len() - offset);
        buf[..len].copy_from_slice(&auvx[offset..offset + len]);
        Ok(len)
    }
}
