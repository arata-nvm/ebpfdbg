use gdbstub::{
    common::Pid,
    target::{TargetResult, ext::exec_file::ExecFile},
};
use log::debug;

use crate::debugger::Debugger;

impl ExecFile for Debugger {
    fn get_exec_file(
        &self,
        _pid: Option<Pid>,
        offset: u64,
        length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        debug!("get_exec_file(offset: {}, length: {})", offset, length);
        let offset = offset as usize;
        if offset >= self.exec_file.len() {
            return Ok(0);
        }

        let len = std::cmp::min(length, self.exec_file.len() - offset);
        buf[..len].copy_from_slice(&self.exec_file.as_bytes()[offset..offset + len]);
        Ok(len)
    }
}
