use std::os::fd::{BorrowedFd, IntoRawFd};

use gdbstub::target::ext::host_io::{
    HostIo, HostIoClose, HostIoCloseOps, HostIoErrno, HostIoError, HostIoOpen, HostIoOpenFlags,
    HostIoOpenMode, HostIoOpenOps, HostIoPread, HostIoPreadOps, HostIoReadlink, HostIoReadlinkOps,
    HostIoResult,
};
use nix::{
    fcntl::{self, OFlag},
    sys::{stat::Mode, uio},
    unistd,
};

use crate::debugger::Debugger;

impl HostIo for Debugger {
    fn support_open(&mut self) -> Option<HostIoOpenOps<'_, Self>> {
        Some(self)
    }

    fn support_readlink(&mut self) -> Option<HostIoReadlinkOps<'_, Self>> {
        Some(self)
    }

    fn support_pread(&mut self) -> Option<HostIoPreadOps<'_, Self>> {
        Some(self)
    }

    fn support_close(&mut self) -> Option<HostIoCloseOps<'_, Self>> {
        Some(self)
    }
}

impl HostIoOpen for Debugger {
    fn open(
        &mut self,
        filename: &[u8],
        flags: HostIoOpenFlags,
        mode: HostIoOpenMode,
    ) -> HostIoResult<u32, Self> {
        let flags = OFlag::from_bits(flags.bits() as i32).expect("invalid flags");
        let mode = Mode::from_bits(mode.bits() as u32).expect("invalid mode");
        let fd =
            fcntl::open(filename, flags, mode).map_err(|e| HostIoError::Errno(map_errno(e)))?;
        let fd = fd.into_raw_fd();
        Ok(fd as u32)
    }
}

impl HostIoReadlink for Debugger {
    fn readlink(&mut self, filename: &[u8], buf: &mut [u8]) -> HostIoResult<usize, Self> {
        let path = fcntl::readlink(filename).map_err(|e| HostIoError::Errno(map_errno(e)))?;
        let path_bytes = path.as_encoded_bytes();
        let len = buf.len().min(path_bytes.len());
        buf[..len].copy_from_slice(&path_bytes[..len]);
        Ok(len)
    }
}

impl HostIoPread for Debugger {
    fn pread(
        &mut self,
        fd: u32,
        count: usize,
        offset: u64,
        buf: &mut [u8],
    ) -> HostIoResult<usize, Self> {
        let fd = unsafe { BorrowedFd::borrow_raw(fd as i32) };
        let nread = uio::pread(fd, &mut buf[..count], offset as i64)
            .map_err(|e| HostIoError::Errno(map_errno(e)))?;
        Ok(nread)
    }
}

impl HostIoClose for Debugger {
    fn close(&mut self, fd: u32) -> HostIoResult<(), Self> {
        unistd::close(fd as i32).map_err(|e| HostIoError::Errno(map_errno(e)))?;
        Ok(())
    }
}

fn map_errno(e: nix::errno::Errno) -> HostIoErrno {
    unsafe { std::mem::transmute::<_, HostIoErrno>(e as u16) }
}
