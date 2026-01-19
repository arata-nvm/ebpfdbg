use std::collections::HashSet;

use gdbstub::target::{
    TargetError, TargetResult,
    ext::catch_syscalls::{CatchSyscalls, SyscallNumbers},
};
use log::{debug, warn};

use crate::debugger::Debugger;

impl CatchSyscalls for Debugger {
    fn enable_catch_syscalls(
        &mut self,
        syscalls: Option<SyscallNumbers<'_, u64>>,
    ) -> TargetResult<(), Self> {
        let syscall_filter = syscalls.map(|numbers| numbers.into_iter().collect::<HashSet<u64>>());

        debug!(
            "enable_catch_syscalls(syscalls: {:?})",
            syscall_filter
                .as_ref()
                .map(|f| format!("{} syscalls", f.len()))
                .unwrap_or_else(|| "all".to_string())
        );

        self.enable_syscall_catch(syscall_filter).map_err(|e| {
            warn!("failed to enable syscall catch handlers: {:?}", e);
            TargetError::NonFatal
        })
    }

    fn disable_catch_syscalls(&mut self) -> TargetResult<(), Self> {
        debug!("disable_catch_syscalls()");

        self.disable_syscall_catch().map_err(|e| {
            warn!("failed to disable syscall catch handlers: {:?}", e);
            TargetError::NonFatal
        })
    }
}
