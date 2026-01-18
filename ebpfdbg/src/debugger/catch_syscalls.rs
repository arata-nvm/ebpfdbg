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

        if let Some(catch_state) = self.syscall_catch.take() {
            self.ebpf
                .detach_sys_enter(catch_state.sys_enter_link)
                .map_err(|e| {
                    warn!("failed to detach sys_enter handler: {:?}", e);
                    TargetError::NonFatal
                })?;
            self.ebpf
                .detach_sys_exit(catch_state.sys_exit_link)
                .map_err(|e| {
                    warn!("failed to detach sys_exit handler: {:?}", e);
                    TargetError::NonFatal
                })?;
        }

        let sys_enter_link = self.ebpf.attach_sys_enter().map_err(|e| {
            warn!("failed to attach sys_enter handler: {:?}", e);
            TargetError::NonFatal
        })?;

        let sys_exit_link = self.ebpf.attach_sys_exit().map_err(|e| {
            warn!("failed to attach sys_exit handler: {:?}", e);
            TargetError::NonFatal
        })?;

        self.syscall_catch = Some(crate::debugger::SyscallCatchState {
            sys_enter_link,
            sys_exit_link,
            syscall_filter,
        });

        Ok(())
    }

    fn disable_catch_syscalls(&mut self) -> TargetResult<(), Self> {
        debug!("disable_catch_syscalls()");

        if let Some(catch_state) = self.syscall_catch.take() {
            self.ebpf
                .detach_sys_enter(catch_state.sys_enter_link)
                .map_err(|e| {
                    warn!("failed to detach sys_enter handler: {:?}", e);
                    TargetError::NonFatal
                })?;
            self.ebpf
                .detach_sys_exit(catch_state.sys_exit_link)
                .map_err(|e| {
                    warn!("failed to detach sys_exit handler: {:?}", e);
                    TargetError::NonFatal
                })?;
        }

        Ok(())
    }
}
