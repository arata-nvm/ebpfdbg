#![no_std]

pub mod syscall_type {
    /// Not a syscall
    pub const NONE: u8 = 0;
    /// Syscall entry
    pub const ENTRY: u8 = 1;
    /// Syscall exit
    pub const EXIT: u8 = 2;
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RegisterState {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub orig_rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub es: u16,
    pub ds: u16,
    pub fsbase: u64,
    pub gsbase: u64,
    pub syscall_type: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RegisterState {}
