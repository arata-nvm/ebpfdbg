use std::net::{TcpListener, TcpStream};

use clap::Parser;
use ebpfdbg::debugger::{Debugger, StopReason};
use gdbstub::{
    common::Signal,
    conn::Connection,
    stub::{
        GdbStub, SingleThreadStopReason,
        run_blocking::{BlockingEventLoop, Event, WaitForStopReasonError},
    },
    target::{Target, ext::catch_syscalls::CatchSyscallPosition},
};
use log::{debug, info};
use nix::sys::resource::{self, Resource};

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Opt {
    program: String,
    #[arg(allow_hyphen_values = true)]
    args: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    if let Err(e) = resource::setrlimit(
        Resource::RLIMIT_MEMLOCK,
        resource::RLIM_INFINITY,
        resource::RLIM_INFINITY,
    ) {
        debug!("remove limit on locked memory failed, err is: {e}");
    }

    let Opt { program, args } = opt;

    let mut debugger = Debugger::launch(program, args)?;
    debugger.continue_to_start()?;

    let conn = wait_for_tcp(9001)?;
    let gdbstub = GdbStub::new(conn);
    gdbstub.run_blocking::<GdbEventLoop>(&mut debugger)?;

    Ok(())
}

enum GdbEventLoop {}

impl BlockingEventLoop for GdbEventLoop {
    type Target = Debugger;
    type Connection = TcpStream;
    type StopReason = SingleThreadStopReason<u64>;

    fn wait_for_stop_reason(
        target: &mut Self::Target,
        _conn: &mut Self::Connection,
    ) -> Result<
        Event<Self::StopReason>,
        WaitForStopReasonError<
            <Self::Target as Target>::Error,
            <Self::Connection as Connection>::Error,
        >,
    > {
        let stop_reason = match target
            .continue_exec()
            .map_err(WaitForStopReasonError::Target)?
        {
            StopReason::Exited(status) => SingleThreadStopReason::Exited(status),
            StopReason::Signaled(signal) => SingleThreadStopReason::Signal(Signal(signal as u8)),
            StopReason::SwBreak => SingleThreadStopReason::SwBreak(()),
            StopReason::HwBreak => SingleThreadStopReason::HwBreak(()),
            StopReason::Watch { kind, addr } => SingleThreadStopReason::Watch {
                tid: (),
                kind: kind.into(),
                addr,
            },
            StopReason::SyscallEntry(syscall_num) => SingleThreadStopReason::CatchSyscall {
                tid: None,
                number: syscall_num,
                position: CatchSyscallPosition::Entry,
            },
            StopReason::SyscallExit(syscall_num) => SingleThreadStopReason::CatchSyscall {
                tid: None,
                number: syscall_num,
                position: CatchSyscallPosition::Return,
            },
        };
        Ok(Event::TargetStopped(stop_reason))
    }

    fn on_interrupt(
        _target: &mut Self::Target,
    ) -> Result<Option<Self::StopReason>, <Self::Target as Target>::Error> {
        unimplemented!();
    }
}

fn wait_for_tcp(port: u16) -> anyhow::Result<TcpStream> {
    let sockaddr = format!("127.0.0.1:{port}");
    info!("Waiting for a GDB connection on {sockaddr}...");

    let sock = TcpListener::bind(sockaddr)?;
    let (stream, addr) = sock.accept()?;
    info!("Debugger connected from {addr}");

    Ok(stream)
}
