use std::{ffi::CString, path::PathBuf};

use aya::{maps::HashMap, programs::UProbe};
use clap::Parser;
use ebpfdbg_common::RegisterState;
use log::{debug, warn};
use nix::{
    sys::{
        resource::{self, Resource},
        signal::{self, Signal},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::{self, ForkResult, Pid},
};
use which::which;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Opt {
    #[arg(short, long)]
    target: Option<String>,
    #[arg(short, long)]
    func: String,

    program: String,
    #[arg(allow_hyphen_values = true)]
    args: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    if let Err(e) = resource::setrlimit(
        Resource::RLIMIT_MEMLOCK,
        resource::RLIM_INFINITY,
        resource::RLIM_INFINITY,
    ) {
        debug!("remove limit on locked memory failed, err is: {e}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpfdbg"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let Opt {
        target,
        func,
        program,
        args,
    } = opt;

    let target = match target {
        Some(target) => PathBuf::from(target),
        None => which(&program)?,
    };

    let program = CString::new(program)?;
    let mut args: Vec<CString> = args
        .into_iter()
        .map(CString::new)
        .collect::<Result<_, _>>()?;
    args.insert(0, program.clone());

    match unsafe { unistd::fork() }? {
        ForkResult::Child => {
            signal::kill(Pid::this(), Signal::SIGSTOP)?;
            unistd::execvp(&program, &args)?;
            unreachable!();
        }
        ForkResult::Parent { child } => {
            let pid = child.as_raw() as u32;
            let uprobe: &mut UProbe = ebpf.program_mut("ebpfdbg").unwrap().try_into()?;
            uprobe.load()?;
            uprobe.attach(func.as_str(), target, Some(pid))?;

            let mut register_states: HashMap<_, u32, RegisterState> =
                HashMap::try_from(ebpf.map_mut("REGISTER_STATES").unwrap())?;

            loop {
                signal::kill(child, Signal::SIGCONT)?;
                match waitpid(child, Some(WaitPidFlag::WUNTRACED))? {
                    WaitStatus::Stopped(_, _) => {
                        let reg_state = register_states.get(&pid, 0)?;
                        println!("Register state at function entry: {reg_state:#x?}");
                        let _ = register_states.remove(&pid);
                    }
                    WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _) => {
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}
