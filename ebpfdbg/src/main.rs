use std::path::PathBuf;

use clap::Parser;
use ebpfdbg::debugger::Debugger;
use log::{debug, info};
use nix::sys::{
    resource::{self, Resource},
    wait::WaitStatus,
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

    let mut debugger = Debugger::launch(program, args)?;
    debugger.add_breakpoint(target, &func)?;
    loop {
        match debugger.continue_exec()? {
            WaitStatus::Stopped(_, _) => {
                let reg_state = debugger.take_register_state()?;
                info!("Register state at function entry: {reg_state:#x?}");
            }
            WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _) => {
                break;
            }
            _ => {}
        }
    }

    Ok(())
}
