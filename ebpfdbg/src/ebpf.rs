use std::path::Path;

use aya::{Ebpf, maps::HashMap, programs::UProbe};
use ebpfdbg_common::RegisterState;

#[derive(Debug)]
pub struct EbpfProgram(Ebpf);

#[derive(Debug)]
pub struct UProbeLinkId(aya::programs::uprobe::UProbeLinkId);

const PROGRAM_UPROBE_HANDLER: &str = "uprobe_handler";
const MAP_REGISTER_STATES: &str = "REGISTER_STATES";

impl EbpfProgram {
    pub fn load() -> anyhow::Result<Self> {
        let ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/ebpfdbg"
        )))?;

        let mut this = EbpfProgram(ebpf);
        let uprobe = this.get_uprobe_handler()?;
        uprobe.load()?;

        Ok(this)
    }

    pub fn attach_uprobe(
        &mut self,
        target: impl AsRef<Path>,
        func: &str,
        pid: u32,
    ) -> anyhow::Result<UProbeLinkId> {
        let uprobe = self.get_uprobe_handler()?;
        let link_id = uprobe.attach(func, target, Some(pid))?;
        Ok(UProbeLinkId(link_id))
    }

    pub fn attach_uprobe_at(
        &mut self,
        target: impl AsRef<Path>,
        offset: u64,
        pid: u32,
    ) -> anyhow::Result<UProbeLinkId> {
        let uprobe = self.get_uprobe_handler()?;
        let link_id = uprobe.attach(offset, target, Some(pid))?;
        Ok(UProbeLinkId(link_id))
    }

    pub fn detach_uprobe(&mut self, link_id: UProbeLinkId) -> anyhow::Result<()> {
        let uprobe = self.get_uprobe_handler()?;
        uprobe.detach(link_id.0)?;
        Ok(())
    }

    fn get_uprobe_handler(&mut self) -> anyhow::Result<&mut UProbe> {
        Ok(self
            .0
            .program_mut(PROGRAM_UPROBE_HANDLER)
            .unwrap()
            .try_into()?)
    }

    pub fn take_register_state(&mut self, pid: u32) -> anyhow::Result<RegisterState> {
        let mut register_states: HashMap<_, u32, RegisterState> =
            HashMap::try_from(self.0.map_mut(MAP_REGISTER_STATES).unwrap())?;
        let last_register_state = register_states.get(&pid, 0)?;
        register_states.remove(&pid)?;
        Ok(last_register_state)
    }
}
