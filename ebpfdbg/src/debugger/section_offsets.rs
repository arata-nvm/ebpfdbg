use gdbstub::{
    arch::Arch,
    target::ext::section_offsets::{Offsets, SectionOffsets},
};
use log::debug;

use crate::{debugger::Debugger, proc::find_text_data_segment_bases};

impl SectionOffsets for Debugger {
    fn get_section_offsets(&mut self) -> Result<Offsets<<Self::Arch as Arch>::Usize>, Self::Error> {
        debug!("get_section_offsets()");
        let (text_seg, data_seg) = find_text_data_segment_bases(self.pid, &self.exec_file)?;
        Ok(Offsets::Segments {
            text_seg,
            data_seg: Some(data_seg),
        })
    }
}
