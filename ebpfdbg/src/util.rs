use capstone::{
    Capstone,
    arch::{BuildsCapstone, x86::ArchMode},
};

pub fn predict_next_pc(pc: u64, code: &[u8]) -> anyhow::Result<u64> {
    let cs = Capstone::new()
        .x86()
        .mode(ArchMode::Mode64)
        .detail(true)
        .build()?;

    let insns = cs.disasm_count(&code, pc, 1)?;
    let insn = insns.get(0).unwrap();

    Ok(pc + insn.len() as u64)
}
