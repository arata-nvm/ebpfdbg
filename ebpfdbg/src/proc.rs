use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader},
    sync::{Mutex, OnceLock},
};

use log::debug;
use nix::unistd::Pid;

static PROC_MAP_CACHE: OnceLock<Mutex<HashMap<i32, Vec<Mapping>>>> = OnceLock::new();

#[derive(Debug)]
struct Mapping {
    start_addr: u64,
    end_addr: u64,
    perm: String,
    offset: u64,
    target: String,
}

pub(crate) fn find_target_and_offset(pid: Pid, addr: u64) -> anyhow::Result<(String, u64)> {
    debug!("looking for address {addr:x} in /proc/{pid}/maps");

    let pid_raw = pid.as_raw();
    let cache = PROC_MAP_CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    {
        let cache_guard = cache
            .lock()
            .map_err(|_| anyhow::anyhow!("failed to lock PROC_MAP_CACHE"))?;

        if let Some(mappings) = cache_guard.get(&pid_raw) {
            if let Some(mapping) = mappings
                .iter()
                .find(|m| m.start_addr <= addr && addr < m.end_addr)
            {
                debug!("found address {addr:x} in cached mapping: {:x?}", mapping);
                let offset = addr - mapping.start_addr + mapping.offset;
                return Ok((mapping.target.clone(), offset));
            }
        }
    }

    let fresh_mappings = parse_proc_map(pid)?;

    let mut cache_guard = cache
        .lock()
        .map_err(|_| anyhow::anyhow!("failed to lock PROC_MAP_CACHE"))?;
    cache_guard.insert(pid_raw, fresh_mappings);

    let mappings = cache_guard
        .get(&pid_raw)
        .expect("mappings must exist after insertion");

    let mapping = mappings
        .iter()
        .find(|m| m.start_addr <= addr && addr < m.end_addr)
        .ok_or_else(|| anyhow::anyhow!("address {addr:x} not found in /proc/{pid}/maps"))?;

    debug!("found address {addr:x} in mapping: {:x?}", mapping);
    let offset = addr - mapping.start_addr + mapping.offset;
    Ok((mapping.target.clone(), offset))
}

pub(crate) fn find_text_data_segment_bases(
    pid: Pid,
    exec_file: &str,
) -> anyhow::Result<(u64, u64)> {
    let mappings = parse_proc_map(pid)?;
    let mut text_base = None;
    let mut data_base = None;

    for mapping in mappings {
        if mapping.target != exec_file {
            continue;
        }

        if mapping.perm == "r-xp" && text_base.is_none() {
            text_base = Some(mapping.start_addr);
        } else if mapping.perm == "rw-p" && data_base.is_none() {
            data_base = Some(mapping.start_addr);
        }
        if text_base.is_some() && data_base.is_some() {
            break;
        }
    }

    text_base.zip(data_base).ok_or_else(|| {
        anyhow::anyhow!(
            "could not find text and data segment bases for {exec_file} in /proc/{pid}/maps"
        )
    })
}

fn parse_proc_map(pid: Pid) -> anyhow::Result<Vec<Mapping>> {
    let f = File::open(format!("/proc/{pid}/maps"))?;
    let reader = BufReader::new(f);

    let mut mappings = Vec::new();
    for line in reader.lines() {
        // e.g. 59fa1df7a000-59fa1dfaa000 r--p 00000000 08:02 7602732                    /usr/bin/bash
        let line = line?;
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 6 {
            continue;
        }

        let addrs = parts[0].split('-').collect::<Vec<_>>();
        if addrs.len() != 2 {
            continue;
        }

        let start_addr = u64::from_str_radix(addrs[0], 16)?;
        let end_addr = u64::from_str_radix(addrs[1], 16)?;
        let perm = parts[1].to_string();
        let offset = u64::from_str_radix(parts[2], 16)?;
        let target = parts[5].to_string();

        mappings.push(Mapping {
            start_addr,
            end_addr,
            perm,
            offset,
            target,
        });
    }

    Ok(mappings)
}
