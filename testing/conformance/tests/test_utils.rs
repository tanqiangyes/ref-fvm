use std::collections::{HashMap, HashSet};
use std::env::var;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::{fmt, iter};

use anyhow::{anyhow, Result};
use async_std::{stream, sync, task};
use cid::Cid;
use colored::*;
use conformance_tests::vector::{MessageVector, Selector, TestVector, Variant};
use conformance_tests::vm::{TestKernel, TestMachine};
use fmt::Display;
use futures::{Future, StreamExt, TryFutureExt, TryStreamExt};
use fvm::executor::{ApplyKind, ApplyRet, DefaultExecutor, Executor};
use fvm::kernel::Context;
use fvm::machine::Machine;
use fvm::state_tree::StateTree;
use fvm_shared::address::Protocol;
use fvm_shared::blockstore::MemoryBlockstore;
use fvm_shared::crypto::signature::SECP_SIG_LEN;
use fvm_shared::encoding::Cbor;
use fvm_shared::message::Message;
use fvm_shared::receipt::Receipt;
use itertools::Itertools;
use lazy_static::lazy_static;
use regex::Regex;
use walkdir::{DirEntry, WalkDir};

/// Checks if the file is a runnable vector.
pub fn is_runnable(entry: &DirEntry) -> bool {
    let file_name = match entry.path().to_str() {
        Some(file) => file,
        None => return false,
    };

    for rx in SKIP_TESTS.iter() {
        if rx.is_match(file_name) {
            println!("SKIPPING: {}", file_name);
            return false;
        }
    }

    file_name.ends_with(".json")
}

/// Compares the result of running a message with the expected result.
pub fn check_msg_result(expected_rec: &Receipt, ret: &ApplyRet, label: impl Display) -> Result<()> {
    let error = ret
        .backtrace
        .iter()
        .map(|e| {
            format!(
                "source: {:?}, code: {:?}, message: {:?}",
                e.source, e.code, e.message
            )
        })
        .collect::<Vec<String>>()
        .join("\n");
    let actual_rec = &ret.msg_receipt;
    let (expected, actual) = (expected_rec.exit_code, actual_rec.exit_code);
    if expected != actual {
        return Err(anyhow!(
            "exit code of msg {} did not match; expected: {:?}, got {:?}. Error: {}",
            label,
            expected,
            actual,
            error
        ));
    }

    let (expected, actual) = (&expected_rec.return_data, &actual_rec.return_data);
    if expected != actual {
        return Err(anyhow!(
            "return data of msg {} did not match; expected: {:?}, got {:?}",
            label,
            expected.as_slice(),
            actual.as_slice()
        ));
    }

    let (expected, actual) = (expected_rec.gas_used, actual_rec.gas_used);
    if expected != actual {
        return Err(anyhow!(
            "gas used of msg {} did not match; expected: {}, got {}",
            label,
            expected,
            actual
        ));
    }

    Ok(())
}

/// Compares the resulting state root with the expected state root. Currently,
/// this doesn't do much, but it could run a statediff.
pub fn compare_state_roots(bs: &MemoryBlockstore, root: &Cid, expected_root: &Cid) -> Result<()> {
    if root == expected_root {
        return Ok(());
    }

    let mut seen = HashSet::new();

    let mut actual = HashMap::new();
    StateTree::new_from_root(bs, root)
        .context("failed to load actual state tree")?
        .for_each(|addr, state| {
            actual.insert(addr, state.clone());
            Ok(())
        })?;

    let mut expected = HashMap::new();
    StateTree::new_from_root(bs, expected_root)
        .context("failed to load expected state tree")?
        .for_each(|addr, state| {
            expected.insert(addr, state.clone());
            Ok(())
        })?;
    for (k, va) in &actual {
        if seen.insert(k) {
            continue;
        }
        match expected.get(k) {
            Some(ve) if va != ve => {
                log::error!("actor {} has state {:?}, expected {:?}", k, va, ve)
            }
            None => log::error!("unexpected actor {}", k),
            _ => {}
        }
    }
    for (k, ve) in &expected {
        if seen.insert(k) {
            continue;
        }
        match actual.get(k) {
            Some(va) if va != ve => {
                log::error!("actor {} has state {:?}, expected {:?}", k, va, ve)
            }
            None => log::error!("missing actor {}", k),
            _ => {}
        }
    }

    return Err(anyhow!(
        "wrong post root cid; expected {}, but got {}",
        expected_root,
        root
    ));
}

/// Represents the result from running a vector.
pub enum VariantResult {
    /// The vector succeeded.
    Ok { id: String },
    /// A variant was skipped, due to the specified reason.
    Skipped { reason: String, id: String },
    /// A variant failed, due to the specified error.
    Failed { reason: anyhow::Error, id: String },
}