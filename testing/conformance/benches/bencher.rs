// Copyright 2019-2022 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT
#[macro_use]
extern crate criterion;

// TODO support skipping
use std::collections::{HashMap, HashSet};
use std::env::var;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::{fmt, iter};

use anyhow::{anyhow, Result};
use async_std::{stream, sync, task};
use cid::Cid;
use colored::*;
use conformance_tests::test_utils::*;
use conformance_tests::vector::{MessageVector, Selector, TestVector, Variant};
use conformance_tests::vm::{TestKernel, TestMachine};
use criterion::{black_box, *};
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

fn apply_messages(messages: &mut Vec<Message>, exec: &mut DefaultExecutor<TestKernel>) {
    // Apply all messages in the vector.
    for (i, msg) in messages.drain(..).enumerate() {
        // Execute the message.
        let mut raw_length = m.bytes.len();
        if msg.from.protocol() == Protocol::Secp256k1 {
            // 65 bytes signature + 1 byte type + 3 bytes for field info.
            raw_length += SECP_SIG_LEN + 4;
        }
        let ret = match exec.execute_message(*msg, ApplyKind::Explicit, raw_length) {
            Ok(ret) => ret,
            Err(e) => break,
        };
    }
}

// This is a struct that tells Criterion.rs to use the "futures" crate's current-thread executor
use criterion::async_executor::FuturesExecutor;

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("conformance-tests");

    // TODO: this goes in a loop of benchmarks to run in the group!
    let vector_name = "test-vectors/corpus/specs_actors_v6/TestCronCatchedCCExpirationsAtDeadlineBoundary/c70afe9fa5e05990cac8ab8d4e49522919ad29e5be3f81ee4b59752c36c4a701-t0100-t0102-storageminer-6.json";
    let path = Path::new(vector_name).to_path_buf();
    let file = File::open(&path)?;
    let reader = BufReader::new(file);
    let vector: TestVector = serde_json::from_reader(reader)?;

    let skip = !vector.selector.as_ref().map_or(true, Selector::supported);
    if skip {
        // selector not supported idk what this means
        return;
    }

    let (bs, imported_root) = v.seed_blockstore().await?;

    let v = sync::Arc::new(v);

    // TODO: become another iterator over variants woo woo
    let variant_num = 0;
    let variant = v.preconditions.variants[variant_num];
    let name = format!("{} | {}", path.display(), variant.id);

    group.bench_function(name,
                         move |b| {
                             b.to_async(FuturesExecutor)
                                 .iter_batched_ref(
                                     || {
                                         let v = v.clone();
                                         let bs = bs.clone();
                                         let machine = TestMachine::new_for_vector(&v, variant, bs);
                                         let mut exec: DefaultExecutor<TestKernel> = DefaultExecutor::new(machine);
                                         let messages = v.apply_messages.iter().map(|m| Message::unmarshal_cbor(&m.bytes).unwrap());
                                         (messages, exec)
                                     }

                                     || async { |(messages, exec)| apply_messages(messages, exec).await },
                                     BatchSize::LargeInput,
                                 )
                         });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
