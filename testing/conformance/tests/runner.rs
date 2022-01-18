// Copyright 2019-2022 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use std::env::var;
use std::fs::File;
use std::io::BufReader;
use std::iter;
use std::path::{Path, PathBuf};

use anyhow::anyhow;
use async_std::{stream, sync, task};
use colored::*;
use conformance_tests::test_utils::*;
use conformance_tests::vector::{MessageVector, Selector, TestVector, Variant};
use conformance_tests::vm::{TestKernel, TestMachine};
use futures::{Future, StreamExt, TryFutureExt, TryStreamExt};
use fvm::executor::{ApplyKind, DefaultExecutor, Executor};
use fvm::machine::Machine;
use fvm_shared::address::Protocol;
use fvm_shared::blockstore::MemoryBlockstore;
use fvm_shared::crypto::signature::SECP_SIG_LEN;
use fvm_shared::encoding::Cbor;
use fvm_shared::message::Message;
use itertools::Itertools;
use walkdir::WalkDir;

#[async_std::test]
async fn conformance_test_runner() -> anyhow::Result<()> {
    pretty_env_logger::init();

    let vector_results = match var("VECTOR") {
        Ok(v) => either::Either::Left(
            iter::once(async move {
                let path = Path::new(v.as_str()).to_path_buf();
                let res = run_vector(path.clone()).await?;
                anyhow::Ok((path, res))
            })
            .map(futures::future::Either::Left),
        ),
        Err(_) => either::Either::Right(
            WalkDir::new("test-vectors/corpus")
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(is_runnable)
                .map(|e| async move {
                    let path = e.path().to_path_buf();
                    let res = run_vector(path.clone()).await?;
                    Ok((path, res))
                })
                .map(futures::future::Either::Right),
        ),
    };

    let mut results = Box::pin(
        stream::from_iter(vector_results)
            // Will _load_ up to 100 vectors at once in any order. We won't actually run the vectors in
            // parallel (yet), but that shouldn't be too hard.
            .map(|task| {
                async move {
                    let (path, jobs) = task.await?;
                    Ok(stream::from_iter(jobs).map(move |job| {
                        let path = path.clone();
                        Ok(async move { anyhow::Ok((path, job.await?)) })
                    }))
                }
                .try_flatten_stream()
            })
            .flatten()
            .try_buffer_unordered(*TEST_VECTOR_PARALLELISM),
    );

    let mut succeeded = 0;
    let mut failed = 0;
    let mut skipped = 0;

    // Output the result to stdout.
    // Doing this here instead of in an inspect so that we get streaming output.
    macro_rules! report {
        ($status:expr, $path:expr, $id:expr) => {
            println!("[{}] vector: {} | variant: {}", $status, $path, $id);
        };
    }

    while let Some((path, res)) = results.next().await.transpose()? {
        match res {
            VariantResult::Ok { id } => {
                report!("OK".on_green(), path.display(), id);
                succeeded += 1;
            }
            VariantResult::Failed { reason, id } => {
                report!("FAIL".white().on_red(), path.display(), id);
                println!("\t|> reason: {:#}", reason);
                failed += 1;
            }
            VariantResult::Skipped { reason, id } => {
                report!("SKIP".on_yellow(), path.display(), id);
                println!("\t|> reason: {}", reason);
                skipped += 1;
            }
        }
    }

    println!();
    println!(
        "{}",
        format!(
            "conformance tests result: {}/{} tests passed ({} skipped)",
            succeeded,
            failed + succeeded,
            skipped,
        )
        .bold()
    );

    if failed > 0 {
        Err(anyhow!("some vectors failed"))
    } else {
        Ok(())
    }
}

/// Runs a single test vector and returns a list of VectorResults,
/// one per variant.
async fn run_vector(
    path: PathBuf,
) -> anyhow::Result<impl Iterator<Item = impl Future<Output = anyhow::Result<VariantResult>>>> {
    let file = File::open(&path)?;
    let reader = BufReader::new(file);
    let vector: TestVector = serde_json::from_reader(reader)?;

    match vector {
        TestVector::Message(v) => {
            let skip = !v.selector.as_ref().map_or(true, Selector::supported);
            if skip {
                Ok(either::Either::Left(
                    v.preconditions.variants.into_iter().map(|variant| {
                        futures::future::Either::Left(async move {
                            Ok(VariantResult::Skipped {
                                id: variant.id,
                                reason: "selector not supported".to_owned(),
                            })
                        })
                    }),
                ))
            } else {
                // First import the blockstore and do some sanity checks.
                let (bs, imported_root) = v.seed_blockstore().await?;
                if !imported_root.contains(&v.preconditions.state_tree.root_cid) {
                    return Err(anyhow!(
                        "imported roots ({}) do not contain precondition CID {}",
                        imported_root.iter().join(", "),
                        v.preconditions.state_tree.root_cid
                    ));
                }
                if !imported_root.contains(&v.postconditions.state_tree.root_cid) {
                    return Err(anyhow!(
                        "imported roots ({}) do not contain postcondition CID {}",
                        imported_root.iter().join(", "),
                        v.preconditions.state_tree.root_cid
                    ));
                }

                let v = sync::Arc::new(v);
                Ok(either::Either::Right(
                    (0..v.preconditions.variants.len()).map(move |i| {
                        let v = v.clone();
                        let bs = bs.clone();
                        let name =
                            format!("{} | {}", path.display(), &v.preconditions.variants[i].id);
                        futures::future::Either::Right(
                                task::Builder::new()
                                    .name(name)
                                    .spawn(async move {
                                        run_variant(bs, &v, &v.preconditions.variants[i])
                                    }).unwrap(),
                            )
                    }),
                ))
            }
        }
    }
}

fn run_variant(
    bs: MemoryBlockstore,
    v: &MessageVector,
    variant: &Variant,
) -> anyhow::Result<VariantResult> {
    let id = variant.id.clone();

    // Construct the Machine.
    let machine = TestMachine::new_for_vector(v, variant, bs);
    let mut exec: DefaultExecutor<TestKernel> = DefaultExecutor::new(machine);

    // Apply all messages in the vector.
    for (i, m) in v.apply_messages.iter().enumerate() {
        let msg = Message::unmarshal_cbor(&m.bytes)?;

        // Execute the message.
        let mut raw_length = m.bytes.len();
        if msg.from.protocol() == Protocol::Secp256k1 {
            // 65 bytes signature + 1 byte type + 3 bytes for field info.
            raw_length += SECP_SIG_LEN + 4;
        }
        let ret = match exec.execute_message(msg, ApplyKind::Explicit, raw_length) {
            Ok(ret) => ret,
            Err(e) => return Ok(VariantResult::Failed { id, reason: e }),
        };

        // Compare the actual receipt with the expected receipt.
        let expected_receipt = &v.postconditions.receipts[i];
        if let Err(err) = check_msg_result(expected_receipt, &ret, i) {
            return Ok(VariantResult::Failed { id, reason: err });
        }
    }

    // Flush the machine, obtain the blockstore, and compare the
    // resulting state root with the expected state root.
    let final_root = match exec.flush() {
        Ok(cid) => cid,
        Err(err) => {
            return Ok(VariantResult::Failed {
                id,
                reason: err.context("flushing executor failed"),
            });
        }
    };

    let machine = match exec.consume() {
        Some(machine) => machine,
        None => {
            return Ok(VariantResult::Failed {
                id,
                reason: anyhow!("machine poisoned"),
            })
        }
    };

    let bs = machine.consume().consume();

    if let Err(err) = compare_state_roots(&bs, &final_root, &v.postconditions.state_tree.root_cid) {
        return Ok(VariantResult::Failed {
            id,
            reason: err.context("comparing state roots failed"),
        });
    }

    Ok(VariantResult::Ok { id })
}
