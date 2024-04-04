// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{str::FromStr, sync::Arc};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use core::time::Duration;

use clap::Parser;
use ethers_core::types::H256;
use ethers_providers::Middleware;
#[cfg(feature = "risc0")]
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use tracing::info;
use zkevm_core::{
    ether_trace::{from_ethers_u256, Http, Provider}, Env, EvmBuilder, EvmResult, ZkDb
};
#[cfg(feature = "risc0")]
use zkevm_methods::{EVM_ELF, EVM_ID};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, default_value = "0x600d18676aef439ec6ba33d143b78878a520682be7fd8331c74bdf672988a2b1")]
    tx_hash: String,

    #[clap(short, long, default_value = "https://rpc.flashbots.net/")]
    rpc_url: String,

    #[clap(short, long)]
    cache_path: Option<PathBuf>,

    #[clap(short, long)]
    polkavm_elf_blob: Option<PathBuf>,

    #[clap(short, long)]
    block_numb: Option<u64>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct State {
    zkdb: ZkDb,
    env: Env,
}

async fn fetch_state(tx_hash: H256, rpc_url: &str, block_numb: Option<u64>) -> State {
    let client = Provider::<Http>::try_from(rpc_url).expect("Invalid RPC url");
    let client = Arc::new(client);

    let tx = client.get_transaction(tx_hash).await.unwrap().unwrap();
    let block_numb = if let Some(numb) = block_numb {
        numb
    } else {
        let numb = tx.block_number.unwrap();
        numb.as_u64() - 1
    };
    info!("Running TX: 0x{:x} at block {}", tx_hash, block_numb);

    let mut env = Env::default();
    env.block.number = from_ethers_u256(block_numb.into());
    env.tx = zkevm_core::ether_trace::txenv_from_tx(tx);
    let trace_db = zkevm_core::ether_trace::TraceTx::new(client, Some(block_numb)).unwrap();
    let env_clone = env.clone();
    let (res, zkdb) = tokio::task::spawn_blocking(move || {
        let mut evm = EvmBuilder::default()
            .with_db(trace_db)
            .with_env(Box::new(env_clone))
            .build();

        let res = evm.transact().unwrap();
        let zkdb = evm.db_mut().create_zkdb();
        (res, zkdb)
    }).await.unwrap();

    if !res.result.is_success() {
        panic!("TX failed in pre-flight");
    }

    return State {
        zkdb,
        env,
    }
}

fn run_polkavm(state: &State, elf_blob_path: &Path) -> (EvmResult, Duration, Duration) {
    let elf_blob = std::fs::read(elf_blob_path).unwrap();

    // Link the ELF file into a PolkaVM program.
    // This part normally happens offline.
    let program_blob = polkavm_linker::program_from_elf(
        polkavm_linker::Config::default(),
        &elf_blob
    ).unwrap();

    // Create the engine. This should only be done once for the lifetime of the process.
    let mut config = polkavm::Config::from_env().unwrap();
    if config.backend().is_none() {
        // Force a recompiler unless otherwise specified.
        config.set_backend(Some(polkavm::BackendKind::Compiler));
    }
    let engine = polkavm::Engine::new(&config).unwrap();

    // Compile the module into native code and set up the host functions.
    let timestamp_compilation = std::time::Instant::now();
    let mut config = polkavm::ModuleConfig::new();
    // Enable gas metering for extra overhead.
    config.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));
    let module = polkavm::Module::new(&engine, &config, program_blob.as_bytes()).unwrap();
    let mut linker = polkavm::Linker::new(&engine);

    struct Context {
        inputs: VecDeque<Vec<u8>>,
        output: Vec<u8>,
    }

    // We follow the original risc0 example when in comes to how the I/O is done.
    linker.func_wrap("next_read_len", |caller: polkavm::Caller<Context>| -> u32 {
        caller.data().inputs.front().map(|input| input.len() as u32).unwrap_or(0)
    }).unwrap();

    linker.func_wrap("read_raw", |mut caller: polkavm::Caller<Context>, address: u32| -> Result<(), polkavm::Trap> {
        let input = caller.data_mut().inputs.pop_front().ok_or_else(|| polkavm::Trap::default())?;
        caller.write_memory(address, &input)
    }).unwrap();

    linker.func_wrap("commit_raw", |caller: polkavm::Caller<Context>, address: u32, length: u32| -> Result<(), polkavm::Trap> {
        let (caller, ctx) = caller.split();
        ctx.output = caller.read_memory_into_vec(address, length)?;
        Ok(())
    }).unwrap();

    let instance_pre = linker.instantiate_pre(&module).unwrap();
    let symbol = module.lookup_export("main").unwrap();
    let elapsed_compilation = timestamp_compilation.elapsed();

    let timestamp_execution = std::time::Instant::now();
    let mut ctx = Context {
        inputs: vec![
            bincode::serde::encode_to_vec(&state.env, bincode::config::standard()).unwrap(),
            bincode::serde::encode_to_vec(&state.zkdb, bincode::config::standard()).unwrap()
        ].into(),
        output: Vec::new()
    };

    let mut state_args = polkavm::StateArgs::new();
    state_args.set_gas(polkavm::Gas::MAX);

    let instance = instance_pre.instantiate().unwrap();
    instance.call(state_args, polkavm::CallArgs::new(&mut ctx, symbol)).unwrap();

    let result = bincode::serde::decode_from_slice(&ctx.output, bincode::config::standard()).unwrap().0;
    let elapsed_execution = timestamp_execution.elapsed();
    (result, elapsed_compilation, elapsed_execution)
}

#[cfg(feature = "risc0")]
fn generate_risc0_proof(state: &State) -> (Receipt, EvmResult, Duration) {
    let timestamp = std::time::Instant::now();
    let exec_env = ExecutorEnv::builder()
        .write(&state.env)
        .unwrap()
        .write(&state.zkdb)
        .unwrap()
        .build()
        .unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Produce a receipt by proving the specified ELF binary.
    let receipt = prover.prove(exec_env, EVM_ELF).unwrap();

    let result = receipt.journal.decode().expect("Failed to deserialize EvmResult");
    let elapsed = timestamp.elapsed();
    (receipt, result, elapsed)
}

#[cfg(feature = "risc0")]
fn verify_risc0_proof(receipt: Receipt) -> Duration {
    let timestamp = std::time::Instant::now();
    receipt.verify(EVM_ID).expect("verification failed");
    timestamp.elapsed()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();
    ();

    let args = Args::parse();
    let cache_path =
        args.cache_path.unwrap_or(Path::new(env!("CARGO_MANIFEST_DIR")).join("cache"))
           .join(format!("{}.json", args.tx_hash));

    let default_elf_blob_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("target")
            .join("riscv-guest")
            .join("riscv32ema-unknown-none-elf")
            .join("release")
            .join("evm");

    let elf_blob_path = args.polkavm_elf_blob.unwrap_or(default_elf_blob_path);
    if !elf_blob_path.exists() {
        eprintln!("ERROR: ELF blob at {elf_blob_path:?} doesn't exist");
        return;
    }

    if !cache_path.exists() {
        let tx_hash = H256::from_str(&args.tx_hash).expect("Invalid transaction hash");
        let state = fetch_state(tx_hash, &args.rpc_url, args.block_numb).await;
        let state_blob = serde_json::to_vec(&state).expect("failed to serialize state");
        std::fs::create_dir_all("cache").expect("failed to create cache dir");
        std::fs::write(&cache_path, state_blob).expect("failed to write to the cache");
    }

    let state: State = serde_json::from_slice(&std::fs::read(&cache_path).unwrap()).unwrap();

    println!("Running on PolkaVM...");
    let (polkavm_result, polkavm_compilation_time, polkavm_execution_time) = run_polkavm(&state, &elf_blob_path);
    println!("  PolkaVM compilation: {:.03}ms", polkavm_compilation_time.as_secs_f64() * 1000.0);
    println!("  PolkaVM execution: {:.03}ms", polkavm_execution_time.as_secs_f64() * 1000.0);
    println!("  PolkaVM total: {:.03}ms", (polkavm_compilation_time + polkavm_execution_time).as_secs_f64() * 1000.0);

    #[cfg(feature = "risc0")]
    {
        println!("\nGenerating risc0 proof...");
        let (receipt, risc0_result, risc0_proof_time) = generate_risc0_proof(&state);

        // Make sure the results match.
        assert_eq!(format!("{:?}", polkavm_result), format!("{:?}", risc0_result));
        println!("risc0 proof generation time: {:.03}s", risc0_proof_time.as_secs_f64());

        println!("\nVerifying risc0 proof...");
        let risc0_validation_time = verify_risc0_proof(receipt);
        println!("risc0 proof validation time: {:.03}s", risc0_validation_time.as_secs_f64());
    }
}
