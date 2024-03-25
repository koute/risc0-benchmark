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

use clap::Parser;
use ethers_core::types::H256;
use ethers_providers::Middleware;
use risc0_zkvm::{default_prover, ExecutorEnv};
use tracing::info;
use zkevm_core::{
    ether_trace::{from_ethers_u256, Http, Provider}, Env, EvmBuilder, EvmResult, ZkDb
};
use zkevm_methods::EVM_ELF;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, default_value = "0x600d18676aef439ec6ba33d143b78878a520682be7fd8331c74bdf672988a2b1")]
    tx_hash: String,

    #[clap(short, long, default_value = "https://rpc.flashbots.net/")]
    rpc_url: String,

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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();
    ();

    let args = Args::parse();
    let cache_path: std::path::PathBuf =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("cache")
            .join(format!("{}.json", args.tx_hash));

    if !cache_path.exists() {
        let tx_hash = H256::from_str(&args.tx_hash).expect("Invalid transaction hash");
        let state = fetch_state(tx_hash, &args.rpc_url, args.block_numb).await;
        let state_blob = serde_json::to_vec(&state).expect("failed to serialize state");
        std::fs::create_dir_all("cache").expect("failed to create cache dir");
        std::fs::write(&cache_path, state_blob).expect("failed to write to the cache");
    }

    let state: State = serde_json::from_slice(&std::fs::read(&cache_path).unwrap()).unwrap();

    info!("Running zkvm...");
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

    let res: EvmResult = receipt
        .journal
        .decode()
        .expect("Failed to deserialize EvmResult");
    info!("exit reason: {:?}", res.reason);
    info!("state updates: {}", res.state.len());
}
