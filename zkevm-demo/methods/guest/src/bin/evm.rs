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
#![cfg_attr(target_feature = "e", no_std)]
#![cfg_attr(target_feature = "e", no_main)]

#[cfg(not(target_feature = "e"))]
use risc0_zkvm::guest::env;
use zkevm_core::{Env, EvmResult, ZkDb, EvmBuilder};

#[cfg(target_feature = "e")]
::core::arch::global_asm!(
    ".pushsection .polkavm_min_stack_size,\"R\",@note",
    ".4byte 0x10000",
    ".popsection"
);

#[cfg(target_feature = "e")]
mod env {
    #[polkavm_derive::polkavm_import]
    extern {
        fn next_read_len() -> usize;
        fn read_raw(dst: *mut u8);
        fn commit_raw(src: *const u8, len: usize);
    }

    pub fn read<'a, T>() -> T where T: serde::Deserialize<'a> {
        let len = unsafe { next_read_len() };
        let mut buffer = alloc::vec![0; len];
        unsafe { read_raw(buffer.as_mut_ptr()) };
        let buffer = buffer.leak();
        bincode::serde::decode_borrowed_from_slice(buffer, bincode::config::standard()).unwrap()
    }

    pub fn commit<T>(value: &T) where T: serde::Serialize {
        let buffer = bincode::serde::encode_to_vec(value, bincode::config::standard()).unwrap();
        unsafe { commit_raw(buffer.as_ptr(), buffer.len()) };
    }

    pub fn log(_: &str) {}
}

#[cfg(target_feature = "e")]
#[global_allocator]
static mut GLOBAL_ALLOC: polkavm_derive::LeakingAllocator = polkavm_derive::LeakingAllocator;

#[cfg(target_feature = "e")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::arch::asm!("unimp", options(noreturn));
    }
}

extern crate alloc;

#[cfg_attr(target_feature = "e", polkavm_derive::polkavm_export)]
fn main() {
    let env: Env = env::read();
    let db: ZkDb = env::read();

    let mut evm = EvmBuilder::default().
        with_db(db)
        .with_env(alloc::boxed::Box::new(env))
        .build();

    let res = evm.transact().unwrap();
    env::commit(&EvmResult::from(res));
    env::log("");
}
