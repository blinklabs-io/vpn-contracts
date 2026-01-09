//! Benchmarks for the VPN payment verification circuit

use criterion::{criterion_group, criterion_main, Criterion};
use vpn_payment_circuit::{PaymentVerificationCircuit, PrivateInputs, PublicInputs};
use halo2curves::pasta::Fp;

fn bench_circuit_construction(c: &mut Criterion) {
    let private = PrivateInputs {
        secret_key: [1u8; 32],
        payment_amount: 30_000_000,
        sequence: 1,
    };

    let public = PublicInputs {
        pricing_tier: 1,
        region_hash: [2u8; 32],
        nullifier: [3u8; 32],
        provider_commitment: [4u8; 32],
        state_root: [5u8; 32],
    };

    c.bench_function("circuit_construction", |b| {
        b.iter(|| {
            let _circuit = PaymentVerificationCircuit::<Fp>::new(&private, &public);
        })
    });
}

criterion_group!(benches, bench_circuit_construction);
criterion_main!(benches);
