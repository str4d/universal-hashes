//! Poly1305 benchmark (using criterion)

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use criterion_cycles_per_byte::CyclesPerByte;
use poly1305::{
    universal_hash::{NewUniversalHash, UniversalHash},
    Poly1305,
};

fn bench(c: &mut Criterion<CyclesPerByte>) {
    let mut group = c.benchmark_group("poly1305");

    for size in &[10, 100, 1000, 10000] {
        let buf = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(BenchmarkId::new("update_padded", size), |b| {
            let mut m = Poly1305::new(&Default::default());
            b.iter(|| m.update_padded(&buf));
        });
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench
);

criterion_main!(benches);
