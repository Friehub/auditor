// SPDX-License-Identifier: MIT
//! Frensense Engine Benchmarks
//!
//! Concrete, realistic benchmarks across every major engine subsystem.
//! Each benchmark uses code that resembles actual production patterns -
//! not synthetic repetition - so results reflect real-world performance.
//!
//! Run locally:
//!   cargo bench --features full
//!
//! Run a single group:
//!   cargo bench --features full -- `scan_throughput`
//!
//! View HTML report:
//!   open target/criterion/report/index.html

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use frensense::engine::auditor::FrensenseAuditor;
use frensense::semantics::{Symbol, SymbolKind, SymbolRegistry};
use frensense::{Engine, FileId};
use std::fmt::Write;
use std::path::Path;
use std::time::Duration;

/// If `FRENSENSE_BENCH_QUICK` is set to `1` or `true`, override each benchmark
/// group with a minimal sample count and short measurement window so CI runs
/// finish in seconds instead of minutes.
fn apply_quick_mode(group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    if std::env::var("FRENSENSE_BENCH_QUICK")
        .ok()
        .is_some_and(|v| v == "1" || v == "true")
    {
        group.sample_size(10);
        group.measurement_time(Duration::from_secs(5));
        group.warm_up_time(Duration::from_secs(1));
    }
}

// ── Realistic source fixtures ─────────────────────────────────────────────────
// These represent actual patterns a developer would write - including patterns
// that trigger rules, patterns that don't, and mixed realistic code.

const RUST_SERVICE_CLEAN: &str = r##"
use rust_decimal::Decimal;
use sqlx::PgPool;

pub struct OrderService {
    pool: PgPool,
}

impl OrderService {
    pub async fn create_order(
        &self,
        user_id: &str,
        items: Vec<OrderItem>,
    ) -> Result<Order, ServiceError> {
        let total = items.iter()
            .fold(Decimal::ZERO, |acc, i| acc + i.price * Decimal::from(i.qty));

        let order = sqlx::query_as!(
            Order,
            r#"INSERT INTO "Order" ("userId", "total") VALUES ($1, $2) RETURNING *"#,
            user_id,
            total
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(order)
    }

    pub async fn cancel_order(&self, order_id: &str, user_id: &str) -> Result<(), ServiceError> {
        let affected = sqlx::query!(
            r#"UPDATE "Order" SET status = 'CANCELLED' WHERE id = $1 AND "userId" = $2"#,
            order_id,
            user_id
        )
        .execute(&self.pool)
        .await?;

        if affected.rows_affected() == 0 {
            return Err(ServiceError::NotFound);
        }
        Ok(())
    }
}
"##;

const RUST_SERVICE_WITH_VIOLATIONS: &str = r#"
use std::fs;

pub async fn process_payment(amount: f64, user_id: &str) -> Result<(), String> {
    // f64 for money - RUST_F64_FOR_MONEY
    // blocking IO in async - RUST_BLOCKING_IN_ASYNC
    let log = fs::read_to_string("/var/log/payments.log").unwrap();
    println!("Processing: {}", log);  // RUST_STD_OUTPUT

    let orders: Vec<String> = vec!["order1".to_string(), "order2".to_string()];
    orders.forEach(async |order| {  // not valid Rust but pattern check
        process(order).await;
    });

    let result = sqlx::query("SELECT * FROM orders WHERE user_id = $1")
        .fetch_all(&pool)
        .await
        .unwrap();  // RUST_UNCHECKED_IO

    Ok(())
}

fn validate_input(input: &str) -> bool {
    // RUST_CSA_VALIDATE_UNCONDITIONAL - no rejection path
    true
}
"#;

const TS_SERVICE_CLEAN: &str = r"
import { prisma } from '../db';
import { TRPCError } from '@trpc/server';
import Decimal from 'decimal.js';

export const orderService = {
  async createFromCart(
    userId: string,
    cartId: string,
    paymentMethod: string,
  ) {
    const cart = await prisma.cart.findFirst({
      where: { id: cartId, userId },
      include: { items: { include: { variant: true } } },
    });

    if (!cart) {
      throw new TRPCError({ code: 'NOT_FOUND', message: 'Cart not found' });
    }

    const subtotal = cart.items.reduce(
      (acc, item) => acc.plus(new Decimal(item.variant.price).times(item.quantity)),
      new Decimal(0),
    );

    const order = await prisma.$transaction(async (tx) => {
      return tx.order.create({
        data: { userId, subtotal, paymentMethod, status: 'PENDING_PAYMENT' },
      });
    });

    return order;
  },
};
";

const TS_SERVICE_WITH_VIOLATIONS: &str = r"
import { prisma } from '../db';

export const badOrderService = {
  // publicProcedure mutation - TRPC_PUBLIC_MUTATION
  deleteOrder: publicProcedure
    .mutation(async ({ ctx, input }) => {
      // No ownership scope - TRPC_PRISMA_NO_WHERE_SCOPE
      await prisma.order.delete({ where: { id: input.orderId } });

      // Event inside transaction - TS_EVENT_INSIDE_TRANSACTION
      await prisma.$transaction(async (tx) => {
        await tx.order.update({ where: { id: input.orderId }, data: { status: 'CANCELLED' } });
        await publishEvent('order.cancelled', { orderId: input.orderId });
      });
    }),

  processRefund: async (orderId: string, ctx: any) => {
    // Non-null assertion on ctx - TRPC_CTX_NON_NULL_ASSERTION
    const userId = ctx.session!.user.id;

    const items = await prisma.orderLine.findMany({ where: { orderId } });

    // async forEach - TS_ASYNC_FOR_EACH
    items.forEach(async (item) => {
      await prisma.refund.create({ data: { itemId: item.id } });
    });

    // Sensitive data logging - TS_SENSITIVE_DATA_LOGGING
    console.log('Processing refund for token:', ctx.session!.token);
  },
};
";

const TS_MIXED_REAL_WORLD: &str = r"
import { z } from 'zod';
import { router, protectedProcedure } from '../trpc';
import { inventoryService } from './inventory-service';
import { paymentService } from './payment-service';
import Decimal from 'decimal.js';

export const checkoutRouter = router({
  createOrder: protectedProcedure
    .input(z.object({
      cartId: z.string(),
      addressId: z.string(),
      paymentMethod: z.enum(['CARD', 'WALLET', 'POD']),
      couponCode: z.string().optional(),
    }))
    .mutation(async ({ ctx, input }) => {
      const { cartId, addressId, paymentMethod, couponCode } = input;
      const userId = ctx.session.user.id;

      const cart = await prisma.cart.findFirst({
        where: { id: cartId, userId },
        include: { items: { include: { variant: { include: { product: true } } } } },
      });

      if (!cart || cart.items.length === 0) {
        throw new TRPCError({ code: 'BAD_REQUEST', message: 'Cart is empty' });
      }

      for (const item of cart.items) {
        await inventoryService.reserve(item.variantId, item.quantity);
      }

      const subtotal = cart.items.reduce(
        (acc, item) => acc.plus(new Decimal(item.variant.price).times(item.quantity)),
        new Decimal(0),
      );

      const order = await prisma.$transaction(async (tx) => {
        const o = await tx.order.create({
          data: { userId, subtotal, addressId, paymentMethod, status: 'PENDING_PAYMENT' },
        });
        return o;
      });

      return order;
    }),
});
";

// ── Group 1: Scan Throughput ──────────────────────────────────────────────────
// Measures raw scan speed across file sizes and violation densities.
// This is what users care about: "how fast does it scan my codebase?"

fn bench_scan_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan_throughput");
    apply_quick_mode(&mut group);

    // Clean Rust service - baseline (no violations, no extra work)
    group.bench_function("rust_clean_service", |b| {
        let mut engine = Engine::new();
        b.iter(|| {
            engine
                .run_content(
                    black_box(Path::new("order_service.rs")),
                    black_box(RUST_SERVICE_CLEAN),
                )
                .unwrap_or_default()
        });
    });

    // Rust service with violations - measures rule firing overhead
    group.bench_function("rust_service_with_violations", |b| {
        let mut engine = Engine::new();
        b.iter(|| {
            engine
                .run_content(
                    black_box(Path::new("bad_service.rs")),
                    black_box(RUST_SERVICE_WITH_VIOLATIONS),
                )
                .unwrap_or_default()
        });
    });

    // Clean TypeScript service
    group.bench_function("ts_clean_service", |b| {
        let mut engine = Engine::new();
        b.iter(|| {
            engine
                .run_content(
                    black_box(Path::new("order-service.ts")),
                    black_box(TS_SERVICE_CLEAN),
                )
                .unwrap_or_default()
        });
    });

    // TypeScript with violations - taint + CSA + tRPC rules all fire
    group.bench_function("ts_service_with_violations", |b| {
        let mut engine = Engine::new();
        b.iter(|| {
            engine
                .run_content(
                    black_box(Path::new("bad-order-service.ts")),
                    black_box(TS_SERVICE_WITH_VIOLATIONS),
                )
                .unwrap_or_default()
        });
    });

    // Real-world mixed TypeScript - representative of an actual service file
    group.bench_function("ts_mixed_real_world", |b| {
        let mut engine = Engine::new();
        b.iter(|| {
            engine
                .run_content(
                    black_box(Path::new("checkout-router.ts")),
                    black_box(TS_MIXED_REAL_WORLD),
                )
                .unwrap_or_default()
        });
    });

    group.finish();
}

// ── Group 2: Scale - Files Per Second ────────────────────────────────────────
// Simulates scanning a real monorepo at different project sizes.
// Uses a temp directory so the full Engine::run() path is exercised.

fn bench_project_scale(c: &mut Criterion) {
    use std::fs;
    use tempfile::tempdir;

    let mut group = c.benchmark_group("project_scale");
    // Fewer samples because each iteration writes files to disk
    group.sample_size(20);
    apply_quick_mode(&mut group);

    for file_count in [10usize, 50, 100, 200] {
        group.bench_with_input(
            BenchmarkId::new("files_scanned", file_count),
            &file_count,
            |b, &n| {
                // Build the project once outside the timed loop
                let dir = tempdir().unwrap();
                for i in 0..n {
                    // Alternate clean and violation files to get realistic mix
                    let content = if i % 3 == 0 {
                        RUST_SERVICE_WITH_VIOLATIONS
                    } else {
                        RUST_SERVICE_CLEAN
                    };
                    fs::write(dir.path().join(format!("service_{i}.rs")), content).unwrap();
                }
                // Also add some TypeScript files
                for i in 0..(n / 5).max(1) {
                    let content = if i % 2 == 0 {
                        TS_SERVICE_WITH_VIOLATIONS
                    } else {
                        TS_MIXED_REAL_WORLD
                    };
                    fs::write(dir.path().join(format!("router_{i}.ts")), content).unwrap();
                }

                b.iter(|| {
                    let mut engine = Engine::new();
                    engine.run(black_box(dir.path())).unwrap_or_default()
                });
            },
        );
    }

    group.finish();
}

// ── Group 3: Taint Analysis Depth ────────────────────────────────────────────
// Measures how taint tracking scales with chain length.
// This is the most computationally expensive subsystem.

fn bench_taint_depth(c: &mut Criterion) {
    let mut group = c.benchmark_group("taint_analysis");
    apply_quick_mode(&mut group);

    // Build taint chains of increasing depth
    for chain_len in [5usize, 20, 50, 100] {
        let source = build_taint_chain(chain_len);

        group.bench_with_input(
            BenchmarkId::new("chain_depth", chain_len),
            &chain_len,
            |b, _| {
                let mut engine = Engine::new();
                b.iter(|| {
                    engine
                        .run_content(
                            black_box(Path::new("taint_chain.ts")),
                            black_box(source.as_str()),
                        )
                        .unwrap_or_default()
                });
            },
        );
    }

    group.finish();
}

/// Generates a realistic taint chain: `password` → `x_1` → `x_2` → ... → `console.log`
fn build_taint_chain(depth: usize) -> String {
    let mut src = String::from("function handler(req: Request) {\n");
    src.push_str("  const password = req.body.password;\n");
    for i in 1..=depth {
        let prev = if i == 1 {
            "password".to_string()
        } else {
            format!("x_{}", i - 1)
        };
        writeln!(src, "  const x_{i} = x_{prev};").unwrap();
    }
    writeln!(src, "  console.log(x_{depth});").unwrap();
    src.push_str("}\n");
    src
}

// ── Group 4: Rule Compilation ─────────────────────────────────────────────────
// Startup cost - how long does it take to compile the full rule set?
// Critical for CLI UX: cold start on every invocation.

fn bench_rule_compilation(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule_compilation");
    apply_quick_mode(&mut group);

    group.bench_function("compile_all_builtin_rules", |b| {
        b.iter(|| {
            let auditor = FrensenseAuditor::default_auditor();
            black_box(auditor)
        });
    });

    group.bench_function("engine_cold_start", |b| {
        b.iter(|| {
            let engine = Engine::new();
            black_box(engine)
        });
    });

    group.finish();
}

// ── Group 5: Symbol Registry (SRI) ───────────────────────────────────────────
// The symbol registry underpins SRI fingerprinting and project rules.
// These benchmarks verify it stays O(log n) under realistic project sizes.

fn bench_symbol_registry(c: &mut Criterion) {
    let mut group = c.benchmark_group("symbol_registry");
    apply_quick_mode(&mut group);

    // Build registries of different sizes representing project scales:
    // 1k = small lib, 10k = medium service, 100k = large monorepo
    for symbol_count in [1_000usize, 10_000, 100_000] {
        let mut registry = SymbolRegistry::new();
        for i in 0..symbol_count {
            registry.insert(Symbol {
                name: format!("fn_{i}"),
                kind: if i % 3 == 0 {
                    SymbolKind::Function
                } else {
                    SymbolKind::Struct
                },
                start_byte: i * 200,
                end_byte: (i * 200) + 150,
                line: i * 15 + 1,
                end_line: i * 15 + 10,
                column: 1,
                file_path: format!("src/module_{}.ts", i / 20),
                file_id: FileId(u32::try_from(i / 20).unwrap_or(0)),
            });
        }

        // Lookup at start, middle, end - covers tree traversal variance
        group.bench_with_input(
            BenchmarkId::new("find_function_at/start", symbol_count),
            &symbol_count,
            |b, _| {
                let file = "src/module_0.ts".to_string();
                b.iter(|| registry.find_function_at(black_box(&file), black_box(5)));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("find_function_at/middle", symbol_count),
            &symbol_count,
            |b, &n| {
                let mid_file = format!("src/module_{}.ts", n / 40);
                let mid_line = (n / 2) * 15;
                b.iter(|| registry.find_function_at(black_box(&mid_file), black_box(mid_line)));
            },
        );
    }

    group.finish();
}

// ── Group 6: Advisory Fingerprinting ─────────────────────────────────────────
// Fingerprints are computed on every advisory. Under large scan loads
// (200 files × 10 advisories each = 2,000 fingerprints) this matters.

fn bench_fingerprinting(c: &mut Criterion) {
    use frensense::Advisory;

    let mut group = c.benchmark_group("fingerprinting");
    apply_quick_mode(&mut group);

    let advisory = Advisory {
        rule_id: "TS_ASYNC_FOR_EACH".into(),
        file_id: FileId(42),
        file_path: "packages/api/modules/order/services/order-service.ts".into(),
        severity: frensense::Severity::Critical,
        observation: "async forEach in a service method".into(),
        impact: "Errors are silently swallowed".into(),
        improvement: "Use for...of".into(),
        line: 847,
        column: 12,
        start_byte: 24_881,
        end_byte: 24_920,
        original_content: "items.forEach(async (item) => {".into(),
        proposed_replacement: None,
        proposed_import: None,
        enclosing_symbol: Some("processRefund".into()),
        confidence: 0.90,
        fingerprint: String::new(),
        auto_fixable: false,
        requires_human: false,
        tags: vec!["async".into(), "service".into()],
        taint_branch_ratio: Some(0.0),
        has_validation_name: None,
        match_evidence: None,
        cwe: None,
        cvss: None,
        owasp: None,
    };

    // Measure identity() - used on every baseline comparison
    group.bench_function("advisory_identity", |b| {
        b.iter(|| black_box(advisory.identity()));
    });

    // Measure fuzzy_identity() - used in resilient baseline matching
    group.bench_function("advisory_fuzzy_identity", |b| {
        b.iter(|| black_box(advisory.fuzzy_identity()));
    });

    group.finish();
}

// ── Group 8: N-gram Post-Processing (Jaccard Similarity) ─────────────────────
// Measures post_process_ngrams at increasing fingerprint counts.
// This is O(n²) pairwise comparison - watch for quadratic degradation.
// Particularly important before v0.4.0 when the style-baseline adds more features.

fn bench_post_process_ngrams(c: &mut Criterion) {
    use rustc_hash::FxHasher;
    use std::hash::{Hash, Hasher};

    let mut group = c.benchmark_group("post_process_ngrams");
    apply_quick_mode(&mut group);

    for fp_count in [10usize, 50, 200, 500] {
        // Generate synthetic fingerprints with deterministic n-gram hashes.
        // Each fingerprint gets 20-50 hashes with controlled overlap (~30% shared).
        let mut fingerprints = Vec::with_capacity(fp_count);
        let shared_hashes: Vec<u64> = (0..20)
            .map(|i| {
                let mut h = FxHasher::default();
                (0usize, i).hash(&mut h);
                h.finish()
            })
            .collect();

        for i in 0..fp_count {
            let ngram_count = 20 + (i % 31);
            let mut hashes = rustc_hash::FxHashSet::default();

            // Add some shared hashes (simulating boilerplate)
            for h in &shared_hashes {
                if i % 3 == 0 || (h % 3) == (i as u64 % 3) {
                    hashes.insert(*h);
                }
            }

            // Add unique hashes
            for j in 0..ngram_count.saturating_sub(hashes.len()).max(3) {
                let mut h = FxHasher::default();
                (i, j).hash(&mut h);
                hashes.insert(h.finish());
            }

            fingerprints.push(frensense::FunctionFingerprint {
                file_path: format!("src/service_{}.rs", i / 10),
                function_name: format!("fn_{i}"),
                line: i * 12 + 1,
                language: "rust".to_string(),
                ngram_hashes: hashes.into_iter().collect::<Vec<_>>(),
                weighted_ngram_hashes: rustc_hash::FxHashMap::default(),
                signature_ngrams: Vec::new(),
                param_type_ngrams: Vec::new(),
                name_segments: Vec::new(),
                structural_markers: Vec::new(),
                type_usages: Vec::new(),
                comment_density: 0.0,
                semantic_markers: Vec::new(),
                skeleton: Vec::new(),
                skeleton_hashes: Vec::new(),
                control_flow_hashes: Vec::new(),
                control_flow_sequence: Vec::new(),
                api_calls: Vec::new(),
                api_call_segments: Vec::new(),
                property_accesses: Vec::new(),
                motif_hashes: Vec::new(),
                data_flow_path_hashes: Vec::new(),
                raw_call_names: Vec::new(),
                param_names: Vec::new(),
                tainted_api_calls: Vec::new(),
                config_literal_hashes: Vec::new(),
                argument_call_types: Vec::new(),
                literal_pattern_hashes: Vec::new(),
                has_http_decorator: false,
                is_registered_handler: false,
                export_handler_kind: None,
            });
        }

        let sources = frensense::SourceRegistry::new();

        group.bench_with_input(
            BenchmarkId::new("pairwise_comparison", fp_count),
            &fp_count,
            |b, _| {
                let engine = Engine::new();
                b.iter(|| {
                    engine.post_process_ngrams(black_box(&fingerprints), black_box(&sources))
                });
            },
        );
    }

    group.finish();
}

// ── Groups wired to criterion ─────────────────────────────────────────────────

criterion_group!(throughput, bench_scan_throughput, bench_project_scale);

criterion_group!(analysis, bench_taint_depth);

criterion_group!(
    engine_internals,
    bench_rule_compilation,
    bench_symbol_registry,
    bench_fingerprinting,
    bench_post_process_ngrams,
);

criterion_main!(throughput, analysis, engine_internals);
