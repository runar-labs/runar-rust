# Storage Engine Options for Runar & KERI Integration

*Status: Draft Analysis – for review*

Runar components (mobile-mock, witness, node daemon) share similar persistence
needs:

1. **KERI Event Logs (KEL/KERL)** – append-heavy, ordered, cryptographically
   verifiable, small random reads during state derivation.
2. **Encrypted Payload Storage** – key–value blobs; read-heavy for node daemon.
3. **High Concurrency** – async workloads, many threads.
4. **Long-term Reliability** – no data loss across OS crashes or power failure.
5. **Cross-Platform** – Linux, macOS, (future) mobile.

Below we evaluate candidate Rust storage engines.

---

## 1. Sled (`sled` crate)

| Aspect | Notes |
| --- | --- |
| **Maturity** | *Beta*, disk format not yet frozen – manual migrations required before 1.0. |
| **Performance** | Excellent write throughput; lock-free read path. |
| **Concurrency** | Designed for multi-threaded workloads; uses lock-free data structures. |
| **Space usage** | Reports of bloat for certain workloads (esp. large values). |
| **Features** | Ordered key-value store, transactional batches, crash-safe, async interface via blocking wrapper. |
| **Risks** | Disk-format instability, small maintainer team, no multi-process safety. |

### Fit for Runar
*Pros*: Fast, good ergonomic API, already integrated in `keri` upstream.
*Cons*: Beta stability clashes with production timeline; migration burden.
*Verdict*: **Acceptable for PoC**, reassess before production.

---

## 2. SQLite (via `rusqlite`, `sqlx`)

| Aspect | Notes |
| --- | --- |
| **Maturity** | Battle-tested, stable disk format. |
| **Performance** | Good read performance, reasonable writes; WAL mode allows
concurrency but still single-writer. |
| **Concurrency** | Multiple readers, single writer (mitigated with WAL & connection pooling). |
| **Space usage** | Compact. |
| **Features** | Full SQL, ACID, predictable tooling & backup. |
| **Risks** | Write contention in highly parallel workloads; binary dependency on C library. |

### Fit for Runar
*Pros*: Rock-solid reliability, easy migration & introspection.
*Cons*: Single-writer model may throttle witness under heavy write bursts; bigger binary size on mobile.
*Verdict*: **Strong candidate for production witness & mobile-mock**, possibly less ideal for high-write node daemon.

---

## 3. RocksDB (via `rocksdb` crate)

| Aspect | Notes |
| --- | --- |
| **Maturity** | Widely used in large-scale systems (TiKV, Cockroach). |
| **Performance** | Excellent for append & range queries; tunable compaction. |
| **Concurrency** | Multi-threaded background flush/compaction; supports many concurrent reads & writes. |
| **Space usage** | Generally efficient; can be tuned. |
| **Features** | Column families, snapshots, prefix iterators, live backup. |
| **Risks** | Native C++ dependency; tuning complexity. |

### Fit for Runar
*Pros*: Scales well to 800+ node networks; append-friendly; stable on-disk format.
*Cons*: Larger binary, trickier build on some platforms.
*Verdict*: **Best technical fit for node daemon** if binary size is acceptable.

---

## 4. LMDB (via `lmdb-rs`, `heed`)

| Aspect | Notes |
| --- | --- |
| **Maturity** | Very stable, used in many projects (OpenLDAP, Ethereum). |
| **Performance** | Fast reads, copy-on-write pages. |
| **Concurrency** | Multi-process readers; single writer txn at a time. |
| **Space usage** | Compact but requires pre-allocation. |
| **Features** | ACID, memory-mapped, zero-copy reads. |
| **Risks** | Write contention, fixed DB size unless re-map. |

### Fit for Runar
*Verdict*: Adequate for witness (mostly reads) but single-writer limitation hurts node.

---

## 5. Komora-io Component Crates

The original sled author is rewriting primitives under the *komora-io* org. Key crates:

| Crate | Purpose | Potential Use in Runar |
| --- | --- | --- |
| **`marble`** | GC-ing object store on sharded-log + pointer indirection. | Encrypted blob storage for node (large file support). |
| **`sharded-log`** | Lock-free, low-contention write-ahead log segments. | Could replace custom append-only event log; excellent for KEL. |
| **`concurrent-map`** | Lock-free B+ tree in-mem map. | Fast in-process cache for hot state. |
| **`cache-advisor`** | Sharded concurrent LRU/clock. | Node layer caching of decrypted payloads. |
| **`ebr`** | Epoch-based reclamation. | Low-level building block, likely indirectly used. |
| **`tiny-lsm`** | Minimal LSM for fixed-size kv. | Sequence number → event pointer index. |
| **`metadata-store`** | Persistent mapping of IDs to offsets. | Secondary indices for quick lookup. |
| **Others (`fault-injection`, `optimistic-cell`, etc.)** | Infrastructure / testing / lock-free cells. | Useful for fuzz & chaos testing.

### Observations
These crates are **experimental** but align with Runar’s highly concurrent design ethos. They promote composability: build only components we need, avoid full DB overhead. However they are pre-1.0 and lack production adoption.

---

## Synthesis & Recommendation

| Component | Recommended Engine | Rationale |
| --- | --- | --- |
| **KERI Event Log (witness+node)** | **RocksDB** (prod) / sled (PoC) | Append-oriented, large write volume, stable format needed for long-term KEL persistence. RocksDB gives reliability today; sled acceptable for rapid prototyping. |
| **Encrypted Blob Store (node)** | `marble` (future) / RocksDB columns | Marble’s GC object store matches immutable encrypted chunks; if not production-ready, reuse RocksDB column family. |
| **Mobile-Mock (wallet)** | SQLite | Small, local, rarely-writing; easy backup via SQL. |
| **In-process Hot Cache** | `concurrent-map` + `cache-advisor` | Lock-free, scan-resistant cache for decrypted payloads; drop-in for node daemon. |

Phased approach:

1. **PoC/Phase-1** (months 0-3): keep sled via upstream `keri` to reduce integration risk; run integration tests.
2. **Phase-2** (months 4-6): spike RocksDB backend wrapper implementing `EventDatabase` trait; benchmark vs sled.
3. **Phase-3** (months 7-9): evaluate komora-io crates; integrate `sharded-log` for high-throughput KEL replication.
4. **Phase-4** (prod hardening): freeze chosen engine(s); implement data-migration tooling.

---

## Action Items

1. **Create `runar-storage` crate** abstracting over sled/RocksDB so higher layers stay agnostic.
2. **Contribute PR to forked `keriox`** adding a generic `EventDatabase` trait + RocksDB implementation (behind feature flag `rocksdb-db`).
3. Produce benchmarks (KEL write/read throughput, crash-recovery) for sled vs RocksDB vs sharded-log.
4. Keep watch on komora-io releases; allocate spike week when they stabilise.

---

*Prepared by: Cascade AI – 2025-06-14*
