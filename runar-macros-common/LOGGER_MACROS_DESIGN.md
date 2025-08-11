## Runar Logger Macros: Zero-overhead when disabled

Goal: Remove `format!` at call sites and avoid any work when a log level is disabled, while preserving the existing logging pipeline, formatting, node/component prefixes, and contextual `Logger` usage.

### Requirements
- Keep using the existing `Logger` type to preserve node id, component, parent, action path, event path, and the current formatting semantics.
- Use the `log` crate for enablement checks and emission (no custom backends).
- Ensure there is zero formatting/allocation overhead when the level is disabled.
- Do not require changes to existing logger internals for initial adoption.

### Design

- Introduce macros that:
  - Check `log::log_enabled!(Level::X)` first.
  - Only when enabled, build the message string via `format!(...)` and emit via the existing `Logger` methods (`debug/info/warn/error`), so existing prefix formatting remains unchanged.
  - Provide both a generic macro and level-specific convenience macros.

Macros provided:
- `runar_log!(logger, Debug|Info|Warn|Error, "...", args...)`
- `rlog_debug!(logger, "...", args...)`
- `rlog_info!(logger,  "...", args...)`
- `rlog_warn!(logger,  "...", args...)`
- `rlog_error!(logger, "...", args...)`

These macros accept any expression for `logger` (typically a `&Logger`), and a format string with optional arguments. They do not allocate or format when the respective level is disabled.

### Example

Before:
```rust
logger.info(format!("Starting {} services", services.len()));
```

After:
```rust
use runar_macros_common::rlog_info;
rlog_info!(logger, "Starting {} services", services.len());
```

Behavior:
- If `Info` is disabled, the macro early-returns and the `format!` is never executed.
- If `Info` is enabled, the message is formatted and passed to `logger.info(...)`, preserving the existing prefix formatting and context.

### Why not bypass `Logger`?

We intentionally route through `Logger::{debug,info,warn,error}` so that the current prefix rendering and context behavior remain exactly the same. This also minimizes the required surface changes and avoids adding new `Logger` APIs.

### Future enhancement (optional)

For even fewer allocations when enabled:
- Add `Logger` helpers that accept `fmt::Arguments` or write prefixes via a `Display` wrapper without allocating a `String`. Then update these macros to use `format_args!` and `log::$level!("{} {}", Prefix(&logger), format_args!(...))`. This keeps compatibility while further reducing allocations on enabled paths.

### Adoption plan

1) Introduce macros in `runar-macros-common` (this crate).
2) Replace hot-path `format!` + `logger.info/debug/...` sites with `rlog_*!(...)` macros.
3) Validate that logs remain identical and that disabled levels incur zero work.
4) Optionally add compile-time level filtering features later.


