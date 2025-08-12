// Lightweight re-export shims for logging macros to avoid macro-crate cycles.
// These forward to runar_common::logging::Logger methods with level checks.

#[macro_export]
macro_rules! log_debug {
    ($logger:expr, $($arg:tt)*) => {{
        if ::log::log_enabled!(::log::Level::Debug) {
            ($logger).debug_args(format_args!($($arg)*));
        }
    }}
}

#[macro_export]
macro_rules! log_info {
    ($logger:expr, $($arg:tt)*) => {{
        if ::log::log_enabled!(::log::Level::Info) {
            ($logger).info_args(format_args!($($arg)*));
        }
    }}
}

#[macro_export]
macro_rules! log_warn {
    ($logger:expr, $($arg:tt)*) => {{
        if ::log::log_enabled!(::log::Level::Warn) {
            ($logger).warn_args(format_args!($($arg)*));
        }
    }}
}

#[macro_export]
macro_rules! log_error {
    ($logger:expr, $($arg:tt)*) => {{
        if ::log::log_enabled!(::log::Level::Error) {
            ($logger).error_args(format_args!($($arg)*));
        }
    }}
}
