/// Internal support types used by the `service_meta` procedural macro.
///
/// This module is **not** part of the public API and may change without notice.

#[derive(Clone, Default)]
#[allow(dead_code)]
#[doc(hidden)]
pub struct ServiceMetadata {
    pub name: String,
    pub path: String,
    pub description: String,
    pub version: String,
    pub network_id: Option<String>,
}
