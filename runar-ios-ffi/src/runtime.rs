use anyhow::Result;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::Duration;
use tokio::runtime::{Handle, Runtime};

/// Managed tokio runtime with explicit lifecycle control
pub struct ManagedRuntime {
    runtime_handle: Arc<Mutex<Option<Handle>>>,
    runtime_thread: Arc<Mutex<Option<thread::JoinHandle<()>>>>,
    shutdown_signal: Arc<AtomicBool>,
    is_running: Arc<AtomicBool>,
}

impl ManagedRuntime {
    pub fn new() -> Self {
        Self {
            runtime_handle: Arc::new(Mutex::new(None)),
            runtime_thread: Arc::new(Mutex::new(None)),
            shutdown_signal: Arc::new(AtomicBool::new(false)),
            is_running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the tokio runtime on a dedicated thread
    pub fn start(&self) -> Result<()> {
        if self.is_running.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("Runtime is already running"));
        }

        let shutdown_signal = self.shutdown_signal.clone();
        let runtime_handle = self.runtime_handle.clone();
        let is_running = self.is_running.clone();

        // Reset shutdown signal
        self.shutdown_signal.store(false, Ordering::SeqCst);

        let handle = thread::spawn(move || {
            // Create multi-threaded runtime
            let rt = match Runtime::new() {
                Ok(runtime) => runtime,
                Err(e) => {
                    eprintln!("Failed to create tokio runtime: {e}");
                    return;
                }
            };

            let handle = rt.handle().clone();

            // Share the handle with the main thread
            *runtime_handle.lock().unwrap() = Some(handle);
            is_running.store(true, Ordering::SeqCst);

            // Block on runtime until shutdown signal
            rt.block_on(async {
                while !shutdown_signal.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            });

            is_running.store(false, Ordering::SeqCst);
        });

        *self.runtime_thread.lock().unwrap() = Some(handle);
        Ok(())
    }

    /// Shutdown the runtime gracefully
    pub fn shutdown(&self) -> Result<()> {
        if !self.is_running.load(Ordering::SeqCst) {
            return Ok(());
        }

        // Signal shutdown
        self.shutdown_signal.store(true, Ordering::SeqCst);

        // Wait for runtime thread to finish
        if let Some(handle) = self.runtime_thread.lock().unwrap().take() {
            match handle.join() {
                Ok(_) => {
                    *self.runtime_handle.lock().unwrap() = None;
                    self.is_running.store(false, Ordering::SeqCst);
                    Ok(())
                }
                Err(_) => Err(anyhow::anyhow!("Failed to join runtime thread")),
            }
        } else {
            Ok(())
        }
    }

    /// Get the runtime handle if available
    pub fn handle(&self) -> Option<Handle> {
        self.runtime_handle.lock().unwrap().clone()
    }

    /// Check if runtime is running
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    /// Spawn a task on the runtime
    pub fn spawn<F>(&self, future: F) -> Result<()>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        if let Some(handle) = self.handle() {
            handle.spawn(future);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Runtime not available"))
        }
    }

    /// Block on a future using the runtime
    pub fn block_on<F, T>(&self, future: F) -> Result<T>
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        if let Some(handle) = self.handle() {
            Ok(futures::executor::block_on(async {
                handle.spawn(future).await.unwrap()
            }))
        } else {
            Err(anyhow::anyhow!("Runtime not available"))
        }
    }
}

impl Drop for ManagedRuntime {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

/// Runtime manager with platform-specific lifecycle
pub struct PlatformRuntimeManager {
    runtime: Arc<ManagedRuntime>,
    app_state: Arc<AtomicBool>, // true = foreground, false = background
}

impl PlatformRuntimeManager {
    pub fn new() -> Self {
        Self {
            runtime: Arc::new(ManagedRuntime::new()),
            app_state: Arc::new(AtomicBool::new(true)), // Start in foreground
        }
    }

    /// Initialize the runtime
    pub fn initialize(&self) -> Result<()> {
        self.runtime.start()
    }

    /// Handle app entering background
    pub fn handle_background(&self) -> Result<()> {
        self.app_state.store(false, Ordering::SeqCst);

        // Shutdown runtime completely
        self.runtime.shutdown()
    }

    /// Handle app entering foreground
    pub fn handle_foreground(&self) -> Result<()> {
        self.app_state.store(true, Ordering::SeqCst);

        // Restart runtime
        self.runtime.start()
    }

    /// Get runtime handle
    pub fn runtime_handle(&self) -> Option<Handle> {
        self.runtime.handle()
    }

    /// Check if app is in foreground
    pub fn is_foreground(&self) -> bool {
        self.app_state.load(Ordering::SeqCst)
    }

    /// Check if runtime is running
    pub fn is_running(&self) -> bool {
        self.runtime.is_running()
    }
}

/// Global runtime manager instance
lazy_static::lazy_static! {
    static ref GLOBAL_RUNTIME_MANAGER: Arc<PlatformRuntimeManager> = Arc::new(PlatformRuntimeManager::new());
}

/// Get the global runtime manager
pub fn get_runtime_manager() -> &'static PlatformRuntimeManager {
    &GLOBAL_RUNTIME_MANAGER
}

/// FFI runtime management functions
pub mod ffi {
    use super::*;
    use crate::error::{CError, RunarErrorCode};

    /// Initialize the runtime
    #[no_mangle]
    pub extern "C" fn runar_runtime_initialize() -> CError {
        match get_runtime_manager().initialize() {
            Ok(_) => CError::new(
                RunarErrorCode::Success,
                "Runtime initialized".to_string(),
                None,
            ),
            Err(e) => CError::from_anyhow(e.into()),
        }
    }

    /// Handle app entering background
    #[no_mangle]
    pub extern "C" fn runar_runtime_handle_background() -> CError {
        match get_runtime_manager().handle_background() {
            Ok(_) => CError::new(
                RunarErrorCode::Success,
                "Runtime backgrounded".to_string(),
                None,
            ),
            Err(e) => CError::from_anyhow(e.into()),
        }
    }

    /// Handle app entering foreground
    #[no_mangle]
    pub extern "C" fn runar_runtime_handle_foreground() -> CError {
        match get_runtime_manager().handle_foreground() {
            Ok(_) => CError::new(
                RunarErrorCode::Success,
                "Runtime foregrounded".to_string(),
                None,
            ),
            Err(e) => CError::from_anyhow(e.into()),
        }
    }

    /// Check if runtime is running
    #[no_mangle]
    pub extern "C" fn runar_runtime_is_running() -> bool {
        get_runtime_manager().is_running()
    }

    /// Check if app is in foreground
    #[no_mangle]
    pub extern "C" fn runar_runtime_is_foreground() -> bool {
        get_runtime_manager().is_foreground()
    }
}
