//! Logging infrastructure for differential fuzzing
//!
//! This module provides structured logging capabilities

use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

/// Severity levels for differential fuzzing logs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// Informational messages (normal operations)
    Info,

    /// Error messages
    Error,

    /// Critical bugs found (differential mismatches)
    Critical,
}

impl LogLevel {
    /// Returns the string representation of the log level for output formatting.
    ///
    /// # Returns
    /// A static string like "!!! INFO !!!", "!!! ERROR !!!", or "!!! CRITICAL !!!"
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Info => "!!! INFO !!!",
            LogLevel::Error => "!!! ERROR !!!",
            LogLevel::Critical => "!!! CRITICAL !!!",
        }
    }
}

/// Thread-safe logger for fuzzing campaigns
struct FuzzLogger {
    /// Optional log file with mutex for concurrent writes
    log_file: Mutex<Option<std::fs::File>>,

    /// Whether to output logs to console (stdout/stderr)
    enable_console: bool,

    /// Minimum severity level to log
    min_level: LogLevel,
}

impl FuzzLogger {
    /// Create a new logger
    fn new(log_path: Option<&str>, enable_console: bool, min_level: LogLevel) -> Self {
        // Check if running from interactive script
        let final_log_path = if let Ok(logs_dir) = env::var("FLORESTA_FUZZ_LOGS_DIR") {
            // Extract target name from log_path or use default
            let target_name = log_path
                .and_then(|p| p.split('/').next_back())
                .unwrap_or("fuzzer.log");
            Some(format!("{}/{}", logs_dir, target_name))
        } else {
            log_path.map(String::from)
        };

        let log_file = if let Some(path) = final_log_path {
            // Create parent directory if needed
            if let Some(parent) = std::path::Path::new(&path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }

            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .ok()
        } else {
            None
        };

        Self {
            log_file: Mutex::new(log_file),
            enable_console,
            min_level,
        }
    }

    /// Log a message at the specified level
    fn log(&self, level: LogLevel, category: &str, message: &str) {
        if level as u8 >= self.min_level as u8 {
            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
            let formatted = format!(
                "[{}] {} [{}] {}",
                timestamp,
                level.as_str(),
                category,
                message
            );

            // Console output
            if self.enable_console {
                match level {
                    LogLevel::Error | LogLevel::Critical => eprintln!("{}", formatted),
                    _ => println!("{}", formatted),
                }
            }

            // File output
            if let Ok(mut file_opt) = self.log_file.lock() {
                if let Some(file) = file_opt.as_mut() {
                    let _ = writeln!(file, "{}", formatted);
                    let _ = file.flush();
                }
            }
        }
    }

    /// Log differential bug discovery
    fn log_differential_bug(
        &self,
        address: &str,
        hex_data: &str,
        floresta_result: bool,
        core_result: bool,
    ) {
        let msg = format!(
            "Differential mismatch:\n  Address: {}\n  Hex: {}\n  Floresta: {}\n  Bitcoin Core: {}",
            address, hex_data, floresta_result, core_result
        );
        self.log(LogLevel::Critical, "DIFFERENTIAL", &msg);
    }
}

/// Global logger instance
use std::sync::OnceLock;
static LOGGER: OnceLock<FuzzLogger> = OnceLock::new();
/// Initializes the global logger instance.
///
/// This must be called once before using `log()` or `log_differential_bug()`.
/// Subsequent calls are ignored (singleton pattern).
///
/// # Arguments
/// * `log_path` - Optional file path for log output
/// * `enable_console` - Whether to also output to console
/// * `min_level` - Minimum severity level to log
pub fn init_logger(log_path: Option<&str>, enable_console: bool, min_level: LogLevel) {
    LOGGER.get_or_init(|| FuzzLogger::new(log_path, enable_console, min_level));
}

/// Logs a message to the global logger.
///
/// # Arguments
/// * `level` - Severity level (Info, Error, Critical)
/// * `category` - Short identifier for the log source (e.g., "FUZZER", "RPC")
/// * `message` - Log message content
pub fn log(level: LogLevel, category: &str, message: &str) {
    if let Some(logger) = LOGGER.get() {
        logger.log(level, category, message);
    }
}

/// Logs a differential bug discovery with structured format.
///
/// # Arguments
/// * `address` - Bitcoin address being tested
/// * `hex_data` - Hex representation of test input
/// * `rust_result` - Floresta (Rust implementation) result
/// * `core_result` - Bitcoin Core result
///
/// Always logs at `Critical` level under "DIFFERENTIAL" category.
pub fn log_differential_bug(address: &str, hex_data: &str, rust_result: bool, core_result: bool) {
    if let Some(logger) = LOGGER.get() {
        logger.log_differential_bug(address, hex_data, rust_result, core_result);
    }
}
