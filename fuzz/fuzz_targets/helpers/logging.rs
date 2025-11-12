//! Logging infrastructure for differential fuzzing
//!
//! This module provides structured logging capabilities 

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use std::env;

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
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Info => "!!! INFO !!!", 
            LogLevel::Error => "!!! ERROR !!!",
            LogLevel::Critical => "!!! CRITICAL !!!",
        }
    }
}

/// Thread-safe logger for fuzzing campaigns
pub struct FuzzLogger {
    log_file: Mutex<Option<std::fs::File>>,
    enable_console: bool,
    min_level: LogLevel,
}

impl FuzzLogger {
    /// Create a new logger
    pub fn new(log_path: Option<&str>, enable_console: bool, min_level: LogLevel) -> Self {
        // Check if running from interactive script
        let final_log_path = if let Ok(logs_dir) = env::var("FLORESTA_FUZZ_LOGS_DIR") {
            // Extract target name from log_path or use default
            let target_name = log_path
                .and_then(|p| p.split('/').last())
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
    pub fn log(&self, level: LogLevel, category: &str, message: &str) {
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
    pub fn log_differential_bug(
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

pub fn init_logger(log_path: Option<&str>, enable_console: bool, min_level: LogLevel) {
    LOGGER.get_or_init(|| FuzzLogger::new(log_path, enable_console, min_level));
}

pub fn log(level: LogLevel, category: &str, message: &str) {
    if let Some(logger) = LOGGER.get() {
        logger.log(level, category, message);
    }
}

pub fn log_differential_bug(address: &str, hex_data: &str, rust_result: bool, core_result: bool) {
    if let Some(logger) = LOGGER.get() {
        logger.log_differential_bug(address, hex_data, rust_result, core_result);
    }
}
