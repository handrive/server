//! Structured logging with JSON format and daily rotation.

use std::path::Path;
use std::time::{Duration, SystemTime};

use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt::format::JsonFields;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter, Layer};

/// Logging configuration.
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Directory for log files.
    pub log_dir: String,
    /// Prefix for log file names (e.g., "handrive-server" -> "handrive-server.2024-01-15.log").
    pub log_file_prefix: String,
    /// Default log level filter (e.g., "info", "debug", "handrive_server=debug").
    pub log_level: String,
    /// Number of days to retain log files (0 = keep forever).
    pub log_retention_days: u32,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            log_dir: "/var/log/handrive".to_string(),
            log_file_prefix: "handrive-server".to_string(),
            log_level: "info".to_string(),
            log_retention_days: 7,
        }
    }
}

/// Initialize structured logging with JSON format and daily rotation.
///
/// Returns a guard that must be kept alive for the duration of the program
/// to ensure all logs are flushed to the file.
pub fn init_logging(config: &LogConfig) -> Result<WorkerGuard, std::io::Error> {
    // Ensure log directory exists
    std::fs::create_dir_all(&config.log_dir)?;

    // Create rolling file appender with daily rotation
    let file_appender = RollingFileAppender::new(
        Rotation::DAILY,
        &config.log_dir,
        &config.log_file_prefix,
    );

    // Create non-blocking writer (returns guard that must be kept alive)
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // Build env filter from config or RUST_LOG env var
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    // JSON file layer
    let json_layer = fmt::layer()
        .json()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .fmt_fields(JsonFields::new())
        .with_filter(env_filter.clone());

    // Console layer (compact, for development)
    let console_layer = fmt::layer()
        .compact()
        .with_target(true)
        .with_filter(env_filter);

    // Initialize subscriber with both layers
    tracing_subscriber::registry()
        .with(json_layer)
        .with(console_layer)
        .init();

    tracing::info!(
        log_dir = %config.log_dir,
        log_prefix = %config.log_file_prefix,
        "Logging initialized with daily rotation"
    );

    Ok(guard)
}

/// Clean up log files older than the specified retention period.
///
/// Returns the number of files deleted.
pub fn cleanup_old_logs(log_dir: &str, file_prefix: &str, retention_days: u32) -> std::io::Result<u64> {
    if retention_days == 0 {
        return Ok(0);
    }

    let log_path = Path::new(log_dir);
    if !log_path.exists() {
        return Ok(0);
    }

    let retention_duration = Duration::from_secs(retention_days as u64 * 24 * 60 * 60);
    let cutoff_time = SystemTime::now()
        .checked_sub(retention_duration)
        .unwrap_or(SystemTime::UNIX_EPOCH);

    let mut deleted_count = 0u64;

    for entry in std::fs::read_dir(log_path)? {
        let entry = entry?;
        let path = entry.path();

        // Only process files that match the log prefix
        if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
            if !file_name.starts_with(file_prefix) {
                continue;
            }
        } else {
            continue;
        }

        // Check file modification time
        if let Ok(metadata) = entry.metadata() {
            if let Ok(modified) = metadata.modified() {
                if modified < cutoff_time {
                    if std::fs::remove_file(&path).is_ok() {
                        deleted_count += 1;
                        tracing::debug!(file = ?path, "Deleted old log file");
                    }
                }
            }
        }
    }

    Ok(deleted_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    /// Create a unique temp directory for a test and return its path.
    /// Caller is responsible for cleanup via `fs::remove_dir_all`.
    fn make_test_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("handrive_log_test_{}_{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_cleanup_retention_zero_keeps_all() {
        let dir = make_test_dir("retention_zero");
        let dir_path = dir.to_str().unwrap();

        let file_path = dir.join("handrive-server.2020-01-01");
        fs::File::create(&file_path).unwrap();

        let deleted = cleanup_old_logs(dir_path, "handrive-server", 0).unwrap();
        assert_eq!(deleted, 0);
        assert!(file_path.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cleanup_nonexistent_dir_returns_zero() {
        let deleted = cleanup_old_logs("/tmp/nonexistent-dir-handrive-test-xyz", "prefix", 7).unwrap();
        assert_eq!(deleted, 0);
    }

    #[test]
    fn test_cleanup_preserves_recent_files() {
        let dir = make_test_dir("preserves_recent");
        let dir_path = dir.to_str().unwrap();

        let file_path = dir.join("handrive-server.recent");
        let mut f = fs::File::create(&file_path).unwrap();
        f.write_all(b"recent log").unwrap();

        let deleted = cleanup_old_logs(dir_path, "handrive-server", 7).unwrap();
        assert_eq!(deleted, 0);
        assert!(file_path.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cleanup_ignores_non_matching_prefix() {
        let dir = make_test_dir("non_matching");
        let dir_path = dir.to_str().unwrap();

        let file_path = dir.join("other-app.2020-01-01");
        fs::File::create(&file_path).unwrap();

        // File doesn't match prefix "handrive-server", so it should not be deleted
        let deleted = cleanup_old_logs(dir_path, "handrive-server", 7).unwrap();
        assert_eq!(deleted, 0);
        assert!(file_path.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cleanup_empty_directory() {
        let dir = make_test_dir("empty_dir");
        let dir_path = dir.to_str().unwrap();

        let deleted = cleanup_old_logs(dir_path, "handrive-server", 7).unwrap();
        assert_eq!(deleted, 0);

        let _ = fs::remove_dir_all(&dir);
    }
}
