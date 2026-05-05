//! Platform-default storage roots for Beam (Phase 9; aligns with ADR 0057 intent).
//!
//! Override roots with `BEAM_DATA_DIR`; session files default to `<data>/sessions`.

use std::path::PathBuf;

/// Root directory for durable Beam state (sessions, future local DB).
#[must_use]
pub fn beam_data_dir() -> PathBuf {
    if let Ok(p) = std::env::var("BEAM_DATA_DIR") {
        return PathBuf::from(p);
    }
    #[cfg(windows)]
    {
        let base = std::env::var("LOCALAPPDATA")
            .unwrap_or_else(|_| std::env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string()));
        PathBuf::from(base).join("Beam")
    }
    #[cfg(not(windows))]
    {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            return PathBuf::from(xdg).join("beam");
        }
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(".local/share/beam");
        }
        PathBuf::from(".local/share/beam")
    }
}

#[must_use]
pub fn beam_sessions_dir() -> PathBuf {
    beam_data_dir().join("sessions")
}

#[must_use]
pub fn beam_cache_dir() -> PathBuf {
    beam_data_dir().join("cache")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_dir_under_data() {
        assert_eq!(beam_sessions_dir(), beam_data_dir().join("sessions"));
        assert_eq!(beam_cache_dir(), beam_data_dir().join("cache"));
    }
}
