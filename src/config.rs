// Configuration schema for Numiport transport.
// Numan Thabit 2025 November weekend fun

use std::{
    env, fmt, fs,
    io::{self, Read},
    path::{Path, PathBuf},
    str::FromStr,
};

use serde::Deserialize;
use thiserror::Error;

/// Error returned while loading or validating configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Error when reading a configuration file from disk.
    #[error("failed to read config '{path}': {source}")]
    Io {
        /// Path that failed to read.
        path: PathBuf,
        /// Source IO error.
        #[source]
        source: io::Error,
    },
    /// Error when parsing the configuration contents.
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
    /// The configuration did not pass validation checks.
    #[error("invalid config: {0}")]
    Validation(String),
}

/// High-level configuration loaded at startup.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    /// Tunable profiles for different network conditions.
    pub profiles: Profiles,
}

impl Config {
    /// Loads configuration from `NUMIPORT_CONFIG` if set, otherwise returns defaults.
    pub fn load() -> Result<Self, ConfigError> {
        match env::var("NUMIPORT_CONFIG") {
            Ok(path) => Self::from_path(path),
            Err(_missing) => {
                let cfg = Self::default();
                cfg.validate()?;
                Ok(cfg)
            }
        }
    }

    /// Loads a configuration file from the provided path.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path_ref = path.as_ref();
        let contents = fs::read_to_string(path_ref).map_err(|source| ConfigError::Io {
            path: path_ref.to_path_buf(),
            source,
        })?;
        Self::from_toml_str(&contents)
    }

    /// Loads configuration from any reader implementing [`Read`].
    pub fn from_reader<R: Read>(mut reader: R) -> Result<Self, ConfigError> {
        let mut buf = String::new();
        reader
            .read_to_string(&mut buf)
            .map_err(|source| ConfigError::Io {
                path: PathBuf::from("<reader>"),
                source,
            })?;
        Self::from_toml_str(&buf)
    }

    /// Loads configuration from a TOML string slice.
    pub fn from_toml_str(input: &str) -> Result<Self, ConfigError> {
        <Self as FromStr>::from_str(input)
    }

    /// Returns the active profile based on `NUMIPORT_PROFILE` or the provided fallback.
    pub fn active_profile(&self, fallback: ProfileName) -> (ProfileName, &Profile) {
        let env_choice = env::var("NUMIPORT_PROFILE")
            .ok()
            .and_then(|value| ProfileName::from_str(&value).ok());
        let name = env_choice.unwrap_or(fallback);
        let profile = self.profiles.get(name);
        (name, profile)
    }

    /// Validates the configuration, returning an error when constraints are violated.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.profiles
            .intra_dc
            .validate()
            .map_err(ConfigError::Validation)?;
        self.profiles
            .cross_dc
            .validate()
            .map_err(ConfigError::Validation)?;
        Ok(())
    }
}

impl FromStr for Config {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cfg: Self = toml::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }
}

/// Named profile selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileName {
    /// Intra-datacenter, low-latency profile.
    IntraDc,
    /// Cross-datacenter, higher-latency profile.
    CrossDc,
}

impl FromStr for ProfileName {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "intra_dc" | "intra" | "lan" => Ok(ProfileName::IntraDc),
            "cross_dc" | "cross" | "wan" => Ok(ProfileName::CrossDc),
            other => Err(ConfigError::Validation(format!(
                "unknown profile '{other}'; expected intra_dc or cross_dc"
            ))),
        }
    }
}

impl fmt::Display for ProfileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfileName::IntraDc => f.write_str("intra_dc"),
            ProfileName::CrossDc => f.write_str("cross_dc"),
        }
    }
}

/// Collection of named profiles used by the transport.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Profiles {
    /// Low-latency intra-datacenter profile.
    #[serde(default = "Profile::intra_dc_defaults")]
    pub intra_dc: Profile,
    /// Cross-datacenter profile tuned for higher RTT and loss.
    #[serde(default = "Profile::cross_dc_defaults")]
    pub cross_dc: Profile,
}

impl Default for Profiles {
    fn default() -> Self {
        Self {
            intra_dc: Profile::intra_dc_defaults(),
            cross_dc: Profile::cross_dc_defaults(),
        }
    }
}

impl Profiles {
    /// Returns a profile by name.
    pub fn get(&self, name: ProfileName) -> &Profile {
        match name {
            ProfileName::IntraDc => &self.intra_dc,
            ProfileName::CrossDc => &self.cross_dc,
        }
    }
}

/// Tunable parameters for a given profile.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Profile {
    /// Token bucket budgets per service class, expressed in bytes per slot.
    pub budgets: Budgets,
    /// Minimum guaranteed send capacity per class.
    pub floors: Floors,
    /// Burst caps per traffic class.
    pub burst_caps: BurstCaps,
    /// ECN scaler thresholds controlling send rate adjustments.
    pub ecn: EcnScaler,
    /// Guard delta bounds for pacing with ETF/SCM_TXTIME.
    pub guard_delta: GuardDeltaBounds,
}

impl Profile {
    /// Default parameters for the intra-DC profile.
    pub fn intra_dc_defaults() -> Self {
        Self {
            budgets: Budgets {
                p0: 2 * MIB,
                p1: 32 * MIB,
                p2: 48 * MIB,
                p3: 8 * MIB,
            },
            floors: Floors {
                p1: 8 * MIB,
                p2: 24 * MIB,
            },
            burst_caps: BurstCaps {
                p0: 4 * MIB,
                p1: 64 * MIB,
                p2: 64 * MIB,
                p3: 8 * MIB,
            },
            ecn: EcnScaler {
                ce_start: 0.01,
                ce_stop: 0.05,
                min_scale: 0.5,
                max_scale: 1.25,
            },
            guard_delta: GuardDeltaBounds {
                min_ns: 50_000,
                max_ns: 1_500_000,
                initial_ns: 250_000,
            },
        }
    }

    /// Default parameters for the cross-DC profile.
    pub fn cross_dc_defaults() -> Self {
        Self {
            budgets: Budgets {
                p0: MIB,
                p1: 16 * MIB,
                p2: 32 * MIB,
                p3: 6 * MIB,
            },
            floors: Floors {
                p1: 6 * MIB,
                p2: 16 * MIB,
            },
            burst_caps: BurstCaps {
                p0: 2 * MIB,
                p1: 32 * MIB,
                p2: 48 * MIB,
                p3: 10 * MIB,
            },
            ecn: EcnScaler {
                ce_start: 0.02,
                ce_stop: 0.08,
                min_scale: 0.4,
                max_scale: 1.5,
            },
            guard_delta: GuardDeltaBounds {
                min_ns: 100_000,
                max_ns: 3_000_000,
                initial_ns: 500_000,
            },
        }
    }

    /// Ensures invariants for the profile hold.
    pub fn validate(&self) -> Result<(), String> {
        if self.budgets.p0 == 0
            || self.budgets.p1 == 0
            || self.budgets.p2 == 0
            || self.budgets.p3 == 0
        {
            return Err("budgets must be non-zero for all classes".into());
        }

        if self.floors.p1 > self.budgets.p1 {
            return Err("P1 floor exceeds budget".into());
        }
        if self.floors.p2 > self.budgets.p2 {
            return Err("P2 floor exceeds budget".into());
        }
        if self.burst_caps.p0 < self.budgets.p0 {
            return Err("P0 burst cap must be >= budget".into());
        }
        if self.burst_caps.p1 < self.budgets.p1 {
            return Err("P1 burst cap must be >= budget".into());
        }
        if self.burst_caps.p2 < self.budgets.p2 {
            return Err("P2 burst cap must be >= budget".into());
        }
        if self.burst_caps.p3 < self.budgets.p3 {
            return Err("P3 burst cap must be >= budget".into());
        }
        if !(0.0..1.0).contains(&self.ecn.ce_start) {
            return Err("ECN ce_start must be in [0,1)".into());
        }
        if !(0.0..=1.0).contains(&self.ecn.ce_stop) {
            return Err("ECN ce_stop must be in [0,1]".into());
        }
        if self.ecn.ce_start >= self.ecn.ce_stop {
            return Err("ECN ce_start must be < ce_stop".into());
        }
        if self.ecn.min_scale <= 0.0 {
            return Err("ECN min_scale must be > 0".into());
        }
        if self.ecn.max_scale < self.ecn.min_scale {
            return Err("ECN max_scale must be >= min_scale".into());
        }

        self.guard_delta.validate()?;

        Ok(())
    }
}

/// Token bucket budgets for each traffic class.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Budgets {
    /// Critical control traffic (repair, leader selection).
    pub p0: u64,
    /// Real-time block propagation payloads.
    pub p1: u64,
    /// Background data required for consensus.
    pub p2: u64,
    /// Opportunistic / best-effort payloads.
    pub p3: u64,
}

impl Default for Budgets {
    fn default() -> Self {
        Profile::intra_dc_defaults().budgets
    }
}

/// Guaranteed floors for key classes.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Floors {
    /// P1 floor in bytes per slot.
    pub p1: u64,
    /// P2 floor in bytes per slot.
    pub p2: u64,
}

impl Default for Floors {
    fn default() -> Self {
        Profile::intra_dc_defaults().floors
    }
}

/// Burst caps applied per traffic class.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BurstCaps {
    /// Maximum burst for P0.
    pub p0: u64,
    /// Maximum burst for P1.
    pub p1: u64,
    /// Maximum burst for P2.
    pub p2: u64,
    /// Maximum burst for P3.
    pub p3: u64,
}

impl Default for BurstCaps {
    fn default() -> Self {
        Profile::intra_dc_defaults().burst_caps
    }
}

/// ECN scaler thresholds.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct EcnScaler {
    /// CE fraction where scaling begins.
    pub ce_start: f32,
    /// CE fraction where scaling clamps to minimum.
    pub ce_stop: f32,
    /// Minimum multiplicative scale.
    pub min_scale: f32,
    /// Maximum multiplicative scale.
    pub max_scale: f32,
}

impl Default for EcnScaler {
    fn default() -> Self {
        Profile::intra_dc_defaults().ecn
    }
}

/// Guard delta bounds expressed in nanoseconds.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GuardDeltaBounds {
    /// Minimum guard delta when ETF is stable.
    pub min_ns: u64,
    /// Maximum guard delta before faulting ETF.
    pub max_ns: u64,
    /// Starting guard delta.
    pub initial_ns: u64,
}

impl GuardDeltaBounds {
    fn validate(&self) -> Result<(), String> {
        if self.min_ns == 0 {
            return Err("guard_delta.min_ns must be > 0".into());
        }
        if self.max_ns <= self.min_ns {
            return Err("guard_delta.max_ns must be > min_ns".into());
        }
        if self.initial_ns < self.min_ns || self.initial_ns > self.max_ns {
            return Err("guard_delta.initial_ns must lie within [min_ns, max_ns]".into());
        }
        Ok(())
    }
}

impl Default for GuardDeltaBounds {
    fn default() -> Self {
        Profile::intra_dc_defaults().guard_delta
    }
}

const MIB: u64 = 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        let cfg = Config::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn invalid_budget_rejected() {
        let input = r#"
            [profiles.intra_dc.budgets]
            p0 = 0
            p1 = 1
            p2 = 1
            p3 = 1
        "#;

        let err = Config::from_toml_str(input).unwrap_err();
        match err {
            ConfigError::Validation(msg) => {
                assert!(msg.contains("budgets"));
            }
            other => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn profile_selection_from_env() {
        let cfg = Config::default();
        std::env::set_var("NUMIPORT_PROFILE", "cross_dc");
        let (profile_name, profile) = cfg.active_profile(ProfileName::IntraDc);
        assert_eq!(profile_name, ProfileName::CrossDc);
        assert_eq!(profile.budgets.p1, Profile::cross_dc_defaults().budgets.p1);
        std::env::remove_var("NUMIPORT_PROFILE");
    }
}
