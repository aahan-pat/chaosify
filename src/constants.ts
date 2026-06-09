// Canonical home for every tunable value in Chaosify.
// Changing a value here propagates to all CLI defaults, core executors, and K8s resource names.

// Default namespace for recon commands and setup/cleanup.
export const DEFAULT_RECON_NAMESPACE = 'chaosify'

// Default namespace used by all probe commands (exec, network, identity, detect, run).
export const DEFAULT_PROBE_NAMESPACE = 'chaosify-tests'

// Names of Kubernetes resources created by `setup init` — kept here so init and cleanup stay in sync.
export const RESOURCE_QUOTA_NAME = 'chaosify-quota'
export const RUNNER_NAME = 'chaosify-runner'

// generateName prefix applied to every test pod so alert sources can correlate them back to Chaosify.
export const POD_GENERATE_NAME = 'chaosify-test-'

// CLI flag defaults — expressed in seconds because that is the unit shown to users in --help output.
export const DEFAULT_POD_TIMEOUT_S = 60
export const DEFAULT_EXEC_TIMEOUT_S = 30
export const DEFAULT_CONNECT_TIMEOUT_S = 5
export const DEFAULT_OBSERVATION_WINDOW_S = 10

// Core executor timeouts — in milliseconds, used directly by executors without any conversion.
export const DEFAULT_ADMISSION_TIMEOUT_MS = 30_000
export const DEFAULT_RUNTIME_TIMEOUT_MS = 60_000
export const DEFAULT_OBSERVATION_WINDOW_MS = 10_000

// Per-exec-step timeout inside a runtime scenario — caps the individual threat command, not the full scenario.
export const DEFAULT_EXEC_STEP_TIMEOUT_MS = 10_000

// Hard timeout for the graphnetes build subprocess before Chaosify kills it.
export const GRAPHNETES_BUILD_TIMEOUT_MS = 60_000

// How often the alert polling loop wakes up to check agent pod logs.
export const ALERT_POLL_INTERVAL_MS = 2_000

// Maximum bytes fetched per log-check call to prevent a chatty agent from stalling the poll loop.
export const ALERT_LOG_LIMIT_BYTES = 512_000

// How often waitForPodRunning polls the API server between readiness checks.
export const POD_READY_POLL_INTERVAL_MS = 500

// Bytes at which stdout and stderr are truncated to keep evidence artifacts from bloating.
// 64 KB gives agents enough room to read full recon command output without generating huge artifacts.
export const STDOUT_MAX_BYTES = 65536
export const STDERR_MAX_BYTES = 65536
