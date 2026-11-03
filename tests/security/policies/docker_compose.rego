package main

import rego.v1

# Allow-listed images that use local builds (no tag pinning required)
build_images := {
	"chronicle-backend",
	"chronicle-frontend",
}

# Services allowed to use host networking
host_network_allowed := {"fail2ban"}

# Config file extensions that should be mounted read-only
config_extensions := {".yml", ".yaml", ".toml", ".conf", ".hcl", ".json"}

# Patterns indicating hardcoded secrets in environment values
secret_key_patterns := {"password", "secret", "key"}

# Environment keys that contain a secret-like word but select a mechanism
# or metadata location rather than carrying credential material.
non_secret_selector_keys := {"pg_tde_key_provider"}

# Explicit disabled sentinels accepted only for the named optional integration.
disabled_secret_sentinel_keys := {"oidc_client_secret"}

one_shot_services contains name if {
	input.services[name].restart == "no"
}

one_shot_services contains name if {
	input.services[_].depends_on[name].condition == "service_completed_successfully"
}

runtime_pinned_images contains image if {
	image := input.services[_].image
	regex.match(`^\$\{[A-Za-z_][A-Za-z0-9_]*:\?[^}]*\}$|@\$\{[A-Za-z_][A-Za-z0-9_]*_DIGEST[A-Za-z0-9_]*[^}]*\}$`, image)
}

# ---------------------------------------------------------------------------
# 1. No `latest` image tags — pin versions (build images are exempt)
# ---------------------------------------------------------------------------
deny contains msg if {
	service := input.services[name]
	image := service.image
	not _is_build_image(image)
	endswith(image, ":latest")
	msg := sprintf("Service '%s' uses ':latest' tag on image '%s'. Pin to a specific version.", [name, image])
}

deny contains msg if {
	service := input.services[name]
	image := service.image
	not _is_build_image(image)
	not contains(image, ":")
	not image in runtime_pinned_images
	msg := sprintf("Service '%s' has no tag on image '%s'. Pin to a specific version.", [name, image])
}

# A tag can be repointed upstream; only a digest names the bytes that were reviewed.
deny contains msg if {
	service := input.services[name]
	image := service.image
	not _is_build_image(image)
	not endswith(image, "-local")
	not contains(image, "@sha256:")

	# Required whole-image references are digest-checked by the selfhost runtime guard.
	not image in runtime_pinned_images
	msg := sprintf("Service '%s' image '%s' is not pinned by digest. Add @sha256:<digest>.", [name, image])
}

_is_build_image(image) if {
	some b in build_images
	contains(image, b)
}

# ---------------------------------------------------------------------------
# 2. Memory limits required on all services
# ---------------------------------------------------------------------------
deny contains msg if {
	service := input.services[name]

	# Fragments inherit omitted fields; explicit overrides must still be checked.
	count({"image", "build", "mem_limit"} & object.keys(service)) > 0
	not _has_memory_limit(service)
	msg := sprintf("Service '%s' is missing a memory limit (mem_limit or deploy.resources.limits.memory).", [name])
}

_has_memory_limit(service) if {
	service.deploy.resources.limits.memory
}

_has_memory_limit(service) if {
	service.mem_limit
}

# ---------------------------------------------------------------------------
# 3. Health checks required on long-running services
# ---------------------------------------------------------------------------
deny contains msg if {
	service := input.services[name]
	count({"image", "build", "healthcheck", "x-no-healthcheck"} & object.keys(service)) > 0
	not name in one_shot_services
	not _has_healthcheck(service)
	msg := sprintf("Service '%s' is missing a healthcheck.", [name])
}

deny contains msg if {
	service := input.services[name]
	service.healthcheck.disable == true
	msg := sprintf("Service '%s' disables its healthcheck; docker compose up --wait requires a working probe.", [name])
}

_has_healthcheck(service) if {
	service.healthcheck
}

# ---------------------------------------------------------------------------
# 4. No host networking (except Fail2ban)
# ---------------------------------------------------------------------------
deny contains msg if {
	service := input.services[name]
	service.network_mode == "host"
	not name in host_network_allowed
	msg := sprintf("Service '%s' uses host networking. This is not allowed (exception: fail2ban).", [name])
}

# ---------------------------------------------------------------------------
# 5. Secret env vars must use ${VAR} substitution, not hardcoded values
# ---------------------------------------------------------------------------

# Handle environment as an object (key: value mapping)
deny contains msg if {
	service := input.services[name]
	env := service.environment[env_key]
	_is_secret_key(lower(env_key))
	is_string(env)
	env != ""
	not _is_accepted_secret_env_value(lower(env_key), env)
	msg := sprintf("Service '%s' has hardcoded secret in environment variable '%s'. Use ${VAR} substitution instead.", [name, env_key])
}

# Handle environment as an array of "KEY=VALUE" strings
deny contains msg if {
	service := input.services[name]
	env_entry := service.environment[_]
	is_string(env_entry)
	contains(env_entry, "=")
	parts := split(env_entry, "=")
	env_key := parts[0]
	_is_secret_key(lower(env_key))
	env_val := substring(env_entry, count(env_key) + 1, -1)
	env_val != ""
	not _is_accepted_secret_env_value(lower(env_key), env_val)
	msg := sprintf("Service '%s' has hardcoded secret in environment variable '%s'. Use ${VAR} substitution instead.", [name, env_key])
}

_is_secret_key(key) if {
	some pattern in secret_key_patterns
	contains(key, pattern)
}

_is_variable_substitution(val) if {
	regex.match(`\$\{[A-Za-z_][A-Za-z0-9_]*[^}]*\}`, val)
}

_is_accepted_secret_env_value(_key, val) if {
	_is_variable_substitution(val)
}

_is_accepted_secret_env_value(key, val) if {
	endswith(key, "_file")
	startswith(trim_space(val), "/run/secrets/")
}

# Grafana names its TLS private-key file setting without a _FILE suffix.
_is_accepted_secret_env_value(key, val) if {
	key == "gf_server_cert_key"
	startswith(val, "/etc/grafana/tls/")
}

_is_accepted_secret_env_value(key, val) if {
	endswith(key, "_files")
	paths := split(val, ",")
	count(paths) > 0
	every path in paths {
		startswith(trim_space(path), "/run/secrets/")
	}
}

_is_accepted_secret_env_value(key, _val) if {
	key in non_secret_selector_keys
}

_is_accepted_secret_env_value(key, val) if {
	key in disabled_secret_sentinel_keys
	lower(trim_space(val)) == "disabled"
}

# ---------------------------------------------------------------------------
# 6. Config volume mounts should be read-only (:ro)
# ---------------------------------------------------------------------------
deny contains msg if {
	service := input.services[name]
	vol := service.volumes[_]
	is_string(vol)
	_is_config_mount(vol)
	not _is_read_only(vol)
	msg := sprintf("Service '%s' has a config volume mount '%s' that is not read-only. Add ':ro' to the mount.", [name, vol])
}

_is_config_mount(vol) if {
	# Extract the container path (second colon-separated segment)
	parts := split(vol, ":")
	count(parts) >= 2
	container_path := parts[1]
	some ext in config_extensions
	endswith(container_path, ext)
}

_is_read_only(vol) if {
	contains(vol, ":ro")
}

# ---------------------------------------------------------------------------
# 7. no-new-privileges security option recommended
# ---------------------------------------------------------------------------
deny contains msg if {
	service := input.services[name]
	count({"image", "build", "security_opt"} & object.keys(service)) > 0
	not _has_no_new_privileges(service)
	msg := sprintf("Service '%s' is missing 'no-new-privileges:true' in security_opt. This is recommended to prevent privilege escalation.", [name])
}

_has_no_new_privileges(service) if {
	some opt in service.security_opt
	opt == "no-new-privileges:true"
}

# ---------------------------------------------------------------------------
# 8. PostgreSQL sslmode must not be weaker than verify-full
#
# The prod backend JDBC URL hardcodes sslmode=verify-full (see
# docker/rhizome-docker.yaml.template). POSTGRES_SSL_MODE is retained only for
# non-prod overrides; any compose service that sets it to a weaker mode would
# (re-)introduce a connection that does not verify the server cert + hostname.
# We block disable / allow / prefer / require / verify-ca.
#
# Compose typically sets this as ${POSTGRES_SSL_MODE:-<default>}. We extract the
# literal default after ":-" and evaluate that. When the value is a bare
# interpolation with no literal default (e.g. ${POSTGRES_SSL_MODE}) or is
# absent, there is no literal to judge, so this rule does not fire — the literal
# default in docker/.env.example (verify-full) governs that case, and a CI run
# would surface a too-weak literal default there. We only deny when a weak mode
# is observable as a literal in the compose file itself.
# ---------------------------------------------------------------------------

# Modes weaker than verify-full (everything except verify-full).
weak_sslmodes := {"disable", "allow", "prefer", "require", "verify-ca"}

# environment as an object (key: value mapping)
deny contains msg if {
	service := input.services[name]
	raw := service.environment.POSTGRES_SSL_MODE
	is_string(raw)
	mode := _sslmode_literal(raw)
	mode in weak_sslmodes
	msg := sprintf("Service '%s' sets POSTGRES_SSL_MODE='%s', weaker than required 'verify-full'. Use sslmode=verify-full (encrypts + verifies server cert AND hostname); the prod JDBC URL in rhizome-docker.yaml.template already hardcodes it.", [name, mode])
}

# environment as an array of "KEY=VALUE" strings
deny contains msg if {
	service := input.services[name]
	env_entry := service.environment[_]
	is_string(env_entry)
	startswith(env_entry, "POSTGRES_SSL_MODE=")
	raw := substring(env_entry, count("POSTGRES_SSL_MODE="), -1)
	mode := _sslmode_literal(raw)
	mode in weak_sslmodes
	msg := sprintf("Service '%s' sets POSTGRES_SSL_MODE='%s', weaker than required 'verify-full'. Use sslmode=verify-full (encrypts + verifies server cert AND hostname); the prod JDBC URL in rhizome-docker.yaml.template already hardcodes it.", [name, mode])
}

# Resolve the literal sslmode value from a compose env value.
# Handles three forms:
#   "require"                       -> "require"
#   "${POSTGRES_SSL_MODE:-require}" -> "require"  (literal default after ":-")
#   "${POSTGRES_SSL_MODE}"          -> "" (no literal — caller's set lookup misses)

# Bare literal (no ${...} interpolation at all). Lowercased because libpq treats sslmode
# case-insensitively, so "REQUIRE"/"Require" are the same weak mode as "require".
_sslmode_literal(raw) = lower(trim_space(raw)) if {
	not contains(raw, "${")
}

# ${VAR:-default} form — take the literal default after ":-" (also lowercased).
_sslmode_literal(raw) = lower(trim_space(fallback)) if {
	contains(raw, "${")
	contains(raw, ":-")
	after := substring(raw, indexof(raw, ":-") + 2, -1)
	fallback := substring(after, 0, indexof(after, "}"))
}

# Initializers need ownership repair. These runtime exceptions already document why
# they read host-owned files or drop privileges in their upstream entrypoint.
root_user_reasons := {
	"postgres": "Percona prepares volumes before dropping to postgres",
	"postgres-replica": "Percona prepares replica volumes before dropping to postgres",
	"db-backup": "Backup bind mounts use the configured host UID, which may be root",
	"cadvisor": "Reads root-owned cgroups and Docker storage",
	"operational-probe": "Reads the private database and monitoring credential mounts",
	# The monitoring overlay's fragment of the one-shot base service (restart "no" lives in
	# selfhost/docker-compose.yml, which conftest scans separately).
	"config-guard": "Writes configuration.prom into the root-owned monitoring_textfiles volume (guard-config.sh write_configuration_metric)",
	"docker-socket-proxy": "Opens the root-owned host Docker socket; read-only GET proxy on an internal network",
}

# Capabilities a service keeps after cap_drop ALL, each with the reason it cannot be removed.
# A cap_add entry passes only when it is listed here for that service (or is an ownership
# capability on an ownership initializer). Keyed by service name, then capability.
capability_reasons := {
	"web": {"NET_BIND_SERVICE": "Caddy binds 80/443 in the tls and local-https modes, and the release caddy binary carries file capability cap_net_bind_service, so a non-root exec fails with EPERM unless the capability stays in the bounding set"},
	"metrics-exporter": {"NET_BIND_SERVICE": "Same caddy binary as web: its cap_net_bind_service file capability makes exec fail with EPERM when the capability is outside the bounding set, although it binds only :9090"},
	"caddy-storage-init": {"DAC_READ_SEARCH": "After a rollback the old root Caddy leaves files inside 10001-owned 0700 directories; root needs traversal to chown them back"},
	"db-backup": {
		"CHOWN": "Bare-compose fallback runs as root (CHRONICLE_HOST_UID unset) and must write dumps into the operator-owned 0700 ./backups; inert for the operator uid",
		"DAC_OVERRIDE": "Bare-compose fallback runs as root (CHRONICLE_HOST_UID unset) and must write dumps into the operator-owned 0700 ./backups; inert for the operator uid",
		"FOWNER": "Bare-compose fallback runs as root (CHRONICLE_HOST_UID unset) and must rotate dumps inside the operator-owned 0700 ./backups; inert for the operator uid",
	},
	"operational-probe": {"DAC_READ_SEARCH": "Reads the operator-owned 0700 backup store and the backend-owned 0700 export store, which belong to different uids"},
}

capability_allowed(name, capability) if capability_reasons[name][capability]

complete_service(service) if {
	count({"image", "build"} & object.keys(service)) > 0
}

deny contains msg if {
	service := input.services[name]
	complete_service(service)
	object.get(service, "read_only", false) != true
	msg := sprintf("Service '%s' must have a read-only root filesystem.", [name])
}

deny contains msg if {
	service := input.services[name]
	complete_service(service)
	not "ALL" in object.get(service, "cap_drop", [])
	msg := sprintf("Service '%s' must drop ALL capabilities.", [name])
}

ownership_capabilities := {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"}

ownership_initializer(name) if name in one_shot_services

ownership_initializer(name) if name in {"postgres", "postgres-replica"}

deny contains msg if {
	service := input.services[name]
	capability := service.cap_add[_]
	not ownership_initializer(name)
	not capability_allowed(name, capability)
	msg := sprintf("Service '%s' retains capability '%s' outside an ownership initializer.", [name, capability])
}

deny contains msg if {
	service := input.services[name]
	capability := service.cap_add[_]
	ownership_initializer(name)
	not capability in ownership_capabilities
	not capability_allowed(name, capability)
	msg := sprintf("Service '%s' retains non-ownership capability '%s'.", [name, capability])
}

deny contains msg if {
	service := input.services[name]
	regex.match(`^(0|root)(:|$)`, object.get(service, "user", ""))
	not name in one_shot_services
	not root_user_reasons[name]
	msg := sprintf("Service '%s' explicitly runs as root without a documented initializer or user exception.", [name])
}

_has_pid_limit(service) if to_number(service.pids_limit) > 0

_has_pid_limit(service) if to_number(service.deploy.resources.limits.pids) > 0

deny contains msg if {
	service := input.services[name]
	complete_service(service)
	not _has_pid_limit(service)
	msg := sprintf("Service '%s' must have a positive PID limit.", [name])
}
