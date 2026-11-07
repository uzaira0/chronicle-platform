package main

import rego.v1

base_service := {
	"image": "example.invalid/service:v1.0.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	"mem_limit": "128m",
	"read_only": true,
	"cap_drop": ["ALL"],
	"pids_limit": 64,
	"cpu_period": 100000,
	"cpu_quota": 100000,
	"user": "10001:0",
	"healthcheck": {"test": ["CMD", "true"]},
	"security_opt": ["no-new-privileges:true"],
	"environment": {},
	"volumes": [],
	"network_mode": "none",
}

test_mutable_tag_is_denied if {
	service := object.union(base_service, {"image": "example.invalid/service:v1.0.0"})
	findings := deny with input as {"services": {"app": service}}
	count(findings) == 1
}

test_local_build_image_is_accepted if {
	service := object.union(base_service, {"image": "chronicle-backend:local"})
	findings := deny with input as {"services": {"app": service}}
	count(findings) == 0
}

test_required_image_interpolation_is_accepted if {
	service := object.union(base_service, {"image": "${BACKEND_IMAGE:?set a digest-pinned image}"})
	findings := deny with input as {"services": {"app": service}}
	count(findings) == 0
}

test_digest_interpolation_is_accepted if {
	every image in ["example.invalid/service:v1@${SERVICE_DIGEST}", "example.invalid/service@${SERVICE_IMAGE_DIGEST:?set digest}"] {
		service := object.union(base_service, {"image": image})
		findings := deny with input as {"services": {"app": service}}
		count(findings) == 0
	}
}

test_optional_or_embedded_image_interpolation_is_denied if {
	every image in ["${BACKEND_IMAGE:-example.invalid/service:v1}", "example.invalid/${IMAGE:?set image}:v1", "example.invalid/service:v1@${SERVICE_TAG}", "example.invalid/service:v1@${SERVICE_DIGEST}:v1"] {
		service := object.union(base_service, {"image": image})
		findings := deny with input as {"services": {"app": service}}
		count(findings) > 0
	}
}

test_restart_no_needs_no_healthcheck if {
	service := object.union(object.remove(base_service, {"healthcheck"}), {"restart": "no"})
	findings := deny with input as {"services": {"init": service}}
	count(findings) == 0
}

test_completed_dependency_needs_no_healthcheck if {
	init := object.remove(base_service, {"healthcheck"})
	app := object.union(base_service, {"depends_on": {"init": {"condition": "service_completed_successfully"}}})
	findings := deny with input as {"services": {"init": init, "app": app}}
	count(findings) == 0
}

test_long_running_service_needs_healthcheck if {
	service := object.union(object.remove(base_service, {"healthcheck"}), {"restart": "unless-stopped"})
	findings := deny with input as {"services": {"app": service}}
	count(findings) == 1
	"Service 'app' is missing a healthcheck." in findings
}

test_no_healthcheck_reason_is_not_a_probe if {
	service := object.union(object.remove(base_service, {"healthcheck"}), {"x-no-healthcheck": "Distroless image has no probe tool."})
	findings := deny with input as {"services": {"app": service}}
	"Service 'app' is missing a healthcheck." in findings
}

test_no_healthcheck_invalid_reason_is_denied if {
	every reason in ["", " \t\n", true, null, 1] {
		service := object.union(object.remove(base_service, {"healthcheck"}), {"x-no-healthcheck": reason})
		findings := deny with input as {"services": {"app": service}}
		count(findings) == 1
		"Service 'app' is missing a healthcheck." in findings
	}
}

test_disabled_healthcheck_is_denied if {
	service := object.union(base_service, {"healthcheck": {"disable": true}})
	findings := deny with input as {"services": {"app": service}}
	count(findings) == 1
	some msg in findings
	contains(msg, "docker compose up --wait")
	contains(msg, "working probe")
}

test_started_dependency_still_needs_healthcheck if {
	dependency := object.remove(base_service, {"healthcheck"})
	app := object.union(base_service, {"depends_on": {"dependency": {"condition": "service_started"}}})
	findings := deny with input as {"services": {"dependency": dependency, "app": app}}
	count(findings) == 1
	"Service 'dependency' is missing a healthcheck." in findings
}

test_one_shot_still_needs_memory_and_security if {
	service := object.union(object.remove(base_service, {"healthcheck", "mem_limit", "security_opt"}), {"restart": "no"})
	findings := deny with input as {"services": {"init": service}}
	count(findings) == 2
}

test_overlay_fragment_inherits_required_fields if {
	findings := deny with input as {"services": {"app": {"environment": {"MODE": "local"}}}}
	count(findings) == 0
}

test_built_service_still_needs_required_fields if {
	service := {"build": {"context": "."}}
	findings := deny with input as {"services": {"app": service}}

	# Six hardening fields, the CPU ceiling, the implicit default network it would join, and no
	# blackhole resolver.
	count(findings) == 9
}

test_overlay_fragment_secrets_still_checked if {
	findings := deny with input as {"services": {"app": {"environment": {"POSTGRES_PASSWORD": "plaintext"}}}}
	count(findings) == 1
}

test_overlay_cannot_remove_security_options if {
	findings := deny with input as {"services": {"app": {"security_opt": []}}}
	count(findings) == 1
}

test_grafana_tls_key_path_is_accepted if {
	service := object.union(base_service, {"environment": {"GF_SERVER_CERT_KEY": "/etc/grafana/tls/monitoring.key"}})
	findings := deny with input as {"services": {"app": service}}
	count(findings) == 0
}

test_grafana_literal_tls_key_is_denied if {
	service := object.union(base_service, {"environment": {"GF_SERVER_CERT_KEY": "plaintext-key"}})
	findings := deny with input as {"services": {"app": service}}
	count(findings) == 1
}

test_native_compose_memory_limit_is_accepted if {
	findings := deny with input as {"services": {"app": base_service}}
	count(findings) == 0
}

test_missing_memory_limit_is_denied if {
	service := object.remove(base_service, {"mem_limit"})
	findings := deny with input as {"services": {"app": service}}
	count(findings) == 1
	"Service 'app' is missing a memory limit (mem_limit or deploy.resources.limits.memory)." in findings
}

test_secret_file_reference_is_accepted if {
	service := object.union(base_service, {"environment": {"POSTGRES_PASSWORD_FILE": "/run/secrets/postgres_password"}})
	findings := deny with input as {"services": {"app": service}}
	count(findings) == 0
}

test_secret_file_list_reference_is_accepted if {
	service := object.union(base_service, {"environment": {"CHRONICLE_SECURITY_METRICS_PASSWORD_FILES": "/run/secrets/metrics/current,/run/secrets/metrics/previous"}})
	findings := deny with input as {"services": {"app": service}}
	count(findings) == 0
}

test_secret_file_list_outside_secret_mount_is_denied if {
	service := object.union(base_service, {"environment": {"CHRONICLE_SECURITY_METRICS_PASSWORD_FILES": "/run/secrets/metrics/current,/tmp/metrics-next"}})
	findings := deny with input as {"services": {"app": service}}
	count(findings) == 1
}

test_non_secret_selector_is_accepted if {
	service := object.union(base_service, {"environment": {"PG_TDE_KEY_PROVIDER": "file"}})
	findings := deny with input as {"services": {"app": service}}
	count(findings) == 0
}

test_exact_disabled_sentinel_is_accepted if {
	service := object.union(base_service, {"environment": {"OIDC_CLIENT_SECRET": "disabled"}})
	findings := deny with input as {"services": {"app": service}}
	count(findings) == 0
}

test_plaintext_secret_is_denied if {
	service := object.union(base_service, {"environment": {"DATABASE_PASSWORD": "not-a-reference"}})
	findings := deny with input as {"services": {"app": service}}
	count(findings) == 1
	"Service 'app' has hardcoded secret in environment variable 'DATABASE_PASSWORD'. Use ${VAR} substitution instead." in findings
}

test_secret_file_outside_secret_mount_is_denied if {
	service := object.union(base_service, {"environment": {"POSTGRES_PASSWORD_FILE": "/tmp/postgres_password"}})
	findings := deny with input as {"services": {"app": service}}
	count(findings) == 1
}

test_non_exact_disabled_value_is_denied if {
	service := object.union(base_service, {"environment": {"OIDC_CLIENT_SECRET": "disabled-but-not-a-sentinel"}})
	findings := deny with input as {"services": {"app": service}}
	count(findings) == 1
}

test_runtime_hardening_controls_are_required if {
	every patch in [{"read_only": false}, {"cap_drop": []}, {"cap_add": ["SYS_ADMIN"]}, {"user": "0:0"}, {"pids_limit": 0}] {
		service := object.union(base_service, patch)
		findings := deny with input as {"services": {"app": service}}
		count(findings) > 0
	}
}

test_initializer_can_use_root_and_ownership_capabilities if {
	service := object.union(base_service, {"restart": "no", "user": "0:0", "cap_add": ["CHOWN", "FOWNER", "DAC_OVERRIDE"]})
	findings := deny with input as {"services": {"volume-init": service}}
	count(findings) == 0
}

test_listed_capability_passes_for_its_service if {
	service := object.union(base_service, {"cap_add": ["NET_BIND_SERVICE"]})
	findings := deny with input as {"services": {"web": service}}
	count(findings) == 0
}

test_unlisted_capability_on_listed_service_is_denied if {
	service := object.union(base_service, {"cap_add": ["NET_BIND_SERVICE", "NET_RAW"]})
	findings := deny with input as {"services": {"web": service}}
	findings == {"Service 'web' retains capability 'NET_RAW' outside an ownership initializer."}
}

test_listed_capability_does_not_transfer_to_another_service if {
	service := object.union(base_service, {"cap_add": ["NET_BIND_SERVICE"]})
	findings := deny with input as {"services": {"app": service}}
	findings == {"Service 'app' retains capability 'NET_BIND_SERVICE' outside an ownership initializer."}
}

test_initializer_non_ownership_capability_needs_a_reason if {
	service := object.union(base_service, {"restart": "no", "user": "0:0", "cap_add": ["CHOWN", "DAC_READ_SEARCH"]})
	listed := deny with input as {"services": {"caddy-storage-init": service}}
	count(listed) == 0
	unlisted := deny with input as {"services": {"volume-init": service}}
	unlisted == {"Service 'volume-init' retains non-ownership capability 'DAC_READ_SEARCH'."}
}

test_every_capability_reason_is_written if {
	every _, capabilities in capability_reasons {
		every capability, reason in capabilities {
			is_string(reason)
			count(trim_space(reason)) > 20
			capability == upper(capability)
		}
	}
}

# --- 9. published ports bind loopback --------------------------------------

test_port_bound_to_a_loopback_default_variable_is_accepted if {
	every port in ["${GRAFANA_BIND:-127.0.0.1}:${GRAFANA_PORT:-3000}:3000", "127.0.0.1:${FLUENT_BIT_FORWARD_PORT:-24224}:24224", {"target": 8080, "published": "${HTTP_PORT:-8080}", "host_ip": "${HTTP_BIND:-127.0.0.1}"}] {
		service := object.union(base_service, {"ports": [port]})
		findings := deny with input as {"services": {"app": service}}
		count(findings) == 0
	}
}

test_port_on_every_interface_is_denied if {
	every port in ["${GRAFANA_PORT:-3000}:3000", "0.0.0.0:3000:3000", "${GRAFANA_BIND:-0.0.0.0}:3000:3000", "${GRAFANA_BIND}:3000:3000", {"target": 8081, "published": "8081"}, {"target": 8081, "published": "8081", "host_ip": "${INTERNAL_BIND:-0.0.0.0}"}] {
		service := object.union(base_service, {"ports": [port]})
		findings := deny with input as {"services": {"app": service}}
		count(findings) == 1
	}
}

test_web_public_listeners_are_the_only_exemption if {
	forward := object.union(base_service, {"ports": ["${HTTPS_PORT:-443}:8443", "${TLS_HTTP_PORT:-80}:8880"]})
	count(deny) == 0 with input as {"services": {"web-forward": forward}}
	other := object.union(base_service, {"ports": ["${HTTPS_PORT:-443}:8443"]})
	count(deny) == 1 with input as {"services": {"app": other}}
	forward_8081 := object.union(base_service, {"ports": ["8081:8081"]})
	count(deny) == 1 with input as {"services": {"web-forward": forward_8081}}
	# web holds no published port any more; a public bind on it is not exempt.
	web := object.union(base_service, {"ports": ["${HTTPS_PORT:-443}:443"]})
	count(deny) == 1 with input as {"services": {"web": web}}
}

# --- 10. only edge services reach beyond the host ---------------------------

test_service_on_an_internal_network_is_accepted if {
	service := object.union(object.remove(base_service, {"network_mode"}), {"networks": ["core"], "dns": [blackhole_resolver]})
	findings := deny with input as {"services": {"backend": service}, "networks": {"core": {"internal": true}}}
	count(findings) == 0
}

test_non_edge_service_on_an_outbound_network_is_denied if {
	every networks in [["core", "egress"], {"default": {}}, ["monitoring-ports"]] {
		service := object.union(object.remove(base_service, {"network_mode"}), {"networks": networks, "dns": [blackhole_resolver]})
		findings := deny with input as {"services": {"backend": service}}
		count(findings) == 1
	}
}

test_service_with_no_network_is_on_the_default_network if {
	service := object.union(object.remove(base_service, {"network_mode"}), {"dns": [blackhole_resolver]})
	count(deny) == 1 with input as {"services": {"backend": service}}
	count(deny) == 0 with input as {"services": {"web-forward": service}}
}

test_edge_service_may_join_an_outbound_network if {
	service := object.union(object.remove(base_service, {"network_mode"}), {"networks": ["egress-clients", "egress"]})
	count(deny) == 0 with input as {"services": {"egress-proxy": service}}
	count(deny) == 1 with input as {"services": {"public-probe": object.union(service, {"dns": [blackhole_resolver]})}}
}

test_non_edge_service_with_a_network_must_name_the_blackhole_resolver if {
	internal := object.union(object.remove(base_service, {"network_mode"}), {"networks": ["core"]})
	every dns in [null, [], ["1.1.1.1"], [blackhole_resolver, "1.1.1.1"]] {
		service := object.union(internal, {"dns": dns})
		findings := deny with input as {"services": {"backend": service}, "networks": {"core": {"internal": true}}}
		count(findings) == 1
	}
	count(deny) == 0 with input as {"services": {"backend": base_service}}
	count(deny) == 0 with input as {"services": {"egress-proxy": internal}, "networks": {"core": {"internal": true}}}
}

test_data_network_that_is_not_internal_is_denied if {
	every network in [{}, {"internal": false}, null] {
		findings := deny with input as {"services": {}, "networks": {"core": network}}
		count(findings) == 1
	}
	count(deny) == 0 with input as {"services": {}, "networks": {"monitoring": {"internal": true}, "egress": {}}}
}

# --- 11. seccomp stays on ----------------------------------------------------

test_unconfined_seccomp_is_denied if {
	every opt in ["seccomp:unconfined", "seccomp=unconfined", "SECCOMP=Unconfined"] {
		service := object.union(base_service, {"security_opt": ["no-new-privileges:true", opt]})
		findings := deny with input as {"services": {"app": service}}
		count(findings) == 1
	}
	profile := object.union(base_service, {"security_opt": ["no-new-privileges:true", "seccomp=./profile.json"]})
	count(deny) == 0 with input as {"services": {"app": profile}}
}

# --- 12. no literal secret behind a substitution ----------------------------

test_secret_with_a_literal_default_is_denied if {
	every value in ["${POSTGRES_PASSWORD:-hunter2hunter2}", "${JWT_SECRET-changeme}"] {
		service := object.union(base_service, {"environment": {"POSTGRES_PASSWORD": value}})
		findings := deny with input as {"services": {"secrets-init": service}}
		count(findings) == 1
	}
}

test_secret_with_an_empty_numeric_or_required_default_is_accepted if {
	every value in ["${POSTGRES_PASSWORD:-}", "${POSTGRES_PASSWORD:?set it}", "${DASHBOARD_SESSION_MINUTES:-480}", "${PASSWORD_LOGIN:-false}"] {
		service := object.union(base_service, {"environment": {"POSTGRES_PASSWORD": value}})
		findings := deny with input as {"services": {"secrets-init": service}}
		count(findings) == 0
	}
}

test_secret_file_directory_under_run_secrets_is_accepted if {
	service := object.union(base_service, {"environment": {"CHRONICLE_SECRETS_DIR": "/run/secrets/chronicle"}})
	count(deny) == 0 with input as {"services": {"backend": service}}
	elsewhere := object.union(base_service, {"environment": {"CHRONICLE_SECRETS_DIR": "/srv/secrets"}})
	count(deny) == 1 with input as {"services": {"backend": elsewhere}}
}

# --- 13. credentials only in the secret writers' environment ------------------

test_credential_substitution_outside_the_secret_writers_is_denied if {
	every value in ["${CHRONICLE_INTERNAL_WEB_SECRET:?set it}", "${POSTGRES_PASSWORD}", "prefix-${METRICS_PASSWORD:-}"] {
		service := object.union(base_service, {"environment": {"ANY_NAME": value}})
		count(deny) == 1 with input as {"services": {"web": service}}
		count(deny) == 0 with input as {"services": {"secrets-init": service}}
	}
}

test_settings_that_only_look_like_credentials_are_accepted if {
	every value in ["${JWT_SECRET_PREVIOUS_EXPIRES_AT:-0}", "${DASHBOARD_PASSWORD_HASH:-}", "${PG_TDE_KEY_PROVIDER:-file}"] {
		service := object.union(base_service, {"environment": {"SETTING": value}})
		count(deny) == 0 with input as {"services": {"backend": service}}
	}
}

# --- 14. CPU ceilings as CFS quotas -----------------------------------------

test_a_service_without_a_cpu_quota_is_denied if {
	service := object.remove(base_service, ["cpu_quota"])
	count(deny) == 1 with input as {"services": {"app": service}}
}

test_cpus_is_denied_because_docker_refuses_it_on_smaller_hosts if {
	service := object.union(base_service, {"cpus": "4"})
	count(deny) == 1 with input as {"services": {"app": service}}
}
