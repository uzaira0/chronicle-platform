package main

import rego.v1

base_service := {
	"image": "example.invalid/service:v1.0.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	"mem_limit": "128m",
	"read_only": true,
	"cap_drop": ["ALL"],
	"pids_limit": 64,
	"user": "10001:0",
	"healthcheck": {"test": ["CMD", "true"]},
	"security_opt": ["no-new-privileges:true"],
	"environment": {},
	"volumes": [],
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
	count(findings) == 6
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
