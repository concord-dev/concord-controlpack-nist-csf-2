package concord.nist_csf_2.rs_an_03

import rego.v1

# NIST CSF 2.0 RS.AN-03 — analysis is performed to establish what has
# taken place during an incident and the root cause of the incident.
# Concord reads a cosigned attestation describing the incident-analysis
# capability (methodology, forensic readiness, documentation standard).

expected_kind := "incident_analysis"

max_review_age_days := 365

required_fields := {
	"analysis_methodology",
	"forensic_capability",
	"documentation_standard",
	"last_reviewed_at",
}

deny contains msg if {
	not input.attestation
	msg := "no incident-analysis attestation collected"
}

deny contains msg if {
	input.attestation.kind != expected_kind
	msg := sprintf("attestation kind is %q, expected %q", [input.attestation.kind, expected_kind])
}

deny contains msg if {
	not input.attestation.signature_verified
	msg := "incident-analysis attestation cosign signature did not verify"
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("incident-analysis attestation missing required field: %s", [f])
}

deny contains msg if {
	count(input.attestation.attested_fields.analysis_methodology) == 0
	msg := "incident-analysis attestation defines zero analysis methodologies"
}

deny contains msg if {
	reviewed_ns := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
	time.now_ns() - reviewed_ns > (((max_review_age_days * 24) * 60) * 60) * 1000000000
	msg := sprintf("incident-analysis capability last reviewed %q — older than %d days", [input.attestation.attested_fields.last_reviewed_at, max_review_age_days])
}
