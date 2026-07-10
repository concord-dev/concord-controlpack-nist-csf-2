package concord.nist_csf_2.rs_an_08

import rego.v1

# NIST CSF 2.0 RS.AN-08 — an incident's magnitude is estimated and
# validated. Concord reads a cosigned attestation describing the
# estimation method, the validation process that confirms the estimate,
# and the impact categories the organization scores.

expected_kind := "incident_magnitude"

max_review_age_days := 365

required_fields := {
	"estimation_method",
	"validation_process",
	"impact_categories",
	"last_reviewed_at",
}

deny contains msg if {
	not input.attestation
	msg := "no incident-magnitude attestation collected"
}

deny contains msg if {
	input.attestation.kind != expected_kind
	msg := sprintf("attestation kind is %q, expected %q", [input.attestation.kind, expected_kind])
}

deny contains msg if {
	not input.attestation.signature_verified
	msg := "incident-magnitude attestation cosign signature did not verify"
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("incident-magnitude attestation missing required field: %s", [f])
}

deny contains msg if {
	count(input.attestation.attested_fields.impact_categories) == 0
	msg := "incident-magnitude attestation scores zero impact categories"
}

deny contains msg if {
	reviewed_ns := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
	time.now_ns() - reviewed_ns > (((max_review_age_days * 24) * 60) * 60) * 1000000000
	msg := sprintf("incident-magnitude method last reviewed %q — older than %d days", [input.attestation.attested_fields.last_reviewed_at, max_review_age_days])
}
