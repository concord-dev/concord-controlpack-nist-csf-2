package concord.nist_csf_2.rs_an_07

import rego.v1

# NIST CSF 2.0 RS.AN-07 — incident data and metadata are collected, and
# their integrity and provenance are preserved. Concord reads a cosigned
# attestation describing the collection process, the integrity controls
# applied to collected data, and the retention period.

expected_kind := "incident_data_integrity"

max_review_age_days := 365

required_fields := {
	"collection_process",
	"integrity_controls",
	"retention_period",
	"last_reviewed_at",
}

deny contains msg if {
	not input.attestation
	msg := "no incident-data-integrity attestation collected"
}

deny contains msg if {
	input.attestation.kind != expected_kind
	msg := sprintf("attestation kind is %q, expected %q", [input.attestation.kind, expected_kind])
}

deny contains msg if {
	not input.attestation.signature_verified
	msg := "incident-data-integrity attestation cosign signature did not verify"
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("incident-data-integrity attestation missing required field: %s", [f])
}

deny contains msg if {
	count(input.attestation.attested_fields.integrity_controls) == 0
	msg := "incident-data-integrity attestation lists zero integrity controls protecting collected data"
}

deny contains msg if {
	reviewed_ns := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
	time.now_ns() - reviewed_ns > (((max_review_age_days * 24) * 60) * 60) * 1000000000
	msg := sprintf("incident-data-integrity process last reviewed %q — older than %d days", [input.attestation.attested_fields.last_reviewed_at, max_review_age_days])
}
