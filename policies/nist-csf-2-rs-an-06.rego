package concord.nist_csf_2.rs_an_06

import rego.v1

# NIST CSF 2.0 RS.AN-06 — the actions performed during an investigation
# are recorded, and the records' integrity and provenance are preserved.
# Concord reads a cosigned attestation describing action logging, chain of
# custody, and the tooling that enforces both.

expected_kind := "investigation_recordkeeping"

max_review_age_days := 365

required_fields := {
	"action_logging",
	"chain_of_custody",
	"tooling",
	"last_reviewed_at",
}

deny contains msg if {
	not input.attestation
	msg := "no investigation-recordkeeping attestation collected"
}

deny contains msg if {
	input.attestation.kind != expected_kind
	msg := sprintf("attestation kind is %q, expected %q", [input.attestation.kind, expected_kind])
}

deny contains msg if {
	not input.attestation.signature_verified
	msg := "investigation-recordkeeping attestation cosign signature did not verify"
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("investigation-recordkeeping attestation missing required field: %s", [f])
}

deny contains msg if {
	count(input.attestation.attested_fields.tooling) == 0
	msg := "investigation-recordkeeping attestation lists zero tools enforcing action logging"
}

deny contains msg if {
	reviewed_ns := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
	time.now_ns() - reviewed_ns > (((max_review_age_days * 24) * 60) * 60) * 1000000000
	msg := sprintf("investigation-recordkeeping practice last reviewed %q — older than %d days", [input.attestation.attested_fields.last_reviewed_at, max_review_age_days])
}
