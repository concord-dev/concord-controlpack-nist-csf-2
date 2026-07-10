package concord.nist_csf_2.rs_co_03

import rego.v1

# NIST CSF 2.0 RS.CO-03 — information is shared with designated internal
# and external stakeholders during an incident. Concord reads a cosigned
# attestation describing the information-sharing protocols, the designated
# recipients, and the approval process gating what is shared.

expected_kind := "incident_information_sharing"

max_review_age_days := 365

required_fields := {
	"sharing_protocols",
	"designated_recipients",
	"approval_process",
	"last_reviewed_at",
}

deny contains msg if {
	not input.attestation
	msg := "no incident-information-sharing attestation collected"
}

deny contains msg if {
	input.attestation.kind != expected_kind
	msg := sprintf("attestation kind is %q, expected %q", [input.attestation.kind, expected_kind])
}

deny contains msg if {
	not input.attestation.signature_verified
	msg := "incident-information-sharing attestation cosign signature did not verify"
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("incident-information-sharing attestation missing required field: %s", [f])
}

deny contains msg if {
	count(input.attestation.attested_fields.designated_recipients) == 0
	msg := "incident-information-sharing attestation names zero designated recipients"
}

deny contains msg if {
	reviewed_ns := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
	time.now_ns() - reviewed_ns > (((max_review_age_days * 24) * 60) * 60) * 1000000000
	msg := sprintf("incident-information-sharing protocol last reviewed %q — older than %d days", [input.attestation.attested_fields.last_reviewed_at, max_review_age_days])
}
