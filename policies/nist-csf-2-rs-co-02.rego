package concord.nist_csf_2.rs_co_02

import rego.v1

# NIST CSF 2.0 RS.CO-02 — internal and external stakeholders are notified
# of incidents. Concord reads a cosigned attestation describing the
# notification matrix, the notification timeframes, and the roster of
# internal and external contacts.

expected_kind := "incident_notification"

max_review_age_days := 365

required_fields := {
	"notification_matrix",
	"timeframes",
	"internal_external_contacts",
	"last_reviewed_at",
}

deny contains msg if {
	not input.attestation
	msg := "no incident-notification attestation collected"
}

deny contains msg if {
	input.attestation.kind != expected_kind
	msg := sprintf("attestation kind is %q, expected %q", [input.attestation.kind, expected_kind])
}

deny contains msg if {
	not input.attestation.signature_verified
	msg := "incident-notification attestation cosign signature did not verify"
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("incident-notification attestation missing required field: %s", [f])
}

deny contains msg if {
	count(input.attestation.attested_fields.internal_external_contacts) == 0
	msg := "incident-notification attestation lists zero internal or external contacts"
}

deny contains msg if {
	reviewed_ns := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
	time.now_ns() - reviewed_ns > (((max_review_age_days * 24) * 60) * 60) * 1000000000
	msg := sprintf("incident-notification matrix last reviewed %q — older than %d days", [input.attestation.attested_fields.last_reviewed_at, max_review_age_days])
}
