package concord.nist_csf_2.gv_rr_01

import rego.v1

# NIST CSF 2.0 GV.RR-01 — organizational leadership is responsible and
# accountable for cybersecurity risk.

expected_kind := "leadership_accountability"

required_fields := {
    "accountable_executive",
    "board_oversight",
    "reporting_cadence",
    "last_reviewed_at",
}

deny contains msg if {
    not input.attestation
    msg := "no leadership-accountability attestation collected"
}

deny contains msg if {
    input.attestation.kind != expected_kind
    msg := sprintf("attestation kind is %q, expected %q", [input.attestation.kind, expected_kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("leadership-accountability attestation missing required field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "leadership-accountability attestation cosign signature did not verify"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    time.now_ns() - reviewed > ((365 * 24) * 60 * 60) * 1000000000
    msg := "leadership review of cybersecurity risk is older than 365 days"
}
