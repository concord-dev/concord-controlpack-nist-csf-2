package concord.nist_csf_2.gv_sc_03

import rego.v1

# NIST CSF 2.0 GV.SC-03 — C-SCRM is integrated into cybersecurity and
# enterprise risk management, with lifecycle monitoring.

expected_kind := "scrm_integration"

required_fields := {
    "integration_process",
    "risk_criteria",
    "monitoring",
    "last_reviewed_at",
}

deny contains msg if {
    not input.attestation
    msg := "no C-SCRM integration attestation collected"
}

deny contains msg if {
    input.attestation.kind != expected_kind
    msg := sprintf("attestation kind is %q, expected %q", [input.attestation.kind, expected_kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("C-SCRM integration attestation missing required field: %s", [f])
}

deny contains msg if {
    count(input.attestation.attested_fields.risk_criteria) == 0
    msg := "C-SCRM integration attestation defines zero supplier risk criteria"
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "C-SCRM integration attestation cosign signature did not verify"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    time.now_ns() - reviewed > ((365 * 24) * 60 * 60) * 1000000000
    msg := "C-SCRM integration has not been reviewed in the last 365 days"
}
