package concord.nist_csf_2.gv_sc_06

import rego.v1

# NIST CSF 2.0 GV.SC-06 — planning and due diligence are performed to
# reduce supply-chain risk before entering supplier relationships.

expected_kind := "procurement_planning"

required_fields := {
    "due_diligence_process",
    "risk_assessment_pre_procurement",
    "approval_gate",
    "last_reviewed_at",
}

deny contains msg if {
    not input.attestation
    msg := "no procurement-planning attestation collected"
}

deny contains msg if {
    input.attestation.kind != expected_kind
    msg := sprintf("attestation kind is %q, expected %q", [input.attestation.kind, expected_kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("procurement-planning attestation missing required field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "procurement-planning attestation cosign signature did not verify"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    time.now_ns() - reviewed > ((365 * 24) * 60 * 60) * 1000000000
    msg := "procurement-planning process has not been reviewed in the last 365 days"
}
