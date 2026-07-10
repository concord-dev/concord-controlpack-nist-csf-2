package concord.nist_csf_2.gv_sc_01

import rego.v1

# NIST CSF 2.0 GV.SC-01 — a cybersecurity supply chain risk management
# (C-SCRM) program is established and agreed by stakeholders.

expected_kind := "scrm_program"

required_fields := {
    "program_scope",
    "roles",
    "governance",
    "last_reviewed_at",
}

deny contains msg if {
    not input.attestation
    msg := "no C-SCRM program attestation collected"
}

deny contains msg if {
    input.attestation.kind != expected_kind
    msg := sprintf("attestation kind is %q, expected %q", [input.attestation.kind, expected_kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("C-SCRM program attestation missing required field: %s", [f])
}

deny contains msg if {
    count(input.attestation.attested_fields.roles) == 0
    msg := "C-SCRM program has no accountable roles assigned"
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "C-SCRM program attestation cosign signature did not verify"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    time.now_ns() - reviewed > ((365 * 24) * 60 * 60) * 1000000000
    msg := "C-SCRM program has not been reviewed in the last 365 days"
}
