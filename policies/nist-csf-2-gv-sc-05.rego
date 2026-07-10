package concord.nist_csf_2.gv_sc_05

import rego.v1

# NIST CSF 2.0 GV.SC-05 — requirements to address supply-chain
# cybersecurity risk are established and integrated into agreements.

expected_kind := "supply_chain_requirements"

required_fields := {
    "contractual_requirements",
    "security_clauses",
    "verification_method",
    "last_reviewed_at",
}

deny contains msg if {
    not input.attestation
    msg := "no supply-chain-requirements attestation collected"
}

deny contains msg if {
    input.attestation.kind != expected_kind
    msg := sprintf("attestation kind is %q, expected %q", [input.attestation.kind, expected_kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("supply-chain-requirements attestation missing required field: %s", [f])
}

deny contains msg if {
    count(input.attestation.attested_fields.contractual_requirements) == 0
    msg := "supply-chain-requirements attestation defines zero contractual requirements"
}

deny contains msg if {
    count(input.attestation.attested_fields.security_clauses) == 0
    msg := "supply-chain-requirements attestation defines zero security clauses"
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "supply-chain-requirements attestation cosign signature did not verify"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    time.now_ns() - reviewed > ((365 * 24) * 60 * 60) * 1000000000
    msg := "supply-chain requirements have not been reviewed in the last 365 days"
}
