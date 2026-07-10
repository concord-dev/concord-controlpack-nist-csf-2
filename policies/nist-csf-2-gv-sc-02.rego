package concord.nist_csf_2.gv_sc_02

import rego.v1

# NIST CSF 2.0 GV.SC-02 — cybersecurity roles and responsibilities for
# suppliers are established and coordinated internally and externally.

expected_kind := "supplier_roles"

required_fields := {
    "supplier_responsibilities",
    "internal_owners",
    "escalation",
    "last_reviewed_at",
}

deny contains msg if {
    not input.attestation
    msg := "no supplier-roles attestation collected"
}

deny contains msg if {
    input.attestation.kind != expected_kind
    msg := sprintf("attestation kind is %q, expected %q", [input.attestation.kind, expected_kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("supplier-roles attestation missing required field: %s", [f])
}

deny contains msg if {
    count(input.attestation.attested_fields.supplier_responsibilities) == 0
    msg := "supplier-roles attestation defines zero supplier responsibilities"
}

deny contains msg if {
    count(input.attestation.attested_fields.internal_owners) == 0
    msg := "supplier-roles attestation assigns no internal owners"
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "supplier-roles attestation cosign signature did not verify"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    time.now_ns() - reviewed > ((365 * 24) * 60 * 60) * 1000000000
    msg := "supplier roles and responsibilities have not been reviewed in the last 365 days"
}
