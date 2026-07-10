package concord.nist_csf_2.gv_oc_02

import rego.v1

# NIST CSF 2.0 GV.OC-02 — internal and external stakeholders are
# understood, and their needs and expectations regarding cybersecurity
# risk management are understood and prioritized.

required_fields := {"internal_stakeholders", "external_stakeholders",
                    "prioritization_basis", "last_reviewed_at"}

max_review_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no organizational-context attestation collected"
}

deny contains msg if {
    input.attestation.kind != "organizational_context"
    msg := sprintf("attestation kind is %q, expected \"organizational_context\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("organizational-context attestation missing field: %s", [f])
}

deny contains msg if {
    count(input.attestation.attested_fields.internal_stakeholders) == 0
    msg := "no internal stakeholders identified"
}

deny contains msg if {
    count(input.attestation.attested_fields.external_stakeholders) == 0
    msg := "no external stakeholders identified"
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "organizational-context attestation cosign signature did not verify"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    age_ns := time.now_ns() - reviewed
    age_ns > max_review_age_days * 24 * 60 * 60 * 1000000000
    msg := sprintf("stakeholder context not reviewed within %d days", [max_review_age_days])
}
