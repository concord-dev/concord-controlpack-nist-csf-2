package concord.nist_csf_2.gv_po_02

import rego.v1

# NIST CSF 2.0 GV.PO-02 — policy for managing cybersecurity risks is
# reviewed, updated, communicated, and enforced to reflect changes in
# requirements, threats, technology, and organizational mission.

required_fields := {"review_cycle", "communication_method",
                    "exception_process", "last_reviewed_at"}

max_review_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no cyber-policy-management attestation collected"
}

deny contains msg if {
    input.attestation.kind != "cyber_policy_management"
    msg := sprintf("attestation kind is %q, expected \"cyber_policy_management\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("cyber-policy-management attestation missing field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "cyber-policy-management attestation cosign signature did not verify"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    age_ns := time.now_ns() - reviewed
    age_ns > max_review_age_days * 24 * 60 * 60 * 1000000000
    msg := sprintf("cybersecurity policy not reviewed within %d days", [max_review_age_days])
}
