package concord.nist_csf_2.gv_rm_02

import rego.v1

# NIST CSF 2.0 GV.RM-02 — risk appetite and risk tolerance statements
# are established, communicated, and maintained.

required_fields := {"risk_appetite_statement", "risk_tolerance_levels",
                    "approving_authority", "last_reviewed_at"}

max_review_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no risk-appetite attestation collected"
}

deny contains msg if {
    input.attestation.kind != "risk_appetite"
    msg := sprintf("attestation kind is %q, expected \"risk_appetite\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("risk-appetite attestation missing field: %s", [f])
}

deny contains msg if {
    count(input.attestation.attested_fields.risk_tolerance_levels) == 0
    msg := "no quantified risk tolerance levels defined"
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "risk-appetite attestation cosign signature did not verify"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    age_ns := time.now_ns() - reviewed
    age_ns > max_review_age_days * 24 * 60 * 60 * 1000000000
    msg := sprintf("risk appetite/tolerance not reviewed within %d days", [max_review_age_days])
}
