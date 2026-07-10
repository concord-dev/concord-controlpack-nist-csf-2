package concord.nist_csf_2.gv_rm_03

import rego.v1

# NIST CSF 2.0 GV.RM-03 — cybersecurity risk management activities and
# outcomes are included in enterprise risk management processes.

required_fields := {"integration_process", "erm_reporting",
                    "escalation_path", "last_reviewed_at"}

max_review_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no erm-integration attestation collected"
}

deny contains msg if {
    input.attestation.kind != "erm_integration"
    msg := sprintf("attestation kind is %q, expected \"erm_integration\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("erm-integration attestation missing field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "erm-integration attestation cosign signature did not verify"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    age_ns := time.now_ns() - reviewed
    age_ns > max_review_age_days * 24 * 60 * 60 * 1000000000
    msg := sprintf("ERM integration not reviewed within %d days", [max_review_age_days])
}
