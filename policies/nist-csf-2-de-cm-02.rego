package concord.nist_csf_2.de_cm_02

import rego.v1

# NIST CSF 2.0 DE.CM-02 — the physical environment is monitored to find
# potentially adverse events. Concord reads a cosigned attestation that records
# the physical monitoring controls in place (CCTV, badge/access logging,
# environmental sensors), the coverage areas those controls span, the alerting
# that turns a physical anomaly into a response, and the date the arrangement
# was last reviewed. Physical monitoring is largely off-cloud, so a signed,
# current attestation is the practical evidence of coverage.

required_fields := {"monitoring_controls", "coverage_areas", "alerting",
                    "last_reviewed_at"}

max_review_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no physical-monitoring attestation collected"
}

deny contains msg if {
    input.attestation.kind != "physical_monitoring"
    msg := sprintf("attestation kind is %q, expected \"physical_monitoring\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("physical-monitoring attestation missing field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "physical-monitoring attestation cosign signature did not verify"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    age_ns := time.now_ns() - reviewed
    age_ns > max_review_age_days * 24 * 60 * 60 * 1000000000
    msg := sprintf("physical-monitoring arrangement not reviewed within %d days", [max_review_age_days])
}
