package concord.nist_csf_2.id_ra_04

import rego.v1

# NIST CSF 2.0 ID.RA-04 — potential impacts and likelihoods recorded.
# Concord verifies a signed risk-impact attestation carrying an impact
# scale, a likelihood scale, a set of recorded (scored) risks, and a
# review within the last year.

required_fields := {"impact_scale", "likelihood_scale", "recorded_risks", "last_reviewed_at"}

max_review_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no risk-impact-analysis attestation collected"
}

deny contains msg if {
    input.attestation.kind != "risk_impact_analysis"
    msg := sprintf("attestation kind is %q, expected \"risk_impact_analysis\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("risk impact analysis missing required field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "risk-impact-analysis attestation cosign signature did not verify"
}

deny contains msg if {
    count(input.attestation.attested_fields.impact_scale) == 0
    msg := "risk impact analysis defines no impact scale"
}

deny contains msg if {
    count(input.attestation.attested_fields.likelihood_scale) == 0
    msg := "risk impact analysis defines no likelihood scale"
}

deny contains msg if {
    count(input.attestation.attested_fields.recorded_risks) == 0
    msg := "risk impact analysis has scored zero risks"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    (time.now_ns() - reviewed) > (max_review_age_days * 24 * 3600 * 1000000000)
    msg := sprintf("risk impact analysis has not been reviewed in over %d days", [max_review_age_days])
}
