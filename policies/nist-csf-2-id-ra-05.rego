package concord.nist_csf_2.id_ra_05

import rego.v1

# NIST CSF 2.0 ID.RA-05 — risk determined from threats, vulnerabilities,
# likelihoods, and impacts. Concord verifies a signed risk-determination
# attestation carrying a methodology, a prioritized risk set, a review
# cadence, and a review within the last year.

required_fields := {"risk_methodology", "prioritized_risks", "review_cadence", "last_reviewed_at"}

max_review_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no risk-determination attestation collected"
}

deny contains msg if {
    input.attestation.kind != "risk_determination"
    msg := sprintf("attestation kind is %q, expected \"risk_determination\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("risk determination missing required field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "risk-determination attestation cosign signature did not verify"
}

deny contains msg if {
    count(input.attestation.attested_fields.prioritized_risks) == 0
    msg := "risk determination produced zero prioritized risks"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    (time.now_ns() - reviewed) > (max_review_age_days * 24 * 3600 * 1000000000)
    msg := sprintf("risk determination has not been reviewed in over %d days", [max_review_age_days])
}
