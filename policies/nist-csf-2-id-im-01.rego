package concord.nist_csf_2.id_im_01

import rego.v1

# NIST CSF 2.0 ID.IM-01 — improvements identified from evaluations.
# Concord verifies a signed improvement-process attestation that names the
# improvement sources, a review cadence, a tracking mechanism, and has been
# reviewed within the last year.

required_fields := {"improvement_sources", "review_cadence", "tracking_mechanism", "last_reviewed_at"}

max_review_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no improvement-process attestation collected"
}

deny contains msg if {
    input.attestation.kind != "improvement_process"
    msg := sprintf("attestation kind is %q, expected \"improvement_process\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("improvement process missing required field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "improvement-process attestation cosign signature did not verify"
}

deny contains msg if {
    count(input.attestation.attested_fields.improvement_sources) == 0
    msg := "improvement process identifies zero improvement sources"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    (time.now_ns() - reviewed) > (max_review_age_days * 24 * 3600 * 1000000000)
    msg := sprintf("improvement process has not been reviewed in over %d days", [max_review_age_days])
}
