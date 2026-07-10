package concord.nist_csf_2.id_ra_03

import rego.v1

# NIST CSF 2.0 ID.RA-03 — internal and external threats identified and
# recorded. Concord verifies a signed threat-identification attestation
# that lists both internal and external threats, a recording method, and
# has been reviewed within the last year.

required_fields := {"internal_threats", "external_threats", "recording_method", "last_reviewed_at"}

max_review_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no threat-identification attestation collected"
}

deny contains msg if {
    input.attestation.kind != "threat_identification"
    msg := sprintf("attestation kind is %q, expected \"threat_identification\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("threat identification missing required field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "threat-identification attestation cosign signature did not verify"
}

deny contains msg if {
    count(input.attestation.attested_fields.internal_threats) == 0
    msg := "threat identification records zero internal threats"
}

deny contains msg if {
    count(input.attestation.attested_fields.external_threats) == 0
    msg := "threat identification records zero external threats"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    (time.now_ns() - reviewed) > (max_review_age_days * 24 * 3600 * 1000000000)
    msg := sprintf("threat identification has not been reviewed in over %d days", [max_review_age_days])
}
