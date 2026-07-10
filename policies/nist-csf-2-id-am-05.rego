package concord.nist_csf_2.id_am_05

import rego.v1

# NIST CSF 2.0 ID.AM-05 — assets prioritized by classification, criticality,
# resources, and mission impact. Concord verifies a signed prioritization
# attestation carrying a classification scheme, the criticality criteria,
# a non-empty prioritized asset set, and a recent review.

required_fields := {"classification_scheme", "criticality_criteria", "prioritized_assets", "last_reviewed_at"}

max_review_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no asset-prioritization attestation collected"
}

deny contains msg if {
    input.attestation.kind != "asset_prioritization"
    msg := sprintf("attestation kind is %q, expected \"asset_prioritization\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("asset prioritization missing required field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "asset-prioritization attestation cosign signature did not verify"
}

deny contains msg if {
    count(input.attestation.attested_fields.criticality_criteria) == 0
    msg := "asset prioritization defines zero criticality criteria"
}

deny contains msg if {
    count(input.attestation.attested_fields.prioritized_assets) == 0
    msg := "asset prioritization ranks zero assets"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    (time.now_ns() - reviewed) > (max_review_age_days * 24 * 3600 * 1000000000)
    msg := sprintf("asset prioritization has not been reviewed in over %d days", [max_review_age_days])
}
