package concord.nist_csf_2.id_am_08

import rego.v1

# NIST CSF 2.0 ID.AM-08 — assets managed throughout their life cycle.
# Concord verifies a signed asset-lifecycle attestation that defines the
# lifecycle stages, documents decommissioning, describes ownership
# tracking, and has been reviewed within the last year.

required_fields := {"lifecycle_stages", "decommissioning_process", "ownership_tracking", "last_reviewed_at"}

max_review_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no asset-lifecycle attestation collected"
}

deny contains msg if {
    input.attestation.kind != "asset_lifecycle"
    msg := sprintf("attestation kind is %q, expected \"asset_lifecycle\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("asset lifecycle attestation missing required field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "asset-lifecycle attestation cosign signature did not verify"
}

deny contains msg if {
    count(input.attestation.attested_fields.lifecycle_stages) == 0
    msg := "asset lifecycle defines zero lifecycle stages"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    (time.now_ns() - reviewed) > (max_review_age_days * 24 * 3600 * 1000000000)
    msg := sprintf("asset lifecycle process has not been reviewed in over %d days", [max_review_age_days])
}
