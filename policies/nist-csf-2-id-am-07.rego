package concord.nist_csf_2.id_am_07

import rego.v1

# NIST CSF 2.0 ID.AM-07 — inventories of data and corresponding metadata.
# Concord verifies a signed data-inventory attestation that lists the data
# categories held, assigns an owner to each, records the classification
# scheme, and has been reviewed within the last year.

required_fields := {"data_categories", "data_owners", "classification", "last_reviewed_at"}

max_review_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no data-inventory attestation collected"
}

deny contains msg if {
    input.attestation.kind != "data_inventory"
    msg := sprintf("attestation kind is %q, expected \"data_inventory\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("data inventory missing required field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "data-inventory attestation cosign signature did not verify"
}

deny contains msg if {
    count(input.attestation.attested_fields.data_categories) == 0
    msg := "data inventory lists zero data categories"
}

deny contains msg if {
    count(input.attestation.attested_fields.data_owners) == 0
    msg := "data inventory assigns no owners to its data categories"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    (time.now_ns() - reviewed) > (max_review_age_days * 24 * 3600 * 1000000000)
    msg := sprintf("data inventory has not been reviewed in over %d days", [max_review_age_days])
}
