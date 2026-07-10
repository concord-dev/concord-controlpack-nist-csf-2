package concord.nist_csf_2.id_am_04

import rego.v1

# NIST CSF 2.0 ID.AM-04 — inventory of services provided by suppliers.
# Concord verifies a signed supplier-services attestation that lists the
# services obtained from suppliers, maps each to its provider, records a
# criticality rating, and has been reviewed within the last year.

required_fields := {"services_inventory", "supplier_mapping", "criticality_rating", "last_reviewed_at"}

max_review_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no supplier-services-inventory attestation collected"
}

deny contains msg if {
    input.attestation.kind != "supplier_services_inventory"
    msg := sprintf("attestation kind is %q, expected \"supplier_services_inventory\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("supplier-services inventory missing required field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "supplier-services-inventory attestation cosign signature did not verify"
}

deny contains msg if {
    count(input.attestation.attested_fields.services_inventory) == 0
    msg := "supplier-services inventory lists zero services"
}

deny contains msg if {
    count(input.attestation.attested_fields.supplier_mapping) == 0
    msg := "supplier-services inventory maps no services to their suppliers"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    (time.now_ns() - reviewed) > (max_review_age_days * 24 * 3600 * 1000000000)
    msg := sprintf("supplier-services inventory has not been reviewed in over %d days", [max_review_age_days])
}
