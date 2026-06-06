package concord.nist_csf_2.gv_sc_04

import rego.v1

acceptable_cert_types := {"soc2", "iso27001", "iso27017", "iso27018"}

deny contains msg if {
    not input.attestation
    msg := "no vendor-register attestation collected"
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "vendor-register attestation signature did not verify"
}

deny contains msg if {
    some vendor in input.attestation.attested_fields.vendors
    not vendor.tier
    msg := sprintf("vendor %q has no tier assigned — every supplier must be prioritised by criticality", [vendor.name])
}

deny contains msg if {
    some vendor in input.attestation.attested_fields.vendors
    vendor.tier == "tier_1"
    count(applicable_certs(vendor)) == 0
    msg := sprintf("tier-1 vendor %q has no acceptable security certification", [vendor.name])
}

applicable_certs(vendor) := certs if {
    certs := [c |
        some c in vendor.certifications
        c.type in acceptable_cert_types
        not c.expired
    ]
}
