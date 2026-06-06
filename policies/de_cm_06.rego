package concord.nist_csf_2.de_cm_06

import rego.v1

expiry_warning_days := 30

deny contains msg if {
    not input.attestation
    msg := "no vendor-register attestation collected"
}

deny contains msg if {
    some vendor in input.attestation.attested_fields.vendors
    vendor.tier == "tier_1"
    some cert in vendor.certifications
    cert.days_until_expiry < expiry_warning_days
    cert.days_until_expiry >= 0
    not cert.renewal_in_progress
    msg := sprintf("tier-1 vendor %q %s cert expires in %d days and renewal is not in progress", [vendor.name, cert.type, cert.days_until_expiry])
}
