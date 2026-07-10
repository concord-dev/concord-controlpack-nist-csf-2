package concord.nist_csf_2.gv_oc_03

import rego.v1

# NIST CSF 2.0 GV.OC-03 — legal, regulatory, and contractual
# requirements regarding cybersecurity, including privacy and civil
# liberties obligations, are understood and managed.

required_fields := {"applicable_regulations", "contractual_obligations",
                    "tracking_process", "last_reviewed_at"}

max_review_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no legal-regulatory-requirements attestation collected"
}

deny contains msg if {
    input.attestation.kind != "legal_regulatory_requirements"
    msg := sprintf("attestation kind is %q, expected \"legal_regulatory_requirements\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("legal-regulatory attestation missing field: %s", [f])
}

deny contains msg if {
    count(input.attestation.attested_fields.applicable_regulations) == 0
    msg := "no applicable regulations enumerated"
}

deny contains msg if {
    count(input.attestation.attested_fields.contractual_obligations) == 0
    msg := "no contractual obligations enumerated"
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "legal-regulatory attestation cosign signature did not verify"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    age_ns := time.now_ns() - reviewed
    age_ns > max_review_age_days * 24 * 60 * 60 * 1000000000
    msg := sprintf("legal/regulatory register not reviewed within %d days", [max_review_age_days])
}
