package concord.nist_csf_2.de_ae_08

import rego.v1

# NIST CSF 2.0 DE.AE-08 — incidents are declared when adverse events meet the
# defined incident criteria. Concord reads a cosigned attestation that records
# the declaration criteria, the severity matrix that classifies a declared
# incident, the decision authority empowered to declare, and the date the
# process was last reviewed. Objective, pre-agreed criteria prevent both
# under-declaration (events quietly closed) and inconsistent, personality-driven
# escalation.

required_fields := {"declaration_criteria", "severity_matrix", "decision_authority",
                    "last_reviewed_at"}

max_review_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no incident-declaration attestation collected"
}

deny contains msg if {
    input.attestation.kind != "incident_declaration"
    msg := sprintf("attestation kind is %q, expected \"incident_declaration\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("incident-declaration attestation missing field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "incident-declaration attestation cosign signature did not verify"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    age_ns := time.now_ns() - reviewed
    age_ns > max_review_age_days * 24 * 60 * 60 * 1000000000
    msg := sprintf("incident-declaration criteria not reviewed within %d days", [max_review_age_days])
}
