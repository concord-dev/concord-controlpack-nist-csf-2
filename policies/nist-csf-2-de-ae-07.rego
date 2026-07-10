package concord.nist_csf_2.de_ae_07

import rego.v1

# NIST CSF 2.0 DE.AE-07 — cyber threat intelligence and other contextual
# information are integrated into the analysis. Concord reads a cosigned
# attestation that records the intel feeds consumed, the process used to tune
# detection content from that intelligence, the cadence on which the
# integration is reviewed, and the date the process was last reviewed. Threat
# intelligence only improves detection when it is operationalised into rules
# and reviewed for continued relevance.

required_fields := {"intel_feeds", "detection_tuning_process", "review_cadence",
                    "last_reviewed_at"}

max_review_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no cti-integration attestation collected"
}

deny contains msg if {
    input.attestation.kind != "cti_integration"
    msg := sprintf("attestation kind is %q, expected \"cti_integration\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("cti-integration attestation missing field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "cti-integration attestation cosign signature did not verify"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    age_ns := time.now_ns() - reviewed
    age_ns > max_review_age_days * 24 * 60 * 60 * 1000000000
    msg := sprintf("threat-intelligence integration not reviewed within %d days", [max_review_age_days])
}
