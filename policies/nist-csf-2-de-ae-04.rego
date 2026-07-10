package concord.nist_csf_2.de_ae_04

import rego.v1

# NIST CSF 2.0 DE.AE-04 — the estimated impact and scope of adverse events are
# understood. Concord reads a cosigned attestation that records how impact and
# scope are determined: the impact criteria applied, the method used to scope
# affected assets and data, the escalation thresholds that route an event by
# severity, and the date the process was last reviewed. Without documented,
# current criteria, impact judgements are ad hoc and non-repeatable.

required_fields := {"impact_criteria", "scoping_method", "escalation_thresholds",
                    "last_reviewed_at"}

max_review_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no event-impact-analysis attestation collected"
}

deny contains msg if {
    input.attestation.kind != "event_impact_analysis"
    msg := sprintf("attestation kind is %q, expected \"event_impact_analysis\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("event-impact-analysis attestation missing field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "event-impact-analysis attestation cosign signature did not verify"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    age_ns := time.now_ns() - reviewed
    age_ns > max_review_age_days * 24 * 60 * 60 * 1000000000
    msg := sprintf("impact/scope analysis criteria not reviewed within %d days", [max_review_age_days])
}
