package concord.nist_csf_2.de_ae_02

import rego.v1

# NIST CSF 2.0 DE.AE-02 — potentially adverse events are analyzed to better
# understand associated activities. Concord reads a cosigned attestation that
# records the documented analysis process: the procedures analysts follow, the
# tooling used to triage and correlate events, the roles responsible, and the
# date the process was last reviewed. A documented, current, signed process is
# the assurance that alerts are actually investigated rather than discarded.

required_fields := {"analysis_procedures", "tooling", "analyst_roles",
                    "last_reviewed_at"}

max_review_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no event-analysis-process attestation collected"
}

deny contains msg if {
    input.attestation.kind != "event_analysis_process"
    msg := sprintf("attestation kind is %q, expected \"event_analysis_process\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("event-analysis-process attestation missing field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "event-analysis-process attestation cosign signature did not verify"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    age_ns := time.now_ns() - reviewed
    age_ns > max_review_age_days * 24 * 60 * 60 * 1000000000
    msg := sprintf("event-analysis process not reviewed within %d days", [max_review_age_days])
}
