package concord.nist_csf_2.de_ae_06

import rego.v1

# NIST CSF 2.0 DE.AE-06 — information on adverse events is provided to
# authorized staff and tools. Concord reads a cosigned attestation that records
# the notification process, the authorized recipients who receive event
# information, the channels used to deliver it, and the date the process was
# last reviewed. Detection has no value if findings do not reach the people and
# systems positioned to act on them, so a documented, current routing process
# is required.

required_fields := {"notification_process", "authorized_recipients", "channels",
                    "last_reviewed_at"}

max_review_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no event-notification attestation collected"
}

deny contains msg if {
    input.attestation.kind != "event_notification"
    msg := sprintf("attestation kind is %q, expected \"event_notification\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("event-notification attestation missing field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "event-notification attestation cosign signature did not verify"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    age_ns := time.now_ns() - reviewed
    age_ns > max_review_age_days * 24 * 60 * 60 * 1000000000
    msg := sprintf("event-notification process not reviewed within %d days", [max_review_age_days])
}
