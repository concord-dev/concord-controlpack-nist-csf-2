package concord.nist_csf_2.pr_at_01

import rego.v1

max_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no training-register attestation collected"
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "training-register signature did not verify"
}

deny contains msg if {
    some person in input.attestation.attested_fields.active_people
    person.last_completion_days_ago > max_age_days
    msg := sprintf("%q has not completed training in %d days", [person.email, person.last_completion_days_ago])
}
