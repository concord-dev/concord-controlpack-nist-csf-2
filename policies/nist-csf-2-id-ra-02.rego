package concord.nist_csf_2.id_ra_02

import rego.v1

# NIST CSF 2.0 ID.RA-02 — cyber threat intelligence received from sharing
# forums. Concord verifies a signed threat-intel attestation that lists the
# intelligence sources, an ingestion process, the consuming teams, and has
# been reviewed within the last year.

required_fields := {"intel_sources", "ingestion_process", "consumers", "last_reviewed_at"}

max_review_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no threat-intelligence-sources attestation collected"
}

deny contains msg if {
    input.attestation.kind != "threat_intel_sources"
    msg := sprintf("attestation kind is %q, expected \"threat_intel_sources\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("threat-intelligence sources missing required field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "threat-intelligence-sources attestation cosign signature did not verify"
}

deny contains msg if {
    count(input.attestation.attested_fields.intel_sources) == 0
    msg := "threat-intelligence program subscribes to zero sources"
}

deny contains msg if {
    count(input.attestation.attested_fields.consumers) == 0
    msg := "threat intelligence is routed to zero consuming teams"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    (time.now_ns() - reviewed) > (max_review_age_days * 24 * 3600 * 1000000000)
    msg := sprintf("threat-intelligence sources have not been reviewed in over %d days", [max_review_age_days])
}
