package concord.nist_csf_2.pr_at_02

import rego.v1

# NIST CSF 2.0 PR.AT-02 — Individuals in specialized roles are provided with
# awareness and training so they possess the knowledge and skills to perform
# relevant tasks. Concord reads a signed attestation for the specialized-role
# training program and fails if it is missing, unsigned, of the wrong kind,
# omits the specialized roles covered, the curriculum, or completion tracking,
# has gone stale (last delivered more than 365 days ago), or lacks a review
# date.

max_age_days := 365

deny contains msg if {
	not input.attestation
	msg := "no specialized-training attestation collected"
}

deny contains msg if {
	input.attestation.kind != "specialized_training"
	msg := sprintf("attestation kind is %q, expected \"specialized_training\"", [input.attestation.kind])
}

deny contains msg if {
	not input.attestation.signature_verified
	msg := "specialized-training attestation signature did not verify"
}

deny contains msg if {
	count(object.get(input.attestation.attested_fields, "specialized_roles", [])) == 0
	msg := "attestation enumerates no specialized roles requiring role-based training"
}

deny contains msg if {
	object.get(input.attestation.attested_fields, "curriculum", "") == ""
	msg := "attestation does not document a specialized-role training curriculum"
}

deny contains msg if {
	object.get(input.attestation.attested_fields, "completion_tracking", false) != true
	msg := "attestation does not confirm that training completion is tracked"
}

deny contains msg if {
	object.get(input.attestation.attested_fields, "training_age_days", 1000000) > max_age_days
	msg := sprintf("specialized-role training last delivered %d days ago (max %d)", [object.get(input.attestation.attested_fields, "training_age_days", 1000000), max_age_days])
}

deny contains msg if {
	object.get(input.attestation.attested_fields, "last_reviewed_at", "") == ""
	msg := "attestation records no last_reviewed_at date"
}
