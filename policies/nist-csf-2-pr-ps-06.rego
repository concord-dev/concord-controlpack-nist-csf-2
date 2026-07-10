package concord.nist_csf_2.pr_ps_06

import rego.v1

# NIST CSF 2.0 PR.PS-06 — A secure software development life cycle is
# integrated into software development practices. Concord reads a signed
# attestation for the SDLC program and fails if it is missing, unsigned, of
# the wrong kind, or omits the security gates enforced in the SDLC, the types
# of security testing performed, confirmation that developers receive secure
# development training, or the review date.

deny contains msg if {
	not input.attestation
	msg := "no secure-SDLC attestation collected"
}

deny contains msg if {
	input.attestation.kind != "secure_sdlc"
	msg := sprintf("attestation kind is %q, expected \"secure_sdlc\"", [input.attestation.kind])
}

deny contains msg if {
	not input.attestation.signature_verified
	msg := "secure-SDLC attestation signature did not verify"
}

deny contains msg if {
	count(object.get(input.attestation.attested_fields, "sdlc_gates", [])) == 0
	msg := "attestation names no security gates in the SDLC (e.g. threat modeling, peer review, security sign-off)"
}

deny contains msg if {
	count(object.get(input.attestation.attested_fields, "security_testing_types", [])) == 0
	msg := "attestation names no security testing types (e.g. SAST, DAST, dependency/secret scanning)"
}

deny contains msg if {
	object.get(input.attestation.attested_fields, "developer_training", false) != true
	msg := "attestation does not confirm that developers receive secure-development training"
}

deny contains msg if {
	object.get(input.attestation.attested_fields, "last_reviewed_at", "") == ""
	msg := "attestation records no last_reviewed_at date"
}
