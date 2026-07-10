package concord.nist_csf_2.pr_aa_02

import rego.v1

# NIST CSF 2.0 PR.AA-02 — Identities are proofed and bound to credentials
# based on the context of interactions. Concord reads a signed
# identity-proofing attestation and fails if it is missing, unsigned, of the
# wrong kind, or omits the documented proofing process, the assurance levels
# it targets, the credential-binding method, or the last review date.

deny contains msg if {
	not input.attestation
	msg := "no identity-proofing attestation collected"
}

deny contains msg if {
	input.attestation.kind != "identity_proofing"
	msg := sprintf("attestation kind is %q, expected \"identity_proofing\"", [input.attestation.kind])
}

deny contains msg if {
	not input.attestation.signature_verified
	msg := "identity-proofing attestation signature did not verify"
}

deny contains msg if {
	object.get(input.attestation.attested_fields, "proofing_process", "") == ""
	msg := "attestation does not document an identity-proofing process"
}

deny contains msg if {
	count(object.get(input.attestation.attested_fields, "assurance_levels", [])) == 0
	msg := "attestation does not declare any identity/authenticator assurance levels"
}

deny contains msg if {
	object.get(input.attestation.attested_fields, "binding_method", "") == ""
	msg := "attestation does not document how identities are bound to credentials"
}

deny contains msg if {
	object.get(input.attestation.attested_fields, "last_reviewed_at", "") == ""
	msg := "attestation records no last_reviewed_at date"
}
