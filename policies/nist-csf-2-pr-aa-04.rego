package concord.nist_csf_2.pr_aa_04

import rego.v1

# NIST CSF 2.0 PR.AA-04 — Identity assertions are protected, conveyed, and
# verified. Concord reads a signed attestation describing how federation and
# SSO assertions are secured, and fails if it is missing, unsigned, of the
# wrong kind, or omits the assertion protocols in use, how assertions/tokens
# are protected in transit, the relying-party verification method, or the
# last review date.

deny contains msg if {
	not input.attestation
	msg := "no identity-assertions attestation collected"
}

deny contains msg if {
	input.attestation.kind != "identity_assertions"
	msg := sprintf("attestation kind is %q, expected \"identity_assertions\"", [input.attestation.kind])
}

deny contains msg if {
	not input.attestation.signature_verified
	msg := "identity-assertions attestation signature did not verify"
}

deny contains msg if {
	count(object.get(input.attestation.attested_fields, "assertion_protocols", [])) == 0
	msg := "attestation names no identity-assertion protocols (e.g. SAML 2.0, OIDC)"
}

deny contains msg if {
	object.get(input.attestation.attested_fields, "token_protection", "") == ""
	msg := "attestation does not document how assertions/tokens are protected in transit"
}

deny contains msg if {
	object.get(input.attestation.attested_fields, "verification_method", "") == ""
	msg := "attestation does not document how relying parties verify assertions"
}

deny contains msg if {
	object.get(input.attestation.attested_fields, "last_reviewed_at", "") == ""
	msg := "attestation records no last_reviewed_at date"
}
