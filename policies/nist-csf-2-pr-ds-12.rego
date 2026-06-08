package concord.nist_csf_2.nist_csf_2_pr_ds_12

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "nist_csf_2_pr_ds_12")
	msg := "NIST-CSF-2-PR.DS-12: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.nist_csf_2_pr_ds_12)
	msg := sprintf("NIST-CSF-2-PR.DS-12: attestation expired (expires_at=%s)", [input.nist_csf_2_pr_ds_12.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.nist_csf_2_pr_ds_12, 365)
	msg := sprintf("NIST-CSF-2-PR.DS-12: attestation not reviewed in 365 days (last_review_at=%s)", [input.nist_csf_2_pr_ds_12.last_review_at])
}
