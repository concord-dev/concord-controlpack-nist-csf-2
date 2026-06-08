package concord.nist_csf_2.nist_csf_2_de_cm_02

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "nist_csf_2_de_cm_02")
	msg := "NIST-CSF-2-DE.CM-02: aws evidence missing"
}

deny contains msg if {
	some r in input.nist_csf_2_de_cm_02.resources
	not r.compliant
	msg := sprintf("NIST-CSF-2-DE.CM-02: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}
