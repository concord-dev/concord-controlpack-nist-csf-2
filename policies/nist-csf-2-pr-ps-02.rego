package concord.nist_csf_2.pr_ps_02

import rego.v1

# NIST CSF 2.0 PR.PS-02 — software is maintained, replaced, and removed
# commensurate with risk. Implemented via NIST 800-53 SI-2 (Flaw Remediation):
# security-relevant flaws must be corrected within a risk-based window (30 days
# for critical/security patches). Read from AWS SSM Patch Manager. Evidence:
# input.patch_compliance.instances. Adapted from concord.fedramp.si_2.
# Fail-closed: absent evidence denies; an instance is denied unless it reports
# a COMPLIANT patch state, and any missing critical/security patch older than
# 30 days denies per instance.

max_patch_age_days := 30

deny contains msg if {
	not input.patch_compliance
	msg := "NIST CSF 2.0 PR.PS-02: no SSM patch-compliance evidence collected"
}

deny contains msg if {
	some instance in input.patch_compliance.instances
	not instance.compliance_status == "COMPLIANT"
	msg := sprintf("NIST CSF 2.0 PR.PS-02: instance %q reports patch-compliance status %q (expected COMPLIANT) (NIST 800-53 SI-2)", [instance.instance_id, object.get(instance, "compliance_status", "UNKNOWN")])
}

deny contains msg if {
	some instance in input.patch_compliance.instances
	instance.oldest_missing_critical_age_days > max_patch_age_days
	msg := sprintf("NIST CSF 2.0 PR.PS-02: instance %q has a missing critical/security patch %d days old, exceeding the %d-day SLA (NIST 800-53 SI-2)", [instance.instance_id, instance.oldest_missing_critical_age_days, max_patch_age_days])
}
