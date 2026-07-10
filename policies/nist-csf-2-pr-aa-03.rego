package concord.nist_csf_2.pr_aa_03

import rego.v1

# NIST CSF 2.0 PR.AA-03 — Users, services, and hardware are authenticated.
# Concord reads the AWS IAM credential report and fails any non-root identity
# that can sign in to the console with a password but has no active MFA
# device. Fail-closed: if no credential report was collected, MFA coverage
# cannot be proven, so the control denies. Root is covered by its own control
# and is only surfaced here as an advisory.

# Fail closed: absent evidence cannot demonstrate authentication strength.
deny contains msg if {
	not input.iam_credentials
	msg := "no IAM credential report collected — cannot verify MFA on console users"
}

# Console-enabled non-root identity without an active MFA device.
deny contains msg if {
	some u in input.iam_credentials.users
	u.user != "<root_account>"
	u.password_enabled == true
	not u.mfa_active
	msg := sprintf("IAM user %q has console access without an active MFA device", [u.user])
}

# Root MFA is enforced elsewhere; advise if root is console-enabled without MFA.
warn contains msg if {
	some u in input.iam_credentials.users
	u.user == "<root_account>"
	u.password_enabled == true
	not u.mfa_active
	msg := "root account has console access without MFA — enable a hardware MFA device on root"
}
