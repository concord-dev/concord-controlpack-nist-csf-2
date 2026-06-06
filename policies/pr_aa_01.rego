package concord.nist_csf_2.pr_aa_01

import rego.v1

deny contains msg if {
    not input.okta_users
    msg := "no Okta evidence collected"
}

deny contains msg if {
    some user in input.okta_users.users
    user.status == "ACTIVE"
    not user.has_strong_mfa
    msg := sprintf("active user %q has no strong MFA factor", [user.email])
}
