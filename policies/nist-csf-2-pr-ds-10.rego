package concord.nist_csf_2.pr_ds_10

import rego.v1

# NIST CSF 2.0 PR.DS-10 — the confidentiality, integrity, and availability of
# data-at-rest are protected. Implemented via NIST 800-53 SC-28: every in-scope
# data store (tagged sensitive="true") must have encryption-at-rest configured.
# Evidence: input.encryption_at_rest.{buckets,rds_instances,ebs_volumes}.
# Adapted from concord.nist_csf_2.pr_ds_01 and concord.hipaa.encryption.
# Fail-closed: absent evidence, or any sensitive resource without encryption,
# denies.

deny contains msg if {
	not input.encryption_at_rest
	msg := "NIST CSF 2.0 PR.DS-10: no data-at-rest encryption evidence collected"
}

deny contains msg if {
	some b in input.encryption_at_rest.buckets
	is_sensitive(b)
	not b.encryption.configured
	msg := sprintf("NIST CSF 2.0 PR.DS-10: sensitive S3 bucket %q has no encryption-at-rest configured (NIST 800-53 SC-28)", [b.name])
}

deny contains msg if {
	some r in input.encryption_at_rest.rds_instances
	is_sensitive(r)
	not r.encryption.configured
	msg := sprintf("NIST CSF 2.0 PR.DS-10: sensitive RDS instance %q has no encryption-at-rest (NIST 800-53 SC-28)", [r.identifier])
}

deny contains msg if {
	some v in input.encryption_at_rest.ebs_volumes
	is_sensitive(v)
	not v.encryption.configured
	msg := sprintf("NIST CSF 2.0 PR.DS-10: sensitive EBS volume %q has no encryption-at-rest (NIST 800-53 SC-28)", [v.volume_id])
}

is_sensitive(resource) if {
	resource.tags.sensitive == "true"
}
