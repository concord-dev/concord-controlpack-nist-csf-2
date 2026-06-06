package concord.nist_csf_2.pr_ds_01

import rego.v1

deny contains msg if {
    not input.encryption_status
    msg := "no encryption evidence collected"
}

deny contains msg if {
    some b in input.encryption_status.buckets
    is_sensitive(b)
    not b.encryption.configured
    msg := sprintf("sensitive bucket %q is not encrypted", [b.name])
}

deny contains msg if {
    some r in input.encryption_status.rds_instances
    is_sensitive(r)
    not r.encryption.configured
    msg := sprintf("sensitive RDS %q is not encrypted", [r.identifier])
}

deny contains msg if {
    some v in input.encryption_status.ebs_volumes
    is_sensitive(v)
    not v.encryption.configured
    msg := sprintf("sensitive EBS %q is not encrypted", [v.volume_id])
}

is_sensitive(resource) if {
    resource.tags.sensitive == "true"
}
