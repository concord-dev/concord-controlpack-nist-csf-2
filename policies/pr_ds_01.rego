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

# doc 31 §4 — no fail-open tag gates: a resource with no 'sensitive' tag is neither confirmed in-scope
# nor out-of-scope, so every deny above skips it and it would pass silently.
# Warn on the unclassified resource instead of ignoring it.

warn contains msg if {
    some resource in input.encryption_status.buckets
    not classified(resource)
    msg := sprintf("S3 bucket %q has no sensitive tag, so this control's checks did not apply to it — tag sensitive=true to bring it into sensitive-data scope or sensitive=false to confirm it is out of scope", [resource.name])
}

warn contains msg if {
    some resource in input.encryption_status.rds_instances
    not classified(resource)
    msg := sprintf("RDS instance %q has no sensitive tag, so this control's checks did not apply to it — tag sensitive=true to bring it into sensitive-data scope or sensitive=false to confirm it is out of scope", [resource.identifier])
}

warn contains msg if {
    some resource in input.encryption_status.ebs_volumes
    not classified(resource)
    msg := sprintf("EBS volume %q has no sensitive tag, so this control's checks did not apply to it — tag sensitive=true to bring it into sensitive-data scope or sensitive=false to confirm it is out of scope", [resource.volume_id])
}

classified(resource) if resource.tags.sensitive == "true"

classified(resource) if resource.tags.sensitive == "false"
