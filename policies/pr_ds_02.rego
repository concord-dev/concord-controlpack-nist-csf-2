package concord.nist_csf_2.pr_ds_02

import rego.v1

deny contains msg if {
    not input.bucket_policies
    msg := "no S3 bucket-policy evidence collected"
}

deny contains msg if {
    some bucket in input.bucket_policies.buckets
    not enforces_secure_transport(bucket)
    msg := sprintf("bucket %q does not enforce TLS via bucket policy", [bucket.name])
}

enforces_secure_transport(bucket) if {
    some statement in bucket.policy.Statement
    statement.Effect == "Deny"
    statement.Condition.Bool["aws:SecureTransport"] == "false"
    statement.Action == "s3:*"
}
