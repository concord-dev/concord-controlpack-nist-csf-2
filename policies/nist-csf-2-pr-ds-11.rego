package concord.nist_csf_2.pr_ds_11

import rego.v1

# NIST CSF 2.0 PR.DS-11 — the confidentiality, integrity, and availability of
# data-in-transit are protected. Implemented via NIST 800-53 SC-8: every
# transmission endpoint carrying sensitive data (tagged sensitive="true") must
# enforce TLS 1.2 or higher.
#   - S3 buckets must deny requests where aws:SecureTransport is false.
#   - ELB listeners must not carry traffic over a plaintext protocol.
#   - TLS/HTTPS listeners must use an SSL policy whose minimum protocol is
#     TLS 1.2.
# Evidence: input.transit_endpoints.{buckets,load_balancers}.
# Adapted from concord.nist_csf_2.pr_ds_02 and
# concord.hipaa.encryption_in_transit. Fail-closed: absent evidence denies.

# ELB security policies whose minimum negotiated protocol is TLS 1.2 or 1.3.
tls12plus_policies := {
	"ELBSecurityPolicy-TLS13-1-2-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
	"ELBSecurityPolicy-TLS-1-2-2017-01",
	"ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
	"ELBSecurityPolicy-FS-1-2-2019-08",
	"ELBSecurityPolicy-FS-1-2-Res-2019-08",
	"ELBSecurityPolicy-FS-1-2-Res-2020-10",
}

deny contains msg if {
	not input.transit_endpoints
	msg := "NIST CSF 2.0 PR.DS-11: no data-in-transit endpoint evidence collected"
}

# S3 bucket that does not deny non-TLS requests.
deny contains msg if {
	some b in input.transit_endpoints.buckets
	is_sensitive(b)
	not bucket_enforces_tls(b)
	msg := sprintf("NIST CSF 2.0 PR.DS-11: sensitive S3 bucket %q does not deny non-TLS requests (missing aws:SecureTransport=false deny) (NIST 800-53 SC-8)", [b.name])
}

# ELB listener carrying sensitive traffic over a plaintext protocol.
deny contains msg if {
	some lb in input.transit_endpoints.load_balancers
	is_sensitive(lb)
	some l in lb.listeners
	plaintext_protocol(l)
	msg := sprintf("NIST CSF 2.0 PR.DS-11: sensitive load balancer %q has a %s listener on port %d that transmits data without TLS (NIST 800-53 SC-8)", [lb.name, upper(l.protocol), l.port])
}

# ELB listener whose TLS policy permits protocols below TLS 1.2.
deny contains msg if {
	some lb in input.transit_endpoints.load_balancers
	is_sensitive(lb)
	some l in lb.listeners
	encrypted_protocol(l)
	not tls12plus(l)
	msg := sprintf("NIST CSF 2.0 PR.DS-11: sensitive load balancer %q listener on port %d uses SSL policy %q which permits TLS below 1.2 (NIST 800-53 SC-8)", [lb.name, l.port, object.get(l, "ssl_policy", "<none>")])
}

is_sensitive(x) if {
	x.tags.sensitive == "true"
}

bucket_enforces_tls(b) if {
	some stmt in b.policy.Statement
	stmt.Effect == "Deny"
	stmt.Condition.Bool["aws:SecureTransport"] == "false"
	action_covers_all(stmt)
}

action_covers_all(stmt) if {
	stmt.Action == "s3:*"
}

action_covers_all(stmt) if {
	some a in stmt.Action
	a == "s3:*"
}

plaintext_protocol(l) if {
	upper(l.protocol) == "HTTP"
}

plaintext_protocol(l) if {
	upper(l.protocol) == "TCP"
}

encrypted_protocol(l) if {
	upper(l.protocol) == "HTTPS"
}

encrypted_protocol(l) if {
	upper(l.protocol) == "TLS"
}

tls12plus(l) if {
	tls12plus_policies[l.ssl_policy]
}

# doc 31 §4 — no fail-open tag gates: a resource with no 'sensitive' tag is neither confirmed in-scope
# nor out-of-scope, so every deny above skips it and it would pass silently.
# Warn on the unclassified resource instead of ignoring it.

warn contains msg if {
	some resource in input.transit_endpoints.buckets
	not classified(resource)
	msg := sprintf("S3 bucket %q has no sensitive tag, so this control's checks did not apply to it — tag sensitive=true to bring it into sensitive-data scope or sensitive=false to confirm it is out of scope", [resource.name])
}

warn contains msg if {
	some resource in input.transit_endpoints.load_balancers
	not classified(resource)
	msg := sprintf("load balancer %q has no sensitive tag, so this control's checks did not apply to it — tag sensitive=true to bring it into sensitive-data scope or sensitive=false to confirm it is out of scope", [resource.name])
}

classified(resource) if resource.tags.sensitive == "true"

classified(resource) if resource.tags.sensitive == "false"
