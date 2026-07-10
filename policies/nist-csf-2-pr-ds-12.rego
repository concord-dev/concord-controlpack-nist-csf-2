package concord.nist_csf_2.pr_ds_12

import rego.v1

# NIST CSF 2.0 PR.DS-12 — backups of data are created, maintained, protected,
# and tested. Implemented via NIST 800-53 CP-9 (System Backup) and CP-9(1)
# (Testing for Reliability and Integrity). For every in-scope data store
# (tagged sensitive="true"):
#   - RDS instances must retain automated backups for >= 30 days.
#   - DynamoDB tables must have point-in-time recovery enabled.
#   - AWS Backup vaults holding in-scope data must be vault-locked and must have
#     had a successful restore test within the last 365 days.
# Evidence: input.data_backups.{rds_instances,dynamodb_tables,backup_vaults}.
# Adapted from concord.fedramp.cp_9 and concord.nist_csf_2.rc_rp_01.
# Fail-closed: absent evidence, or any in-scope resource that is unprotected or
# untested, denies.

min_retention_days := 30

max_restore_test_age_days := 365

deny contains msg if {
	not input.data_backups
	msg := "NIST CSF 2.0 PR.DS-12: no backup evidence collected"
}

deny contains msg if {
	some rds in input.data_backups.rds_instances
	in_scope(rds)
	rds.backup_retention_period < min_retention_days
	msg := sprintf("NIST CSF 2.0 PR.DS-12: in-scope RDS instance %q has backup retention %d days (floor is %d) (NIST 800-53 CP-9)", [rds.identifier, rds.backup_retention_period, min_retention_days])
}

deny contains msg if {
	some table in input.data_backups.dynamodb_tables
	in_scope(table)
	not table.point_in_time_recovery_enabled
	msg := sprintf("NIST CSF 2.0 PR.DS-12: in-scope DynamoDB table %q has point-in-time recovery disabled (NIST 800-53 CP-9)", [table.name])
}

deny contains msg if {
	some vault in input.data_backups.backup_vaults
	vault.holds_in_scope_data
	not vault.locked
	msg := sprintf("NIST CSF 2.0 PR.DS-12: backup vault %q holds in-scope data but is not vault-locked (tamper-resistant retention required) (NIST 800-53 CP-9)", [vault.name])
}

# CP-9(1): backups must be tested. A vault holding in-scope data whose most
# recent successful restore test is older than a year (or which has never been
# tested) is a finding.
deny contains msg if {
	some vault in input.data_backups.backup_vaults
	vault.holds_in_scope_data
	not restore_tested_recently(vault)
	msg := sprintf("NIST CSF 2.0 PR.DS-12: backup vault %q has not had a successful restore test in the last %d days (restore_test_age_days=%v) (NIST 800-53 CP-9(1))", [vault.name, max_restore_test_age_days, object.get(vault, "restore_test_age_days", "never")])
}

restore_tested_recently(vault) if {
	vault.restore_test_age_days <= max_restore_test_age_days
}

in_scope(resource) if {
	resource.tags.sensitive == "true"
}
