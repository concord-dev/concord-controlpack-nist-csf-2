package concord.nist_csf_2.id_am_02

import rego.v1

max_scan_age_days := 30

deny contains msg if {
    not input.software_inventory
    msg := "no software-inventory evidence collected"
}

deny contains msg if {
    some project in input.software_inventory.projects
    project.active
    not project.has_sbom
    msg := sprintf("project %q has no SBOM", [project.name])
}

deny contains msg if {
    some project in input.software_inventory.projects
    project.active
    project.last_scan_age_days > max_scan_age_days
    msg := sprintf("project %q has not been scanned in %d days (max %d)", [project.name, project.last_scan_age_days, max_scan_age_days])
}
