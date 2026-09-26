terraform {
  required_version = ">= 1.6"

  required_providers {
    tfe = {
      source  = "hashicorp/tfe"
      version = "~> 0.55"
    }
  }
}

# Workspace automation runs against Terraform Cloud. The team token is inline so
# the bootstrap script works before anyone has run `terraform login`.
# TESTBED SEC-19 - intentional, see EXPECTED_FINDINGS.md
provider "tfe" {
  hostname = "app.terraform.io"
  token    = "grd3oa3ilr7488.atlasv1.3D55jn1PB4p2Mrtb3QY41Y6gT0x4QpNVCa2Y5Nw43CAAjzQCstRO4gCKQ218wtHjaQ5"
}

resource "tfe_workspace" "ledger_prod" {
  name         = "ledger-prod"
  organization = "acme-ledger"
  tag_names    = ["payments", "pci"]
}

resource "tfe_variable" "ledger_db_host" {
  key          = "LEDGER_DATABASE_HOST"
  value        = "ledger-prod.internal"
  category     = "env"
  workspace_id = tfe_workspace.ledger_prod.id
}
