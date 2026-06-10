terraform {
  backend "azurerm" {
    resource_group_name  = "rg-eastus01"
    storage_account_name = "playgroundtfstate7c3"
    container_name       = "civo-secops-gitops-lab"
    key                  = "civo.tfstate"
    use_oidc             = true
  }
}