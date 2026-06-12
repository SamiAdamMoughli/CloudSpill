resource "azurerm_linux_function_app" "vuln_func" {
  name                = "vuln-function-app"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location

  storage_account_name       = azurerm_storage_account.vuln_storage.name
  storage_account_access_key = azurerm_storage_account.vuln_storage.primary_access_key
  service_plan_id            = azurerm_service_plan.example.id

  # VULNERABILITY: Allow HTTP traffic
  https_only = false

  site_config {
    application_stack {
      python_version = "3.9"
    }
  }

  identity {
    type = "SystemAssigned"
  }
}
