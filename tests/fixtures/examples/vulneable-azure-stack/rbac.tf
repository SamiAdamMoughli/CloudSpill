data "azurerm_subscription" "primary" {}

resource "azurerm_role_assignment" "vuln_admin" {
  # VULNERABILITY: Assigning the "Owner" role at the subscription level
  scope                = data.azurerm_subscription.primary.id
  role_definition_name = "Owner"
  principal_id         = azurerm_linux_function_app.vuln_func.identity[0].principal_id
}
