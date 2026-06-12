resource "azurerm_postgresql_server" "vuln_db" {
  name                = "vuln-pg-server"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  sku_name = "B_Gen5_1"

  storage_mb                   = 5120
  backup_retention_days        = 7
  geo_redundant_backup_enabled = false
  auto_grow_enabled            = false

  administrator_login          = "dbadmin"
  administrator_login_password = "SuperSecretPassword123!"
  version                      = "11"

  # VULNERABILITY: SSL enforcement disabled
  ssl_enforcement_enabled          = false

  # VULNERABILITY: Public network access allowed
  public_network_access_enabled    = true
}

resource "azurerm_postgresql_firewall_rule" "vuln_fw" {
  name                = "allow-all"
  resource_group_name = azurerm_resource_group.rg.name
  server_name         = azurerm_postgresql_server.vuln_db.name

  # VULNERABILITY: Firewall allows 0.0.0.0/0
  start_ip_address    = "0.0.0.0"
  end_ip_address      = "255.255.255.255"
}
