resource "azurerm_storage_account" "vuln_storage" {
  name                     = "vulnstorageacct"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # VULNERABILITY: Allow HTTP traffic
  enable_https_traffic_only = false

  # VULNERABILITY: Allow public access to blobs
  allow_nested_items_to_be_public = true

  # VULNERABILITY: Outdated TLS version
  min_tls_version = "TLS1_0"
}

resource "azurerm_storage_container" "vuln_container" {
  name                  = "public-data"
  storage_account_name  = azurerm_storage_account.vuln_storage.name

  # VULNERABILITY: Full public read access for container and blobs
  container_access_type = "container"
}
