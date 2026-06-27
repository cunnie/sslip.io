resource "ovh_dedicated_server" "nameserver" {
  service_name    = "ns3133463.ip-51-75-53.eu"
  display_name    = "ns-ovh.sslip.io"
  os              = "ubuntu2404-server_64"
  boot_id         = 1
  monitoring      = false
  no_intervention = false

  lifecycle {
    prevent_destroy = true
  }
}
