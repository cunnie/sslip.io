data "ovh_dedicated_installation_template" "template" {
  template_name = "fedora43_64"
}

resource "ovh_dedicated_server" "nameserver" {
  service_name    = "ns3133463.ip-51-75-53.eu"
  display_name    = "ns-ovh.sslip.io"
  os              = data.ovh_dedicated_installation_template.template.template_name
  boot_id         = 1
  monitoring      = false
  no_intervention = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "ovh_dedicated_server_reinstall_task" "server_reinstall" {
  service_name = ovh_dedicated_server.nameserver.service_name
  os           = data.ovh_dedicated_installation_template.template.template_name

  customizations {
    post_installation_script = file("${path.module}/cloud-init.sh")
  }

  lifecycle {
    ignore_changes = all
  }
}
