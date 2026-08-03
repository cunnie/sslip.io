terraform {
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "~> 0.111"
    }
  }
}

provider "proxmox" {
  endpoint = "https://pve.nono.io:8006/"
  # must be root because "only root can set 'hookscript' config"
  username = "root@pam"
  # must be password, not API token,  because "proxmox_virtual_environment_file"
  password = var.password
  insecure = true
}

variable "password" {
  description = "Proxmox user password"
  type        = string
  sensitive   = true
}

resource "proxmox_virtual_environment_vm" "dnstap" {
  name      = "dnstap"
  vm_id     = 120
  node_name = "pve"
  # Do NOT use "hook_script_file_id"; it runs the hook on the HOST not the VM
  # hook_script_file_id = proxmox_virtual_environment_file.post_install_script.id

  # we want all our VMs to run the qemu-guest-agent
  agent {
    enabled = true
  }

  cpu {
    cores   = 4
    sockets = 1
    type    = "host"
  }
  memory {
    dedicated = 65536 # 64 GiB in MB
  }

  disk {
    datastore_id = "local-lvm"
    interface    = "scsi0"
    size         = 64 # Size in GiB
  }

  # Pass through the host disk /dev/sda directly to the VM
  disk {
    datastore_id      = ""
    interface         = "scsi1"
    path_in_datastore = "/dev/sda"
    file_format       = "raw"
  }

  # Clone from template
  clone {
    vm_id = 1002 # Fedora 44
  }

  # Cloud-init configuration inline
  initialization {
    ip_config {
      ipv4 {
        address = "10.9.9.120/24"
        gateway = "10.9.9.1"
      }
      ipv6 {
        address = "2601:645:8103:e3a0::78/64"
        gateway = "2601:645:8103:e3a0::"
      }

    }
    dns {
      servers = ["8.8.8.8", "8.8.4.4"]
    }
    datastore_id      = "local-lvm"
    user_data_file_id = proxmox_virtual_environment_file.cloud_config.id
  }

  network_device {
    bridge      = "vmbr0"
    model       = "virtio"
    mac_address = "02:00:00:00:00:78"
  }

  operating_system {
    type = "l26" # Linux 2.6 kernel and later
  }
  boot_order = ["scsi0"]
}

# We can't use API token; we must user/pass because this resource.
# "The resource with this content type uses SSH access to the node. You might need to configure the ssh option in the provider section"
# https://registry.terraform.io/providers/bpg/proxmox/latest/docs/resources/virtual_environment_file
# Cloud-init configuration file
resource "proxmox_virtual_environment_file" "cloud_config" {
  content_type = "snippets"
  datastore_id = "local"
  node_name    = "pve"

  source_file {
    path = "cloud-init-dnstap.yaml"
  }
}

output "vm_info" {
  value = {
    name   = proxmox_virtual_environment_vm.dnstap.name
    vmid   = proxmox_virtual_environment_vm.dnstap.vm_id
    node   = proxmox_virtual_environment_vm.dnstap.node_name
    cores  = proxmox_virtual_environment_vm.dnstap.cpu[0].cores
    memory = proxmox_virtual_environment_vm.dnstap.memory[0].dedicated
  }
}
