locals {
  config = yamldecode(file("${path.module}/../../config.yaml"))
  autostop_enabled = local.config.auto_stop.enabled
  timezone         = local.config.auto_stop.timezone
  schedule         = local.config.auto_stop.schedule
  start_script = <<EOF
Connect-AzAccount -Identity
Start-AzAksCluster -ResourceGroupName '${azurerm_resource_group.lab.name}' -Name '${var.cluster_name}'
EOF

  stop_script = <<EOF
Connect-AzAccount -Identity
Stop-AzAksCluster -ResourceGroupName '${azurerm_resource_group.lab.name}' -Name '${var.cluster_name}'
EOF
}