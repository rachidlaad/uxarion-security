[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string]$Version = "latest"
)

$script = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/rachidlaad/uxarion/main/scripts/install/install.ps1"
$scriptBlock = [scriptblock]::Create($script)
& $scriptBlock -Version $Version
