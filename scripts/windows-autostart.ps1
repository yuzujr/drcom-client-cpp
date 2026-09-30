param(
    [switch]$Uninstall,
    [string]$Executable = (Join-Path $PSScriptRoot 'drcom_client.exe'),
    [string]$Config = (Join-Path $PSScriptRoot 'drcom.conf')
)

$ErrorActionPreference = 'Stop'
$taskName = 'DRCOM Client'

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host 'DRCOM autostart removed.'
    exit 0
}

$executablePath = (Resolve-Path -LiteralPath $Executable).Path
$configPath = (Resolve-Path -LiteralPath $Config).Path
$logDirectory = Join-Path $env:LOCALAPPDATA 'DrcomClient'
New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null

$action = New-ScheduledTaskAction -Execute $executablePath `
    -Argument ('-c "{0}"' -f $configPath) -WorkingDirectory $logDirectory
$trigger = New-ScheduledTaskTrigger -AtLogOn -User ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$principal = New-ScheduledTaskPrincipal `
    -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
    -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Write-Host "DRCOM autostart installed. Logs: $logDirectory\drcom.log"
