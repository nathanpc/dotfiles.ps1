# Enable-OpenSSH.ps1
# Sets up and enables OpenSSH client and server on Windows.
#
# Author: Nathan Campos <nathan@innoveworkshop.com>

#Requires -RunAsAdministrator

# Just show the current status of the OpenSSH features.
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'

# Install the OpenSSH client and server.
Write-Output "Installing OpenSSH Client..."
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
Write-Output "Installing OpenSSH Server..."
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start and setup the SSH server.
Write-Output "Starting the SSH Server..."
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

# Confirm the Firewall rule is configured.
if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
    Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
} else {
    Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
}
