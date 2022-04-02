# Setup-Server2008R2-Exchange2010-PreReq.ps1
# Sets up the pre-requisites to install Exchange 2010 on Server 2008 R2.
#
# Author: Nathan Campos <nathan@innoveworkshop.com>

Write-Output "Preparing to install the pre-requisites to install Exchange 2010..."

# Warning.
Write-Output "Before proceeding make sure you have the Microsoft Filter Pack installed. This can be downloaded from https://www.microsoft.com/en-us/download/details.aspx?id=17062"
timeout /t -1

# Import Server Manager.
Write-Output "Importing the Server Manager module..."
Import-Module ServerManager

# Install optional Windows features.
Write-Output "Installing optional Windows features..."
Add-WindowsFeature NET-Framework, RSAT-ADDS, Web-Server, Web-Basic-Auth, `
    Web-Windows-Auth, Web-Metabase, Web-Net-Ext, Web-Lgcy-Mgmt-Console, `
    Web-ISAPI-Ext, Web-Digest-Auth, Web-Dyn-Compression, NET-HTTP-Activation, `
    RPC-Over-HTTP-Proxy, Desktop-Experience

# Final steps.
Write-Output "A system restart is now required."
Write-Host "Remember to execute the following cmdlet after the restart:" -ForegroundColor Yellow -NoNewline
Write-Output "Set-Service NetTcpPortSharing -StartupType Automatic"
timeout /t -1
