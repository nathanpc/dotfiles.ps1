# Enable-IISRemoteManagement.ps1
# Enables remote management of an IIS server.
#
# Author: Nathan Campos <nathan@innoveworkshop.com>

<#
.SYNOPSIS
Comfirms an action with the user.

.PARAMETER Message
Message that will be shown for the user to accept or reject.

.OUTPUTS
True if the user confirmed the action.
#>
Function Confirm-WithUser {
    Param(
        [Parameter(Mandatory = $true)]
        [String]$Message
    )

    $Response = Read-Host -Prompt "$Message [y/n]"
    While ($Response -NotMatch "[YyNn]") {
        $Response = Read-Host -Prompt "$Message [y/n]"
    }

    Return $Response -Match "[Yy]"
}

<#
.SYNOPSIS
A little welcome message and a confirmation with the user to begin the process.
#>
Function Write-Introduction {
    Write-Output "============================================="
    Write-Output "=====   IIS Remote Management Enabler   ====="
    Write-Output "=====         by Nathan Campos          ====="
    Write-Output "============================================="
    Write-Output ""

    If (-Not (Confirm-WithUser "Do you wish to enable IIS remote management on this server?")) {
        Exit
    }

    Write-Output ""
}

Function Enable-RemoteManagement {
    Write-Output "Installing Web Management Service..."
    Install-WindowsFeature Web-Mgmt-Service
    
    Write-Output "Creating firewall rules..."
    netsh advfirewall firewall add rule name=”IIS Remote Management” dir=in action=allow service=WMSVC
    
    Write-Output "Enabling IIS Remote Management..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WebManagement\Server" -Name "EnableRemoteManagement" -Type DWord -Value 1

    Write-Output "Setting the Web Management Service to start on boot..."
    sc.exe config WMSVC start=auto
    
    Write-Output "Starting the Web Management Service..."
    net start WMSVC
}

# Run the script.
Write-Introduction
Enable-RemoteManagement
Write-Output "Done."