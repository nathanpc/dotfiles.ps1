# Enable-CoreRemoteManagement.ps1
# Enables remote management tools on a Core-edition of a Windows server.
#
# Author: Nathan Campos <nathan@innoveworkshop.com>
# Found At: https://cloudoasis.com.au/2017/03/17/remotely-administering-windows-server-core-with-computer-management/

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
    Write-Output "========================================================="
    Write-Output "===== Windows Server Core Remote Management Enabler ====="
    Write-Output "=====               by Nathan Campos                ====="
    Write-Output "========================================================="
    Write-Output ""

    If (-Not (Confirm-WithUser "Do you wish to enable remote management on this server?")) {
        Exit
    }

    Write-Output ""
}

Function Enable-RemoteManagement {
    Enable-NetFireWallRule -DisplayName "Windows Management Instrumentation (DCOM-In)"
    Enable-NetFireWallRule -DisplayGroup "Remote Event Log Management"
    Enable-NetFireWallRule -DisplayGroup "Remote Service Management"
    Enable-NetFireWallRule -DisplayGroup "Remote Volume Management"
    Enable-NetFireWallRule -DisplayGroup "Remote Scheduled Tasks Management"
    Enable-NetFireWallRule -DisplayGroup "Windows Firewall Remote Management"
}

# Run the script.
Write-Introduction
Enable-RemoteManagement
Write-Host "Note:" -ForegroundColor Yellow -NoNewline
Write-Output "Remember to execute the following cmdlet in the server that will be managing this server:"
Write-Output "Enable-NetFirewallRule -DisplayGroup `"Remote Volume Management`""