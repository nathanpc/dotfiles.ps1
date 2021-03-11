# Block-FsrmMacJunk.ps1
# Sets up file screens to block junk files from Mac OS from your network shares.
#
# Author: Nathan Campos <nathan@innoveworkshop.com>

# Variables
$MacJunkPatterns = @("._*", "*.DS_Store", "*._.DS_Store", "*.Trashes",
    "*.apdisk", "*.TemporaryItems")

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
Creates the file group describing all the junk files a Mac can place on a file system.

.DESCRIPTION
Creates the file group describing all the junk files a Mac can place on a file system.

.INPUTS
None.

.OUTPUTS
Nothing.

.LINK
New-FsrmFileGroup
#>
Function New-MacJunkFileGroup {
    Write-Output "Creating junk Mac files file group..."
    New-FsrmFileGroup -Name "Mac Files" -IncludePattern $MacJunkPatterns | Out-Null
}

<#
.SYNOPSIS
Creates the file screen template to block all the junk files from Macs.

.DESCRIPTION
Creates the file screen template to block all the junk files from Macs.

.INPUTS
None.

.OUTPUTS
Nothing.

.LINK
New-FsrmFileScreenTemplate

.LINK
New-MacJunkFileGroup
#>
Function New-MacJunkFileScreenTemplate {
    Write-Output "Creating junk Mac files file screen template..."
    New-FsrmFileScreenTemplate -Name "Block Mac Junk Files" -IncludeGroup "Mac Files" `
        -Active | Out-Null
}

<#
.SYNOPSIS
Creates the file screen to block all the junk files from Macs in a particular directory.

.DESCRIPTION
Creates the file screen to block all the junk files from Macs in a particular directory.

.PARAMETER Path
Path of the directory that you want to screen for Mac junk.

.INPUTS
Path of the directory that you want to screen for Mac junk.

.OUTPUTS
Nothing.

.LINK
New-FsrmFileScreen

.LINK
New-MacJunkFileScreenTemplate
#>
Function New-MacJunkFileScreen {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline, Position = 0, Mandatory = $true)]
        [String]$Path
    )

    Write-Output "Creating junk Mac files screen in `"$Path`"..."
    New-FsrmFileScreen -Path $Path -Template "Block Mac Junk Files" -Active | Out-Null
}

# Check for the required arguments.
If ($args.Count -lt 1) {
    Write-Error "No directory to create the Mac junk file screen was passed to the script."
    Write-Output "Usage: Block-FsrmMacJunk <PathToScreen>`n"

    Write-Output "    PathToScreen    Path of the directory that you want to screen for Mac junk."
    Exit
}
$SharePath = $args[0]

# Create everything needed for the file screen.
New-MacJunkFileGroup
New-MacJunkFileScreenTemplate
New-MacJunkFileScreen $SharePath

# Delete any existing Mac junk.
If (Confirm-WithUser "Do you want to delete the Mac junk files that are already in the directory?") {
    Write-Output "Deleting all of the Mac junk for your network share..."
    Get-ChildItem -Path $SharePath -Include $MacJunkPatterns -Recurse -Force | Remove-Item -Force
}

Write-Output "All done!"