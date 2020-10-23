# CadsoftEagleUtilities.psm1
# A module with utilities for automating some tasks related to Cadsoft's EAGLE
# ECAD package.
#
# Author: Nathan Campos <nathan@innoveworkshop.com>

<#
.SYNOPSIS
Removes those pesky backup files (.s#1, .b#2, etc.) that Eagle lefts behind.

.DESCRIPTION
Removes those pesky backup files (.s#1, .b#2, etc.) that Eagle lefts behind.

.PARAMETER Path
Path of the directory that you want to be cleaned.

.INPUTS
Directory to be cleaned.

.OUTPUTS
Nothing.

.LINK
Remove-Item
#>
function Remove-EagleBackupFiles {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline, Position = 0, Mandatory = $true)]
        [String[]]$Path
    )

    # Get all the files with extensions like .s#1, .b#2, and deletes them.
    Get-ChildItem $Path\* | 
        Where-Object { $_.FullName -Match "\.\w#\d$" } |
        Remove-Item
}

<#
.SYNOPSIS
Builds a Gerber ZIP package for distribution and uploading to PCB manufacturers.

.DESCRIPTION
Builds a Gerber ZIP package for distribution and uploading to PCB manufacturers.

.PARAMETER Path
Path of the directory where the exported Gerbers reside in.

.PARAMETER Name
Name of the project. This will be the name of the ZIP file after it's packaged.

.PARAMETER DestinationPath
Path to where the ZIP file with the Gerbers will be placed.

.PARAMETER Clean
Deletes the Gerbers that were compressed into an archive.

.INPUTS
None.

.OUTPUTS
Nothing.

.LINK
Compress-Archive
#>
function Compress-Gerbers {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]$Path,
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$Name,
        [Parameter(Position = 2, Mandatory = $false)]
        [String]$DestinationPath = (Get-Item $Path).FullName,
        [Parameter(Position = 3, Mandatory = $false)]
        [Switch]$Clean
    )

    # Get the path to the current directory.
    $Path = (Get-Item $Path).FullName
    $DestinationFile = Join-Path -Path (Get-Item $DestinationPath).FullName -ChildPath "$Name.zip"

    # Get our precious gerbers.
    $Gerbers = Get-Item $Path\* |
               Where-Object { $_.FullName -Match "\.(g[bmpt]\w)|(dri)|(txt)$" }

    # Compress the package for manufacturing.
    Compress-Archive -Path $Gerbers -DestinationPath $DestinationFile -Force

    # Clean up the unpackaged Gerbers.
    If ($Clean -eq $true) {
        Remove-Item $Gerbers
    }
}