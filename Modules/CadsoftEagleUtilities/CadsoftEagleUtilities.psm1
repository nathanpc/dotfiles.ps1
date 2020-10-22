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
    param(
        [Parameter(ValueFromPipeline, Position = 0, Mandatory = $true)]
        [String[]]$Path
    )

    # Get all the files with extensions like .s#1, .b#2, and deletes them.
    Get-ChildItem $Path\* | 
        Where-Object { $_.FullName -match "\.\w#\d$" } |
        Remove-Item
}