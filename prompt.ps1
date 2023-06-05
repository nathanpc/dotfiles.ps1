# prompt.ps1
# Gives us a more usable prompt.
#
# Author: Nathan Campos <nathan@innoveworkshop.com>

<#
.SYNOPSIS
Converts an ugly path into a pretty, and hopefully shorter, one. Great for a
prompt.

.PARAMETER Path
Path that we want to prettify.

.OUTPUTS
Hopefully prettified path.
#>
Function Get-PrettyPath() {
    Param(
        [Parameter(Mandatory = $false)]
        [String]$Path = $executionContext.SessionState.Path.CurrentLocation.Path
    )

    # Check if our path is relative to the user's home directory.
    If ($Path.StartsWith($Home)) {
        Return $Path.Replace($Home, "~")
    }

    # Check if our path is an UNC path.
    If ($Path.StartsWith("Microsoft.PowerShell.Core\FileSystem::")) {
        Return $Path.Replace("Microsoft.PowerShell.Core\FileSystem::", "")
    }

    # Well, looks like we can't make this one pretty.
    Return $Path
}

<#
.SYNOPSIS
The prompt string that we are so familiar with.

.OUTPUTS
A pretty prompt string.
#>
Function prompt() {
    $Status = $?
    $Path = Get-PrettyPath
    $PS1 = ""

    # Color codes.
    $ESC    = [char]27
    $Reset  = "$ESC[0m"
    $Red    = "$ESC[31m"
    $Yellow = "$ESC[33m"
    $Cyan   = "$ESC[36m"

    # Build up the prompt
    $PS1 += If ($Status) { $Cyan } Else { $Red }
    $PS1 += "PS${Reset} "
    $PS1 += "${Yellow}${Path}"
    $PS1 += If ($Path.StartsWith("\\")) { $Red } Else { $Reset }
    $PS1 += "$('>' * ($nestedPromptLevel + 1))${Reset} "

    Return $PS1;
}
