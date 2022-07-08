# Microsoft.PowerShell_profile.ps1
# Our PowerShell profile. Microsoft's equivalent to .bash_profile.
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
    Return "PS $(Get-PrettyPath)$('>' * ($nestedPromptLevel + 1)) ";
}

# Have a nice suggestions menu appear when we want to tab complete something.
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete

# Make sure we don't conflict with the proper wget command.
If (Test-Path Alias:wget) {
	Remove-Item Alias:wget
}

# Handy little alias to use as an alternative to bash's &
Function bg() {
    Start-Process -NoNewWindow @args
}

# Since we always want to start Emacs in the background...
Function emacs() {
	bg emacs @args
}
