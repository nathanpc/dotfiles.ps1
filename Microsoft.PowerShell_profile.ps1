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

# We sure love our symbolic links from Unixland...
Function ln() {
    Param(
        [Parameter(Mandatory = $true)]
        [String]$Target,
        [Parameter(Mandatory = $true)]
        [String]$Path
    )

    New-Item -ItemType SymbolicLink -Path $Path -Target $Target
}

<#
.SYNOPSIS
Converts any integer to its hexadecimal representation in a string.

.PARAMETER Number
Integer that we wish to convert.

.OUTPUTS
Hexadecimal representation of the number in a string.
#>
Function ToHex() {
    Param(
        [Int64]$Number
    )

    "0x{0:X2}" -f $Number
}

<#
.SYNOPSIS
Converts any integer to its binary representation in a string.

.PARAMETER Number
Integer that we wish to convert.

.OUTPUTS
Binary representation of the number in a string.
#>
Function ToBin() {
    Param(
        [Int64]$Number
    )

    "0b" + [System.Convert]::ToString($Number, 2)
}
