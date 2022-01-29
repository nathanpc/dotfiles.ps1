# ProgrammingUtilities.psm1
# A set of nice utilities to help us in our programming tasks.
#
# Author: Nathan Campos <nathan@innoveworkshop.com>

<#
.SYNOPSIS
Creates a nice banner to separate sections in very long C/C++ source code.

.DESCRIPTION
Creates a nice banner to separate sections in very long C/C++ source code.

.PARAMETER Title
Title of the section of code to put centered in the banner.

.PARAMETER Columns
Number of columns to use in order to generate the banner.

.PARAMETER CommentToken
Token used by the programming language to denote a comment.

.INPUTS
Title of the section of code.

.OUTPUTS
Nice banner with the title centered in the middle
#>
function Write-CodeSectionBanner {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline, Position = 0, Mandatory = $true)]
        [String]$Title,
        [Parameter(Position = 1, Mandatory = $false)]
        [Int]$Columns = 80,
        [Parameter(Position = 2, Mandatory = $false)]
        [String]$CommentToken = "//"
    )

    # Some internal variables.
    $Buffer = ""
    $LateralLength = $CommentToken.Length * 2
    $TokenRepeat = [Math]::Floor($Columns / $CommentToken.Length)
    $LeftSpace = [Math]::Floor(($Columns - $LateralLength - $Title.Length) / 2)
    $RightSpace = $LeftSpace

    # Check if we need to add an extra character to a specific side.
    If (($LateralLength + $LeftSpace + $RightSpace + $Title.Length) -lt $Columns) {
        $RightSpace++
    }

    # Create the header of the banner.
    For ($i = 0; $i -lt $TokenRepeat; $i++) {
        $Buffer += $CommentToken
    }
    $Buffer += "`r`n" + $CommentToken
    For ($i = 0; $i -lt ($Columns - $LateralLength); $i++) {
        $Buffer += " "
    }
    $Buffer += $CommentToken + "`r`n"

    # Create the title part of the banner.
    $Buffer += $CommentToken
    For ($i = 0; $i -lt $LeftSpace; $i++) {
        $Buffer += " "
    }
    $Buffer += $Title
    For ($i = 0; $i -lt $RightSpace; $i++) {
        $Buffer += " "
    }
    $Buffer += $CommentToken

    # Create the footer of the banner.
    $Buffer += "`r`n" + $CommentToken
    For ($i = 0; $i -lt ($Columns - $LateralLength); $i++) {
        $Buffer += " "
    }
    $Buffer += $CommentToken + "`r`n"
    For ($i = 0; $i -lt $TokenRepeat; $i++) {
        $Buffer += $CommentToken
    }

    # Show the finalized string.
    Write-Output $Buffer
}
