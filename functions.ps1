# functions.ps1
# Some handy functions to use everywhere.
#
# Author: Nathan Campos <nathan@innoveworkshop.com>

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
