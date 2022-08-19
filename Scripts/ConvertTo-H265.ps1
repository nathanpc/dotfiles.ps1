# ConvertTo-H265.ps1
# Converts MOV files to use the H.265 codec.
#
# Author: Nathan Campos <nathan@innoveworkshop.com>

# Script parameters.
Param(
    [Parameter(Mandatory = $false)]
    [String]$Path = ".\",
    [Switch]$Clean = $false,
    [Switch]$SkipConvert = $false
)

# Go through MOV files.
Get-ChildItem $Path -Filter *.mov | ForEach-Object {
    # Get the input and output file paths.
    $InFile = $_.FullName
    $OutFile = [IO.Path]::ChangeExtension($InFile, "mp4")
    
    # Actually perform the conversion.
    If (!$SkipConvert) {
        Write-Output "Converting $($_.Name)"
        ffmpeg -i "$InFile" -c:v libx265 -vtag hvc1 -c:a aac -b:a 160k "$OutFile"
    }

    # Remove the old file.
    If ($Clean) {
        Write-Output "Removing $($_.Name)"
        Remove-Item $InFile
    }
}

Write-Output "Done."
