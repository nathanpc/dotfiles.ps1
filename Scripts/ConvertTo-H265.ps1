# ConvertTo-H265.ps1
# Converts MOV files to use the H.265 codec.
#
# Author: Nathan Campos <nathan@innoveworkshop.com>

# Script parameters.
Param(
    [Parameter(Mandatory = $false)]
    [String]$Path = ".\",
    [Parameter(Mandatory = $false)]
    [String]$DestPath = ".\",
    [Switch]$Clean = $false,
    [Switch]$SkipConvert = $false,
    [Parameter(Mandatory = $false)]
    [String]$SourceExt = "mov",
    [Parameter(Mandatory = $false)]
    [String]$DestExt = "mp4"
)

# Go through MOV files.
Get-ChildItem $Path -Filter "*.$SourceExt" | ForEach-Object {
    # Get the input and output file paths.
    $InFile = $_.FullName
    $OutFile = [IO.Path]::ChangeExtension((Join-Path -Path $DestPath -ChildPath $_.Name), $DestExt)
    
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
