# Set-ADComputersDNSAliases.ps1
# Creates aliases for all Active Directory computers under a domain that's
# different from the AD one.
#
# Author: Nathan Campos <nathan@innoveworkshop.com>

# Script parameters.
Param(
    [Parameter(Mandatory = $false)]
    [String]$ZoneName = "farm.lan",
    [Parameter(Mandatory = $false)]
    [String]$Server = "CLOUDBERRY"
)

# Get the AD computers.
[Microsoft.ActiveDirectory.Management.ADAccount[]]$Computers =
    (Get-ADComputer -Filter * -Properties IPv4Address)

# Iterate through the available computers.
foreach ($Computer in $Computers) {
    # Ignore computers without an IP address.
    if (!$Computer.IPv4Address) {
        continue;
    }

    # Check if we should add a new record or update an existing one.
    [Microsoft.DnsClient.Commands.DnsRecord]$ExistingRecord = Resolve-DnsName `
        -Name "$($Computer.Name.ToLower()).$ZoneName" -Server "CLOUDBERRY"
    if ($ExistingRecord.Name -eq "$($Computer.Name.ToLower()).$ZoneName") {
        # Update record.
        if ($ExistingRecord.IPAddress -ne $Computer.IPv4Address) {
            # Get the existing record.
            $OldRecord = Get-DnsServerResourceRecord -Name $Computer.Name.ToLower() `
                -ZoneName $ZoneName -ComputerName $Server

            # If we got a zone, then just grab the @ record.
            if ($OldRecord -is [array]) {
                $OldRecord = $OldRecord[0]
            }

            # Change the IP address of the record.
            $NewRecord = $OldRecord.Clone()
            $NewRecord.RecordData.IPv4Address = $Computer.IPv4Address
            Set-DnsServerResourceRecord -NewInputObject $NewRecord -OldInputObject $OldRecord `
                -ZoneName $ZoneName -ComputerName $Server

            Write-Host ("[UPDATE] $($Computer.Name.ToLower()).$ZoneName -> {0}" -f `
                "$($ExistingRecord.IPAddress) -> $($Computer.IPv4Address)")
        }
    } else {
        # New record!
        Add-DnsServerResourceRecordA -Name $Computer.Name.ToLower() -ZoneName $ZoneName `
            -AllowUpdateAny -IPv4Address $Computer.IPv4Address -ComputerName $Server

        Write-Host "[NEW] $($Computer.Name.ToLower()).$ZoneName -> $($Computer.IPv4Address)"
    }
}
