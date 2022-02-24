# Set-ADComputersDNSAliases.ps1
# Creates aliases for all Active Directory computers under a domain that's
# different from the AD one. This script is non-destructive and won't mess
# with any DNS entries that aren't related to specific AD computers.
#
# Author: Nathan Campos <nathan@innoveworkshop.com>

# Script parameters.
Param(
    [Parameter(Mandatory = $false)]
    [String]$ADServer = "CLOUDBERRY",
    [Parameter(Mandatory = $false)]
    [String]$DNSServer = "CLOUDBERRY",
    [Parameter(Mandatory = $false)]
    [String]$ZoneName = "farm.lan"
)

<#
.SYNOPSIS
Adds a new DNS entry to the to the specified server. If it already exists its
IP address just gets updated.

.PARAMETER ComputerName
DNS server name.

.PARAMETER Name
Name of the DNS entry that will be prepended to the DNS Zone.

.PARAMETER ZoneName
DNS Zone of the entry you are trying to edit.

.PARAMETER IPAddress
IP address to be associated with this entry.
#>
Function Add-DNSEntryOrSetIfExisting {
    Param(
        [Parameter(Mandatory = $true)]
        [String]$ComputerName,
        [Parameter(Mandatory = $true)]
        [String]$Name,
        [Parameter(Mandatory = $true)]
        [String]$ZoneName,
        [Parameter(Mandatory = $true)]
        [IPAddress]$IPAddress
    )

    # FQDN.
    $FullName = "$Name.$ZoneName"

    # Check if we should add a new record or update an existing one.
    [Microsoft.DnsClient.Commands.DnsRecord]$ExistingRecord = Resolve-DnsName `
        -Name $FullName -Server $ComputerName
    if ($ExistingRecord.Name -eq $FullName) {
        # Update record.
        if ($ExistingRecord.IPAddress -eq $IPAddress) {
            # Looks like there's nothing to update here.
            Write-Host "[SKIPPED]`t $FullName `t`t $($ExistingRecord.IPAddress)"
            Return
        }

        # Get the existing record.
        $OldRecord = Get-DnsServerResourceRecord -Name $Name `
            -ZoneName $ZoneName -ComputerName $ComputerName

        # If we got a zone, then just grab the @ record.
        if ($OldRecord -is [array]) {
            $OldRecord = $OldRecord[0]
        }

        # Change the IP address of the record.
        $NewRecord = $OldRecord.Clone()
        $NewRecord.RecordData.IPv4Address = $IPAddress
        Set-DnsServerResourceRecord -NewInputObject $NewRecord `
            -OldInputObject $OldRecord -ZoneName $ZoneName -ComputerName $ComputerName

        Write-Host ("[UPDATE]`t $FullName `t`t {0}" -f `
            "$($ExistingRecord.IPAddress) -> $($Computer.IPv4Address)")
    } else {
        # New record!
        Add-DnsServerResourceRecordA -Name $Name -ZoneName $ZoneName `
            -AllowUpdateAny -IPv4Address $IPAddress -ComputerName $ComputerName

        Write-Host "[NEW]`t $FullName `t`t $IPAddress"
    }
}

<#
.SYNOPSIS
Goes through the AD computers adding/updating their entries in the DNS server.

.PARAMETER ADServer
Active Directory server.

.PARAMETER DNSServer
DNS server.

.PARAMETER ZoneName
DNS Zone that'll be used as the basis for the entries.
#>
Function Set-ADComputersDNSAliases {
    Param(
        [Parameter(Mandatory = $true)]
        [String]$ADServer,
        [Parameter(Mandatory = $true)]
        [String]$DNSServer,
        [Parameter(Mandatory = $true)]
        [String]$ZoneName
    )

    # Get AD computers.
    [Microsoft.ActiveDirectory.Management.ADAccount[]]$Computers =
        (Get-ADComputer -Filter * -Properties IPv4Address -Server $ADServer)

    # Iterate through the available computers.
    foreach ($Computer in $Computers) {
        # Ignore computers without an IP address.
        if (!$Computer.IPv4Address) {
            continue;
        }

        # Add or set the DNS entry for the computer.
        Add-DNSEntryOrSetIfExisting -ComputerName $DNSServer -ZoneName $ZoneName `
            -Name $Computer.Name.ToLower() -IPAddress $Computer.IPv4Address
    }
}

# Go for it.
Set-ADComputersDNSAliases -ADServer $ADServer -DNSServer $DNSServer -ZoneName $ZoneName
