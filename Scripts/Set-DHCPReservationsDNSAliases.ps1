# Set-DHCPReservationsDNSAliases.ps1
# Creates aliases for all DHCP reservations so that everyone of them can have
# a FQDN in the network. This script is non-destructive and won't mess with
# any DNS entries that aren't related to reservations.
#
# Author: Nathan Campos <nathan@innoveworkshop.com>

# Script parameters.
Param(
    [Parameter(Mandatory = $false)]
    [String]$DHCPServer = "CLOUDBERRY",
    [Parameter(Mandatory = $false)]
    [String]$DNSServer = "CLOUDBERRY",
    [Parameter(Mandatory = $false)]
    [IPAddress]$ScopeId = "192.168.1.0",
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
            "$($ExistingRecord.IPAddress) `t`t $IPAddress")
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

.PARAMETER DHCPServer
DHCP server.

.PARAMETER DNSServer
DNS server.

.PARAMETER ZoneName
DNS Zone that'll be used as the basis for the entries.

.PARAMETER ScopeId
DHCP server scope ID.
#>
Function Set-DHCPReservationsDNSAliases {
    Param(
        [Parameter(Mandatory = $true)]
        [String]$DHCPServer,
        [Parameter(Mandatory = $true)]
        [String]$DNSServer,
        [Parameter(Mandatory = $true)]
        [String]$ZoneName,
        [Parameter(Mandatory = $true)]
        [IPAddress]$ScopeId
    )

    # Get DHCP reservations.
    [Microsoft.Management.Infrastructure.CimInstance[]]$Reservations =
        (Get-DhcpServerv4Reservation -ComputerName $DHCPServer -ScopeId $ScopeId)

    # Iterate through the reservations.
    foreach ($Reservation in $Reservations) {
        # Normalize the reservation name.
        $Name = $Reservation.Name
        $Name = $Name.Replace(".$((Get-ADDomain).DNSRoot)", "")
        $Name = $Name.ToLower().Trim() -replace '[^A-Za-z0-9\-]'

        # Add or set the DNS entry for the computer.
        Add-DNSEntryOrSetIfExisting -ComputerName $DNSServer -ZoneName $ZoneName `
            -Name $Name -IPAddress $Reservation.IPAddress
    }
}

# Go for it.
Set-DHCPReservationsDNSAliases -DHCPServer $DHCPServer -DNSServer $DNSServer `
    -ZoneName $ZoneName -ScopeId $ScopeId
