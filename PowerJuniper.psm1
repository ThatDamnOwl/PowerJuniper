#Imports
$OldVerbose = $VerbosePreference
$VerbosePreference = "SilentlyContinue"

Import-module Posh-SSH -force -verbose:$False -ErrorAction SilentlyContinue
Import-module CommonFunctions -force -verbose:$False -ErrorAction SilentlyContinue

if (-not (Test-Path C:\Temp))
{
    new-item C:\Temp -itemtype Directory
}

if (-not (Test-Path C:\Temp\NetworkTools))
{
    new-item C:\Temp\NetworkTools -itemtype Directory
}

$VerbosePreference = $OldVerbose

#Constants
$MaxConcurrentSessions = 50
$BasicServicePorts = @(21,22,25,80,443,445,4444,8080,8443)



Function Format-JuniperJson
{
    param
    (
        [string[]]
        $json
    )

    $tofs = $tofs

    $ofs = "`n"

    $newJson = @()
    for ($lineNo = 0; [int]$lineNo -lt ([int]$json.count); $lineNo++)
    {
        $line = $json[$lineNo]
        if ($removingLines)
        {
            $removingLines = $removingLines -and (-not ($line -match "]"))
        }
        else {
            if ($line -match "\[")
            {
                $lineName = $line -replace "\s*""([^""]*)"" : \[",'$1'
                $readAhead = $json[($lineNo + 2)]
                if ($readAhead -match """data"" : ")
                {
                    $removingLines = $true
                    $newJson += $readAhead -replace "data",$lineName
                }
                else {
                    $newJson += $Line
                }
            }
            else {
                $newJson += $Line
            }            
        }
    }

    for ($lineNo = 0; $lineNo -lt ($newJson.count - 1); $lineNo++)
    {
        if ($newJson[$lineNo] -match """" -and $newJson[$lineNo + 1] -match """")
        {
            $newJson[$lineNo] = "$($newJson[$lineNo])," -replace ", ,",","
        }
    }
    return $newJson
}

Function Get-JuniperXML
{
    param
    (
        [Parameter(Mandatory=$false)]
        [string]
        $Hostname,
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PsCredential]
        $Credential,
        [Parameter(Mandatory=$false)]
        [SSH.SshSession]
        $Session,
        [Parameter(Mandatory=$false)]
        [string]
        $Query,
        [Parameter(Mandatory=$false)]
        [string[]]
        $Hostnames,
        [Parameter(Mandatory=$false)]
        [Object[]]
        $Credentials,
        [Parameter(Mandatory=$false)]
        [int]
        $CommandTimeout = 2000
    )  

    Write-Verbose "Starting juniper xml query"

    if ($Hostnames -ne $null)
    {
        Write-Verbose "Multiple hostnames provided"
        foreach ($Hostname in $Hostnames)
        {
            Write-Debug "Attempting to connect to $Hostname"
            $Result = Get-JuniperXML -Hostname $Hostname -Credential $Credential -Session $Session -Query $Query -Credentials:$Credentials -CommandTimeout $CommandTimeout 

            if ($Result -ne $null)
            {
                return $Result
            }
        }

        return $null
    }

    if ($Credentials -ne $null)
    {
        Write-Verbose "Multiple credentials provided"
        foreach ($CredentialObject in $Credentials)
        {
            Write-Debug "Attempting with $($CredentialObject.username)"
            $Result = Get-JuniperXML -HostName $Hostname -Credential $CredentialObject -Session $Session -Query $Query -CommandTimeout $CommandTimeout 

            if ($Result -ne $null)
            {
                return $Result
            }
        }

        return $null
    }

    if ($TempSession = (($Session -eq $null) -or (($Session.Host -ne $Hostname) -and ($Hostname -ne "") -and ($Session.connected))))
    {
        if (-not $Credential)
        {
            write-Host "Please Enter the credentials for this switch"
            $Credential = Get-Credential
        }

        if (-not $Hostname -and $Session)
        {
            $Hostname = $Session.Host
        }
        elseif (-not $Hostname) {
            write-Host "Please Enter the host you'd like to query"
            $Hostname = read-host
        }

        if (Test-HostStatus $Hostname)
        {
            $Session = New-SSHSession -ComputerName $Hostname -Credential $Credential -AcceptKey -ErrorAction SilentlyContinue
        }
    }

    if ($Session)
    {
        Write-Debug "Starting to query device with query $Query | display xml | no-more"
        $TrimLines = 0
        $ShellStream = new-sshshellstream -sessionid $Session.SessionId
        if ($Creds.Username -eq "root")
        {
            $Ignore = invoke-sshstreamshellcommand -shellstream $ShellStream -command "cli"
        }

        $Out = @(invoke-sshstreamshellcommand -shellstream $ShellStream -Command "$Query | display xml | no-more" -promppattern "\{master.0\}" -CommandTimeout $CommandTimeout)

        ##$Out.GetType() | write-Host
        
        Write-Debug "Total lines returned $($Out.count)"

        $XMLOut = $Out | where {$_ -match "<"}
        
        Write-Debug "Total lines of XML $($XMLOut.count)"

        if ($XMLOut.count -eq 0)
        {
            $Out | Write-Debug
        }

        $XMLOutput = ([xml]$XMLOut).'rpc-reply'
    }
    else {
       Write-Host "Failed to connect to $Hostname"
       return $null
    }

    if ($TempSession)
    {
        $ignore = Remove-SSHSession -SessionId $Session.SessionId
    }
    #write-verbose $TempSession
    return $XMLOutput
}

Function Get-JuniperHardwareInfo
{
    param
    (
        [Parameter(Mandatory=$false)]
        [string]$Hostname,
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PsCredential]
        $Credential,
        [Parameter(Mandatory=$false)]
        [SSH.SshSession]
        $Session,
        [Parameter(Mandatory=$false)]
        [string[]]
        $Hostnames,
        [Parameter(Mandatory=$false)]
        [Object[]]
        $Credentials,
        [Parameter(Mandatory=$false)]
        [int]
        $CommandTimeout = 2000
    )
    return (Get-JuniperXML -Session $Session -Credential $Credential -Hostname $Hostname -Query "show chassis hardware" -Hostnames:$Hostnames -Credentials:$Credentials -CommandTimeout $CommandTimeout)
}

Function Get-JuniperLLDPNeighbors
{
    param
    (
        [Parameter(Mandatory=$false)]
        [string]$Hostname,
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PsCredential]
        $Credential,
        [Parameter(Mandatory=$false)]
        [SSH.SshSession]
        $Session,
        [Parameter(Mandatory=$false)]
        [string[]]
        $Hostnames,
        [Parameter(Mandatory=$false)]
        [Object[]]
        $Credentials,
        [Parameter(Mandatory=$false)]
        [int]
        $CommandTimeout = 2000
    )
    return (Get-JuniperXML -Session $Session -Credential $Credential -Hostname $Hostname -Query "show lldp neighbors" -Hostnames:$Hostnames -Credentials:$Credentials -CommandTimeout $CommandTimeout)
}

Function Get-JuniperRouteInfo
{
    param
    (
        [Parameter(Mandatory=$false)]
        [string]$Hostname,
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PsCredential]
        $Credential,
        [Parameter(Mandatory=$false)]
        [SSH.SshSession]
        $Session,
        [Parameter(Mandatory=$false)]
        [string[]]
        $Hostnames,
        [Parameter(Mandatory=$false)]
        [Object[]]
        $Credentials,
        [Parameter(Mandatory=$false)]
        [int]
        $CommandTimeout = 2000
    )
    return (Get-JuniperXML -Session $Session -Credential $Credential -Hostname $Hostname -Query "show route" -Hostnames:$Hostnames -Credentials:$Credentials -CommandTimeout $CommandTimeout)
}

Function Get-JuniperBGPPeers
{
    param
    (
        [Parameter(Mandatory=$false)]
        [string]$Hostname,
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PsCredential]
        $Credential,
        [Parameter(Mandatory=$false)]
        [SSH.SshSession]
        $Session,
        [Parameter(Mandatory=$false)]
        [string[]]
        $Hostnames,
        [Parameter(Mandatory=$false)]
        [Object[]]
        $Credentials,
        [Parameter(Mandatory=$false)]
        [int]
        $CommandTimeout = 2000
    )
    return (Get-JuniperXML -Session $Session -Credential $Credential -Hostname $Hostname -Query "show bgp neighbor" -Hostnames:$Hostnames -Credentials:$Credentials -CommandTimeout $CommandTimeout)
}

Function Get-JuniperRouteInfoCSV
{
    param
    (
        [Parameter(Mandatory=$true)]
        [SSH.SshSession]
        $Session
    )

    $Routes = Get-RouteInfo -Session $Session
    $Peers = Get-BGPPeers -Session $Session
    "RouterIP,LocalID,RemoteID,Route,ASN,Next-Hop,Active"
    foreach ($Route in $Routes.'route-information'.'route-table'.rt)
    {
        $RTEntries = $Route.'rt-entry'
        foreach ($RTEntry in $RTEntries)
        {
            $RouteASNs = $RTEntry.'as-path' -replace "[ ]{2,}"," " -split " " | where {$_ -match "\S" } | where{$_ -match "\d{1,}"}
            if($RTEntry.'protocol-name' -eq 'Static')
            {
                "$($Session.Host),,,$($Route.'rt-destination'),,$($RTEntry.nh.to)"
            }
            elseif ($RTEntry.'protocol-name' -eq 'BGP')
            {
                foreach ($ASN in $RouteASNs)
                {
                    $PeerInfo = $peers.'bgp-information'.'bgp-peer' | where {$_.'peer-as' -match $ASN}
                    "$($Session.Host),$($PeerInfo.'local-id'),$($PeerInfo.'peer-id'),$($Route.'rt-destination'),$($ASN),$($RTEntry.nh.to),$($RTEntry.'active-tag' -eq "*")"
                }
            }
            elseif ($RTEntry.'protocol-name' -in @("local","direct"))
            {
                
            }
            else {
                Write-Host "unknown Routing protocol - $($RTEntry.'protocol-name')"
            }
        }
    }
}





