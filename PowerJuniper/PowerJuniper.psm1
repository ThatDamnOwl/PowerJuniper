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

Function Get-JuniperVersioningInfo
{
    param
    (
        $Switches
    )

    $ReturnSwitches = @()

    foreach ($Switch in ($Switches[0..($Switches.count - 1)]))
    {
        Write-host $Switch.IPAddress
        $Software = $null
        $Hardware = $null
        $Session = $null
        $CredNo = 0
        do
        {
            try
            {
                $Session = New-SSHSession -ComputerName $Switch.IPAddress -Credential $Creds[$CredNo] -AcceptKey -ConnectionTimeout 10000 -OperationTimeout 10000 -ErrorAction SilentlyContinue
                if ($Session -ne $null)
                {
                    $ShellStream = new-sshshellstream -sessionid $Session.SessionId

                    if ($Creds[$CredNo].Username -eq "root")
                    {
                        $Ignore = Invoke-SSHStreamShellCommand -ShellStream $ShellStream -Command "cli"
                    }

                    $Software = Get-JuniperXML -Hostname $Switch.IPAddress -Session $Session -Query "show system software" -Verbose -CommandTimeout 10000
                    $Hardware = Get-JuniperXML -Hostname $Switch.IpAddress -Session $Session -Query "show chassis hardware" -Verbose -CommandTimeout 10000
                }
                else
                {
                Write-Verbose "Credential set $CredNo failed to auth"
                }
            }
            catch
            {

            }
            $CredNo++

        }
        while (($Session -eq $null) -and ($CredNo -lt $Creds.count))

        if ($Session -ne $null)
        {
            $Ignore = $Session | Remove-SSHSession
        }

        Write-Verbose "Softwarae Queried - $($Software -ne $null)"
        Write-Verbose "Hardware Queried - $($Hardware -ne $null)"
        $ReturnSwitches += [pscustomobject]@{"IpAddress" = $Switch.IPAddress
          "software" = $Software
          "hardware" = $Hardware
          "credinc" = $CredNo}

    }

    Return $ReturnSwitches
}

Function Compare-JuniperVersioningInfoToJTAC
{
    param
    (
        $Switches,
        $SwitchVersions
    )
    foreach ($Switch in $Switches)
    {
        if ($Switch.hardware -ne $null)
        {
            $JTACVerion = $null
            $Inc = 0
            do
            {
                if ($Switch.hardware."chassis-inventory".chassis.description -match $SwitchVersions[$Inc].Model)
                {
                    $JTACVersion = $SwitchVersions[$Inc]
                }
                $Inc++
            }
            while (($JTACVerion -eq $null) -and ($Inc -lt $SwitchVersions.count))

            $Ignore = $Switch.software.junos -match "([^/]*)/junos$"

            $ChassisDescription = $Switch.hardware."chassis-inventory".chassis.description
            $CurrentVersion = $Matches[1]
            $JTACSuggestedVersion = $JTACVersion."OS Version"
            $VersionsMatch = $CurrentVersion -match [regex]::Escape($JTACSuggestedVersion)
        }
        $Switch | Add-Member -Type NoteProperty -name Model -Value $ChassisDescription -force
        $Switch | Add-Member -Type NoteProperty -name CurrentVersion -Value $CurrentVersion -force
        $Switch | Add-Member -Type NoteProperty -name JTACVersion -Value $JTACSuggestedVersion -force
        $Switch | Add-Member -Type NoteProperty -name MatchesJTACVersion -Value $VersionsMatch -force

    }

    return $Switches
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
        $CommandTimeout = 10000,
        [Parameter(Mandatory=$false)]
        [int]
        $ConnectTimeout = 10000
    )  
    if (($Hostname -eq "") -and ($Session -ne $null))
    {
        $Hostname = $Session.host    
    }

    Write-Verbose "Starting juniper xml query on $Hostname"

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

    if ($TempSession = (($Session -eq $null) -or (($Session.Host -ne $Hostname) -and ($Hostname -ne "") -and ($Session.connected))))
    {
        Write-Verbose "No Session has been provided, generating one"
        $Session = New-JuniperSSHSession -Credential $Credential `
                                         -Credentials $Credentials `
                                         -Hostname $Hostname `
                                         -ConnectTimeout $ConnectTimeout `
                                         -CommandTimeout $CommandTimeout `
                                         -ErrorAction SilentlyContinue 

    }

    if ($Session)
    {
        Write-Debug "Starting to query device with query $Query | display xml | no-more"
        $TrimLines = 0
        $ShellStream = New-JuniperSSHShellStream -Session $Session

        $Out = @(invoke-sshstreamshellcommand -shellstream $ShellStream -Command "$Query | display xml | no-more" -promppattern "\{master.0\}" -CommandTimeout $CommandTimeout)

        ##$Out.GetType() | write-Host

        $ReadingXML = $false
        $OutputXML = @()

        foreach ($Line in $Out)
        {
            if ($Line -match "rpc-reply")
            {
                $ReadingXML = -not $ReadingXML
            }
            if ($ReadingXML -or ($Line -match "rpc-reply"))
            {
                $OutputXML += $Line
            }
        }

        Write-Debug "Total lines of XML $($OutputXML.count)"

        $XMLOutput = ([xml]$OutputXML)

        if ($XMLOutput -ne $null)
        {
            $XMLOutput | Add-Member -type NoteProperty -name RawOut -Value $Out
        }
        else
        {
            $OutputXML | Write-Debug
            #$XMLOutput = @{RawOut = $Out}    
        }
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

Function New-JuniperSSHSession
{
    param
    (
        $Credential,
        [Object[]]
        $Credentials,
        $Hostname,
        $ConnectTimeout = 10000,
        $CommandTimeout = 10000,
        $ErrorAction = "SilentlyContinue"
    )

    if ($Credentials -ne $null)
    {
        Write-Verbose "Multiple credentials provided"
        foreach ($CredentialObject in $Credentials)
        {
            Write-Debug "Attempting with $($CredentialObject.username)"
            $Result = New-JuniperSSHSession -HostName $Hostname `
                                            -Credential $CredentialObject `
                                            -CommandTimeout $CommandTimeout `
                                            -ConnectTimeout $ConnectTimeout `
                                            -ErrorAction $ErrorAction

            if ($Result -ne $null)
            {
                return $Result
            }
        }

        return $null
    }

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
    Write-Verbose "Checking that $Hostname is online"
    if (Test-HostStatus $Hostname)
    {
        Write-Verbose "$Hostname is online"
        $Session = New-SSHSession -ComputerName $Hostname `
                                  -Credential $Credential `
                                  -AcceptKey `
                                  -ConnectionTimeout $ConnectTimeout `
                                  -OperationTimeout $CommandTimeout `
                                  -ErrorAction $ErrorAction
        if ($Session)
        {
            $Session | Add-Member -Type NoteProperty -Name CredentialUsed -Value $Credential
        }
    }
    else
    {
        Write-Verbose "$Hostname is offline"    
    }

    return $Session
}

Function New-JuniperSSHShellStream
{
    param
    (
        $Session
    )

    $ShellStream = new-sshshellstream -sessionid $Session.SessionId

    if ($Session.CredentialUsed.Username -eq "root")
    {
        $Ignore = invoke-sshstreamshellcommand -shellstream $ShellStream -command "cli"
    }

    return $ShellStream
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
        $CommandTimeout = 10000
    )
    return (Get-JuniperXML -Session $Session -Credential $Credential -Hostname $Hostname -Query "show chassis hardware" -Hostnames:$Hostnames -Credentials:$Credentials -CommandTimeout $CommandTimeout)
}

Function Get-JuniperSoftwareInfo
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
        $CommandTimeout = 10000
    )
    return (Get-JuniperXML -Session $Session -Credential $Credential -Hostname $Hostname -Query "show system software" -Hostnames:$Hostnames -Credentials:$Credentials -CommandTimeout $CommandTimeout)
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
        $CommandTimeout = 10000
    )
    return (Get-JuniperXML -Session $Session -Credential $Credential -Hostname $Hostname -Query "show lldp neighbors" -Hostnames:$Hostnames -Credentials:$Credentials -CommandTimeout $CommandTimeout)
}

Function Get-JuniperLLDPLocalInformation
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
        $CommandTimeout = 10000
    )
    return (Get-JuniperXML -Session $Session -Credential $Credential -Hostname $Hostname -Query "show lldp local-information" -Hostnames:$Hostnames -Credentials:$Credentials -CommandTimeout $CommandTimeout)
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
        $CommandTimeout = 10000
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
        $CommandTimeout = 10000
    )
    return (Get-JuniperXML -Session $Session -Credential $Credential -Hostname $Hostname -Query "show bgp neighbor" -Hostnames:$Hostnames -Credentials:$Credentials -CommandTimeout $CommandTimeout)
}

Function Get-JuniperSpanningTreeInterfaces
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
        $CommandTimeout = 10000
    )
    return (Get-JuniperXML -Session $Session -Credential $Credential -Hostname $Hostname -Query "show spanning-tree interface" -Hostnames:$Hostnames -Credentials:$Credentials -CommandTimeout $CommandTimeout)
}

Function Get-JuniperARPTable
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
        $CommandTimeout = 50000
    )
    return (Get-JuniperXML -Session $Session -Credential $Credential -Hostname $Hostname -Query "show arp" -Hostnames:$Hostnames -Credentials:$Credentials -CommandTimeout $CommandTimeout)
}

Function Get-JuniperRouteInfoCSV
{
    param
    (
        [Parameter(Mandatory=$true)]
        [SSH.SshSession]
        $Session
    )

    $Routes = Get-JuniperRouteInfo -Session $Session
    $Peers = Get-JuniperBGPPeers -Session $Session
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

Function Invoke-JuniperInfoPull
{
    param
    (
        $TargetSwitchIP,
        $Credential = $null,
        [Object[]]
        $Credentials
    )


    $Session = New-JuniperSSHSession -Hostname $TargetSwitchIP `
                                     -Credential $Credential `
                                     -Credentials $Credentials

    if ($Session -ne $null)
    {
        $Object = [pscustomobject]@{
            IP = $TargetSwitchIP
            JuniperSoftwareInfo = (Get-JuniperSoftwareInfo -Session $Session)
            JuniperHardwareInfo = (Get-JuniperHardwareInfo -Session $Session)
            JuniperLLDPNeighbors = (Get-JuniperLLDPNeighbors -Session $Session)
            JuniperLLDPLocalInformation = (Get-JuniperLLDPLocalInformation -Session $Session)
            JuniperRouteInfo = (Get-JuniperRouteInfo -Session $Session)
            JuniperBGPPeers = (Get-JuniperBGPPeers -Session $Session)
            JuniperSpanningTreeInterfaces = (Get-JuniperSpanningTreeInterfaces -Session $Session)
            JuniperARPTable = (Get-JuniperARPTable -Session $Session)
        }
    }

    return $Object
}

Function Invoke-JuniperTreeExplore
{
    param
    (
        [Object]
        $CurrentNode,
        [Object[]]
        $AllNodes,
        [Object[]]
        $ExploredNodes
    )

    if ($ExploredNodes -eq $null)
    {
        $ExploredNodes = @()
    }

    $ChassisID = $CurrentNode.JuniperLLDPLocalInformation.'lldp-local-info'.'lldp-local-chassis-id'

    foreach ($Node in $CurrentNode.JuniperLLDPNeighbors.'lldp-neighbors-information'.'lldp-neighbor-information')
    {
        Write-Verbose "Investigating chassis $($Node.'lldp-remote-chassis-id')"
        $ChildNode = $null
        $ChildNode = $AllNodes | where {$_.JuniperLLDPLocalInformation.'lldp-local-info'.'lldp-local-chassis-id' -eq $Node.'lldp-remote-chassis-id'} |
                                 where {$_.JuniperLLDPLocalInformation.'lldp-local-info'.'lldp-local-chassis-id' -notin $ExploredNodes.ChassisID}
        if ($ChildNode -ne $null)
        {
            Write-Verbose "chassis $($Node.'lldp-remote-chassis-id') is not part of the currently explored tree"
            $ChildNode | Add-Member -type NoteProperty -name ChassisID -Value $ChildNode.JuniperLLDPLocalInformation.'lldp-local-info'.'lldp-local-chassis-id' -force
            if ($ChildNode.RootSwitch -eq $null)
            {

                $ChildNode | Add-Member -type NoteProperty -name RootSwitch -Value $ChassisID -force
            }
            
            $ExploredNodes += $ChildNode

            $ChildNodes = $null
            $ChildNodes = $ChildNode.JuniperLLDPNeighbors.'lldp-neighbors-information'.'lldp-neighbor-information' | 
                                        where {$_.'lldp-remote-chassis-id' -notin $ExploredNodes.ChassisID}
            if ($ChildNodes -ne $null)
            {
                Write-Verbose "chassis $($Node.'lldp-remote-chassis-id') has child nodes"
                foreach ($NextChildNode in $ChildNodes)
                {
                    $NodeInfo = $AllNodes | where {$_.JuniperLLDPLocalInformation.'lldp-local-info'.'lldp-local-chassis-id' -eq $NextChildNode.'lldp-remote-chassis-id'}
                    $ExploredNodes = Invoke-JuniperTreeExplore $NodeInfo $AllNodes $ExploredNodes                
                }
            }
        }
    }

    return $ExploredNodes
}



