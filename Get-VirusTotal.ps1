#============================== Get VirusTotal Commands ==============================#
function Get-VirusTotalCommands {     
    Write-Host " "
    Write-Host "================= ================= ================="
    Write-Host " "
    Write-Host "Below are the VirusTotal Commands." -ForegroundColor Green
    
    Write-Host "
    1. Get-VirusTotalIP
    2. Get-VirusTotalDomain
    3. Get-VirusTotalUrl
    4. Submit-VirusTotalUrl
    5. Get-VirusTotalFile"

    Write-Host "
    You must Sign in to Virus Total to get your FREE API Key" -ForegroundColor Red
    Write-Host " "

    Write-Host "Get help with Get-Help command, e.g." -ForegroundColor Yellow
    Write-host "
    Get-Help Get-VirusTotalIP"

    Write-Host " "
    Write-Host "Get examples with below command" -ForegroundColor Yellow
    Write-host "
    Get-Help Get-VirusTotalIP -Examples
    Get-Help Get-VirusTotalDomain -Examples
    Get-Help Get-VirusTotalUrl -Examples
    Get-Help Submit-VirusTotalUrl -Examples
    Get-Help Get-VirusTotalFile -Examples"
    Write-Host " "
    Write-Host "================= Created by Haridas Vhadade - 24-Jan-2023 ================="
    Write-Host " "
}

#============================== Get VirusTotal IP ==============================#
function Get-VirusTotalIP {
    <#
.SYNOPSIS
Get IP Reputation Details from Virus Total Site

.Description
Created by Haridas Vhadade.
Date - 19-Jan-2023

.Example
Get-VirusTotalIP -VT_APIKEY "xkksdfkskxkdjkld" -IP "8.8.8.8"

.Example
Get-VirusTotalIP -VT_APIKEY "xkksdfkskxkdjkld" -IP_TextFile c:\temp\ip_list.txt

Create a text file with One IP at each line and save it. e.g.
8.8.8.8
1.1.1.1

.Example
Get IP Reputation and save report to file.

Get-VirusTotalIP -VT_APIKEY "xkksdfkskxkdjkld" -IP_TextFile c:\temp\ip_list.txt | Export-Csv -NoTypeInformation -Path c:\temp\ip_report.csv

#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$IP,
        [Parameter(Mandatory = $false)]
        [string]$IP_TextFile,
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [String]$VT_APIKEY    
    )   

    if ($ip_textfile) {
        try {
            $IP_list = Get-Content $ip_textfile        
        }
        catch {
            Write-Host "$_.Exception.Message"
            break
        }        
    }
    elseif ($IP) {
        $IP_list = $IP
    }
    else {
        Write-Host "You must either provide IP or text file with ip list" -ForegroundColor Red
        Exit;
    }
                      
    #Get vt url and ip result
    $vt_ip_url = "https://www.virustotal.com/api/v3/ip_addresses/"

    $headers = @{    
        "Accept"   = "application/json"
        "x-apikey" = $VT_APIKEY
    }

    $vt_ip_report = @()

    foreach ( $ip in $IP_list ) {
        write-host working on $ip -ForegroundColor Green
        $url = $vt_ip_url + $IP 
            
        $virusTotalResult = ""
        $virusTotalResult = Invoke-RestMethod -Uri $url -Method 'Get'  -Headers $headers

        if (!$virusTotalResult) {
            $ip_report = [PSCustomObject]@{
                IP         = $IP
                country    = "Failed to get Data"
                as_owner   = ""
                harmless   = ""
                malicious  = ""
                suspicious = ""
                undetected = ""
            }
        }
        else {
            $ip_report = [PSCustomObject]@{
                IP         = $IP
                country    = $virusTotalResult.data.attributes.country
                as_owner   = $virusTotalResult.data.attributes.as_owner
                harmless   = $virusTotalResult.data.attributes.last_analysis_stats.harmless
                malicious  = $virusTotalResult.data.attributes.last_analysis_stats.malicious
                suspicious = $virusTotalResult.data.attributes.last_analysis_stats.suspicious
                undetected = $virusTotalResult.data.attributes.last_analysis_stats.undetected
            }
        }
        $vt_ip_report += $ip_report
    }
    return $vt_ip_report
}
   

#======================= Get-VirusTotalDomain ==================#
function Get-VirusTotalDomain {
    <#
.SYNOPSIS
Get Domain Reputation Details from Virus Total Site
You need to Sign Up at Virus Total and get the API Key.

.Description
Created by Haridas Vhadade.
Date - 19-Jan-2023

.Example
Get-VirusTotalDomain -VT_APIKEY "xkksdfkskxkdjkld" -Domain "Google.com"

.Example
Get-VirusTotalDomain -VT_APIKEY "xkksdfkskxkdjkld" -Domain_TextFile c:\temp\domain_list.txt

Create a text file with domain name on each line. e.g.
google.com
yahoo.com

.Example
Get Domain Reputation from Virus Total and save report to file

Get-VirusTotalDomain -VT_APIKEY "xkksdfkskxkdjkld" -Domain_TextFile c:\temp\domain_list.txt | Export-Csv -NoTypeInformation -Path c:\temp\domain_report.csv

#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$Domain_TextFile,
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [String]$VT_APIKEY    
    )   

    if ($Domain_TextFile) {
        try {
            $Domain_list = Get-Content $Domain_TextFile        
        }
        catch {
            Write-Host "$_.Exception.Message"
            break
        }        
    }
    elseif ($Domain) {
        $Domain_list = $Domain
    }
    else {
        Write-Host "You must either provide Domain or text file with Domain list" -ForegroundColor Red
        Exit;
    }
    
    $vt_domain_url = "https://www.virustotal.com/api/v3/domains/"

    $headers = @{    
        "Accept"   = "application/json"
        "x-apikey" = $VT_APIKEY
    }

    $vt_domain_report = @()

    foreach ( $Domain in $Domain_list ) {
        write-host working on $Domain -ForegroundColor Green
        $url = $vt_domain_url + $Domain 

        $virusTotalResult = ""
        $virusTotalResult = Invoke-RestMethod -Uri $url -Method 'Get'  -Headers $headers
            
        if (!$virusTotalResult) {
            $domain_report = [PSCustomObject]@{
                Domain        = $domain
                harmless      = "Failed to get data"
                malicious     = ""
                suspicious    = ""
                undetected    = ""
                category      = ""
                creation_date = ""
                whois_date    = ""
                whois         = ""
            } 
        }
        else {
            $domain_report = [PSCustomObject]@{
                Domain        = $domain
                harmless      = $virusTotalResult.data.attributes.last_analysis_stats.harmless
                malicious     = $virusTotalResult.data.attributes.last_analysis_stats.malicious
                suspicious    = $virusTotalResult.data.attributes.last_analysis_stats.suspicious
                undetected    = $virusTotalResult.data.attributes.last_analysis_stats.undetected
                category      = $virustotalResult.data.attributes.categories.'alphaMountain.ai'
                creation_date = (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($virustotalResult.data.attributes.creation_date))
                whois_date    = (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($virustotalResult.data.attributes.whois_date))
                whois         = $virustotalResult.data.attributes.whois    
            }
        }
        $vt_domain_report += $domain_report            
    }
    return $vt_domain_report       
}

#======================= Get-VirusTotalUrl ==================#
function Get-VirusTotalUrl {
    <#
.SYNOPSIS
Get Website URL Reputation Details from Virus Total Site.
You need to Sign Up at Virus Total and get the API Key.

.Description
Created by Haridas Vhadade.
Date - 19-Jan-2023

.Example
Get-VirusTotalUrl -VT_APIKEY "xkksdfkskxkdjkld" -Url_Address "https://google.com"

.Example
Get-VirusTotalUrl -VT_APIKEY "xkksdfkskxkdjkld" -Url_TextFile c:\temp\url_list.txt

Create a text file with website urls on each line e.g.
https://google.com
https://yahoo.com

.Example
Get URL reputation from Virus Total and save report to file.

Get-VirusTotalUrl -VT_APIKEY "xkksdfkskxkdjkld" -Url_TextFile c:\temp\url_list.txt  | Export-Csv -NoTypeInformation -Path c:\temp\url_report.csv

.Notes

.Link
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Url_Address,
        [Parameter(Mandatory = $false)]
        [string]$Url_TextFile,
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [String]$VT_APIKEY    
    )   

    if ($Url_TextFile) {
        try {
            $url_list = Get-Content $Url_TextFile        
        }
        catch {
            Write-Host "$_.Exception.Message"
            break
        }        
    }
    elseif ($Url_Address) {
        $url_list = $Url_Address
    }
    else {
        Write-Host "You must either provide Domain or text file with website url list" -ForegroundColor Red
        Exit;
    }
                      
    #Get vt url and ip result        
    $vt_url_url = "https://www.virustotal.com/api/v3/urls"

    $headers = @{    
        "Accept"   = "application/json"
        "x-apikey" = $VT_APIKEY            
    }

    $vt_url_report = @()

    foreach ( $url_address in $url_list ) {
        write-host working on $url_address -ForegroundColor Green
            
        $Bytes = [Text.Encoding]::UTF8.GetBytes($url_address)
        $base64url = ([Convert]::ToBase64String($Bytes)).split("=")

        $url = $vt_url_url + "/" + $base64url
        $virusTotalResult = ""    
        $virusTotalResult = Invoke-RestMethod -Uri $url -Method GET -Headers $headers
        
        if (!$virusTotalResult) {
            $url_report = [PSCustomObject]@{
                url                = $virusTotalResult.data.attributes.url
                harmless           = "Failed to get data"
                malicious          = ""
                suspicious         = ""
                undetected         = ""
                category           = ""
                last_analysis_date = ""
                title              = ""
            }
        }
        else {
            $url_report = [PSCustomObject]@{
                url                = $virusTotalResult.data.attributes.url
                harmless           = $virusTotalResult.data.attributes.last_analysis_stats.harmless
                malicious          = $virusTotalResult.data.attributes.last_analysis_stats.malicious
                suspicious         = $virusTotalResult.data.attributes.last_analysis_stats.suspicious
                undetected         = $virusTotalResult.data.attributes.last_analysis_stats.undetected        
                category           = $virustotalResult.data.attributes.categories.'alphaMountain.ai'    
                last_analysis_date = (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($virustotalResult.data.attributes.last_analysis_date))      
                title              = $virusTotalResult.data.attributes.title
            }
        }
        $vt_url_report += $url_report            
    }
    return $vt_url_report  
}

#======================= Submit-VirusTotalUrl ==================#
function Submit-VirusTotalUrl {
    <#
.SYNOPSIS
Submit Website URL for scanning with Virus Total Site.
You need to Sign Up at Virus Total and get the API Key.

.Description
Created by Haridas Vhadade.
Date - 19-Jan-2023

.Example
Submit-VirusTotalUrl -VT_APIKEY "xkksdfkskxkdjkld" -Url_Address "https://google.com"

.Example
Submit-VirusTotalUrl -VT_APIKEY "xkksdfkskxkdjkld" -Url_TextFile c:\temp\url_list.txt

Create a text file with website urls on each line e.g.
https://google.com
https://yahoo.com

.Notes

.Link
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Url_Address,
        [Parameter(Mandatory = $false)]
        [string]$Url_TextFile,
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [String]$VT_APIKEY    
    )   

    if ($Url_TextFile) {
        try {
            $url_list = Get-Content $Url_TextFile        
        }
        catch {
            Write-Host "$_.Exception.Message"
            break
        }        
    }
    elseif ($Url_Address) {
        $url_list = $Url_Address
    }
    else {
        Write-Host "You must either provide website url or text file with website url list" -ForegroundColor Red
        Exit;
    }

                       
    #Get vt url and ip result        
    $vt_url_url = "https://www.virustotal.com/api/v3/urls"

    $headers = @{    
        "Accept"       = "application/json"
        "x-apikey"     = $VT_APIKEY
        "content-type" = "application/x-www-form-urlencoded" 
    }

    $vt_url_report = @()

    foreach ( $url_address in $url_list ) {
        write-host working on $url_address -ForegroundColor Green
                        
        #Submit url to vt for scan
        $url = $vt_url_url
        $Form = @{ 'url' = $url_address }
        $virusTotalResult = ""                                    
        $virusTotalResult = Invoke-RestMethod -Uri $url -Method POST -Headers $headers -ContentType 'application/x-www-form-urlencoded' -Body $Form
        
        if (!$virusTotalResult) {
            $url_report = [PSCustomObject]@{
                url  = $url_address
                type = "Failed to Submit URL"
                id   = ""             
            }
        }
        else {
            $url_report = [PSCustomObject]@{
                url  = $url_address
                type = $virusTotalResult.data.type
                id   = $virusTotalResult.data.id              
            }
        }
        $vt_url_report += $url_report            
    }
    return $vt_url_report     
}

#============================== Get VirusTotal File ==============================#
function Get-VirusTotalFile {
    <#
.SYNOPSIS
Get File Reputation Details from Virus Total Site

.Description
Created by Haridas Vhadade.
Date - 19-Jan-2023

.Example
Get-VirusTotalFile -VT_APIKEY "xkksdfkskxkdjkld" -FileHash "sdfasdfasd34534fsdf"

.Example
Get-VirusTotalFile -VT_APIKEY "xkksdfkskxkdjkld" -FileHash_list c:\temp\FileHash_list.txt

Create a text file with One IP at each line and save it. e.g.
sdfasdfasd34534fsdfsdtfhg
sdfasdfasd34534fsdfsdfasd

.Example
Get File reputation from Virus Total and save report to file.
Get-VirusTotalFile -VT_APIKEY "xkksdfkskxkdjkld" -FileHash_list c:\temp\FileHash_list.txt | Export-Csv -NoTypeInformation -Path c:\temp\ip_report.csv

#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$FileHash,
        [Parameter(Mandatory = $false)]
        [string]$FileHash_TextFile,
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [String]$VT_APIKEY    
    )   

    if ($FileHash_TextFile) {
        try {
            $FileHash_list = Get-Content $FileHash_TextFile        
        }
        catch {
            Write-Host "$_.Exception.Message"
            break
        }        
    }
    elseif ($FileHash) {
        $FileHash_list = $FileHash
    }
    else {
        Write-Host "You must either provide File Hash or text file with File Hash" -ForegroundColor Red
        Exit;
    }
                      
    #Get vt url and ip result
    $vt_ip_url = "https://www.virustotal.com/api/v3/files/"

    $headers = @{    
        "Accept"   = "application/json"
        "x-apikey" = $VT_APIKEY
    }

    $file_hash_report = @()

    foreach ( $FileHash in $FileHash_list ) {
        write-host working on $FileHash -ForegroundColor Green
        $url = $vt_ip_url + $FileHash 
        Write-Host this is the url $url -ForegroundColor Yellow
        
        $virusTotalResult = ""        
        $virusTotalResult = Invoke-RestMethod -Uri $url -Method 'Get'  -Headers $headers
               
        if (!$virusTotalResult) {            
            write-host "Failed to get data from url" -ForegroundColor Red
            $filehash_report = [PSCustomObject]@{
                FileHash           = $FileHash
                meaningful_name    = "Failed to Get Data"
                type_description   = ""
                last_analysis_date = ""
                harmless           = ""
                malicious          = ""
                suspicious         = ""
                undetected         = ""
                sha256             = ""
                sha1               = ""
                md5                = ""
                fileSizeKB         = ""
            }            
        }
        else {            
            $filehash_report = [PSCustomObject]@{
                FileHash           = $FileHash
                meaningful_name    = $virusTotalResult.data.attributes.meaningful_name
                type_description   = $virusTotalResult.data.attributes.type_description
                last_analysis_date = (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($virusTotalResult.data.attributes.last_analysis_date))
                harmless           = $virusTotalResult.data.attributes.last_analysis_stats.harmless
                malicious          = $virusTotalResult.data.attributes.last_analysis_stats.malicious
                suspicious         = $virusTotalResult.data.attributes.last_analysis_stats.suspicious
                undetected         = $virusTotalResult.data.attributes.last_analysis_stats.undetected
                sha256             = $virusTotalResult.data.attributes.sha256
                sha1               = $virusTotalResult.data.attributes.sha1
                md5                = $virusTotalResult.data.attributes.md5
                fileSizeKB         = ($virusTotalResult.data.attributes.size / 1KB)                
            }            
        }
        $file_hash_report += $filehash_report        
    }
    return $file_hash_report
}


#======================= ======================= ==================#
#Clear-Host
Get-VirusTotalCommands
