Function Add-OneLoginApiEventLogSource {
    <#
        .DESCRIPTION
            Adds an Event Log source, for script/module logging. Adding an Event Log source requires administrative rights.
        .NOTES 
            Author: Mike Hashemi
            V1.0.0.0 date: 19 April 2017
                - Initial release.
            V1.0.0.1 date: 1 May 2017
                - Minor updates to status handling.
            V1.0.0.2 date: 4 May 2017
                - Added additional return value.
            V1.0.0.3 date: 22 May 2017
                - Changed output to reduce the number of "Write-Host" messages.
            V1.0.0.4 date: 21 June 2017
                - Fixed typo.
                - Significantly improved performance.
                - Changed logging.
            V1.0.0.5 date: 21 June 2017
                - Added a return value if the event log source exists.
            V1.0.0.6 date: 28 June 2017
                - Added [CmdletBinding()].
            V1.0.0.7 date: 28 June 2017
                - Added a check for the source, then a check on the status of the query.
            V1.0.0.8 date: 13 March 2018
                - Updated whitespace.
                - Updated output to only output status on 'verbose'.
            V1.0.0.9 date: 23 August 2019
        .PARAMETER EventLogSource
            Mandatory parameter. This parameter is used to specify the event source, that script/modules will use for logging.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        $EventLogSource
    )

    $message = ("{0}: Beginning {1}." -f [datetime]::Now, $MyInvocation.MyCommand)
    If ($PSBoundParameters['Verbose']) { Write-Verbose $message }

    # Check if $EventLogSource exists as a source. If the shell is not elevated and the check fails to access the Security log, assume the source does not exist.
    Try {
        $sourceExists = [System.Diagnostics.EventLog]::SourceExists("$EventLogSource")
    }
    Catch {
        $sourceExists = $False
    }

    If ($sourceExists -eq $False) {
        $message = ("{0}: The event source `"{1}`" does not exist. Prompting for elevation." -f [datetime]::Now, $EventLogSource)
        Write-Host $message -ForegroundColor White

        Try {
            Start-Process PowerShell -Verb RunAs -ArgumentList "New-EventLog -LogName Application -Source $EventLogSource -ErrorAction Stop"
        }
        Catch [System.InvalidOperationException] {
            $message = ("{0}: It appears that the user cancelled the operation." -f [datetime]::Now)
            Write-Host $message -ForegroundColor Yellow
            Return "Error"
        }
        Catch {
            $message = ("{0}: Unexpected error launching an elevated Powershell session. The specific error is: {1}" -f [datetime]::Now, $_.Exception.Message)
            Write-Host $message -ForegroundColor Red
            Return "Error"
        }

        Return "Success"
    }
    Else {
        $message = ("{0}: The event source `"{1}`" already exists. There is no action for {2} to take." -f [datetime]::Now, $EventLogSource, $MyInvocation.MyCommand)
        Write-Verbose $message

        Return "Success"
    }
} #1.0.0.9
Function Get-OneLoginApiUser {
    <#
        .DESCRIPTION
            Retrieve properties of one or more users (filtered based on ID, username, or samaccountname).
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 13 July 2021
                - Initial release
        .LINK
            https://github.com/wetling23/Public.OneLoginApi.PowerShellModule
        .PARAMETER AccessToken
            Represents a valid (not expired) OneLogin OATH token (https://developers.onelogin.com/api-docs/2/oauth20-tokens/generate-tokens-2).
        .PARAMETER Username
            Represents a user-specified list of OneLogin user names, for which to return the user objects. When excluded (and when ID/SamAccountName are not specified), all users will be returned.
        .PARAMETER Id
            Represents a user-specified list of OneLogin user IDs, for which to return the user objects. When excluded (and when Username/SamAccountName are not specified), all users will be returned.
        .PARAMETER SamAccountName
            Represents a user-specified list of OneLogin user names, for which to return the user objects. When excluded (and when Username/ID are not specified), all users will be returned.
        .PARAMETER QueryLimit
            Represents the maximum number of objects the API will return in a single call.
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-OneLoginApiUser -AccessToken <access token>

            Return all OneLogin users. Limited logging output will be written only to the host.
        .EXAMPLE
            PS C:\> Get-OneLoginApiUser -AccessToken <access token> -Username jsmith@domain.com

            Return the OneLogin users where the username is "jsmith@domain.com". Limited logging output will be written only to the host.
        .EXAMPLE
            PS C:\> Get-OneLoginApiUser -AccessToken <access token> -Id 34 -EventSource OneLoginScript

            Return the OneLogin users where the Id is "34". Limited logging output will be written to the event log and to the host.
        .EXAMPLE
            PS C:\> Get-OneLoginApiUser -AccessToken <access token> -SamAccountName jsmith -Verbose -LogPath C:\Temp\log.txt

            Return the OneLogin users where the samaccountname is "jsmith". Verbose logging output will be written to C:\Temp\log.txt and to the host.
    #>
    [CmdletBinding(DefaultParameterSetName = 'allusers')]
    param (
        [Parameter(Mandatory)]
        [securestring]$AccessToken,

        [Parameter(ParameterSetName = 'username')]
        [string[]]$Username,

        [Parameter(ParameterSetName = 'id')]
        [int[]]$Id,

        [Parameter(ParameterSetName = 'samaccountname')]
        [string[]]$SamAccountName,

        [int]$QueryLimit = 1000,

        [string]$EventLogSource,

        [string]$LogPath
    )

    $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    # Initialize variables.
    $page = 1
    $stopLoop = $false
    $users = [System.Collections.Generic.List[PSObject]]::new()
    [System.Net.ServicePointManager]::SecurityProtocol = ([System.Net.SecurityProtocolType]'Tls11,Tls12')
    $baseUrl = 'https://api.us.onelogin.com/api/2'
    $resourcePath = '/users'
    $httpVerb = "GET"
    $headers = @{
        "Authorization" = "bearer $([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken)))"
    }

    #region get a list of users - api v2 - ps v5.1
    Do {
        $queryParams = "?limit=$queryLimit&page=$page"

        $message = ("{0}: Getting page {1} of users." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $page)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        Try {
            $response = Invoke-RestMethod -Method $httpVerb -UseBasicParsing -Uri "$baseUrl$resourcePath$queryParams" -Headers $headers
        }
        Catch {
            $message = ("{0}: Unexpected error getting user. Error: {1}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $_.Exception.Message)
            If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

            Exit 1
        }

        $message = ("{0}: Adding {1} users to the list." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $response.Count)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $users.AddRange([System.Collections.Generic.List[PSObject]]@($response))

        $message = ("{0}: There are {1} users in `$users." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $users.Count)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        If ($response.Count -lt $queryLimit) {
            $stopLoop = $true
        }

        $page++
    }
    Until ($stopLoop -eq $true)
    #endregion get a list of users - api v2 - ps v5.1

    Switch ($PsCmdlet.ParameterSetName) {
        "allusers" { Continue }
        { $_ -in ("username", "id", "samaccountname") } {
            $message = ("{0}: Filtering users." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
        }
        "username" {
            $users = $users | Where-Object { $_.username -in $Username }
        }
        "id" {
            $users = $users | Where-Object { $_.id -in $Id }
        }
        "samaccountname" {
            $users = $users | Where-Object { $_.samaccountname -in $SamAccountName }
        }
    }

    $message = ("{0}: Returning {1} users." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $users.id.Count)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    $users

} #V1.0.0.0

Function New-OneLoginApiBearerToken {
    <#
        .DESCRIPTION
            Retrieve OneLogin OAUTH bearer access token. See https://developers.onelogin.com/api-docs/1/getting-started/working-with-api-credentials for authentication details.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 13 July 2021
                - Initial release
            V1.0.0.1 date: 22 July 2021
        .LINK
            https://github.com/wetling23/Public.OneLoginApi.PowerShellModule
        .PARAMETER ClientId
            Represents a API client ID, which exists in OneLogin.
        .PARAMETER ClientSecret
            Represents a API client secret, which exists in OneLogin.
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> New-OneLoginApiBearerToken -ClientID <client ID> -ClientSecret (<client secret> | ConvertTo-SecureString -AsPlainText -Force)

            Returns a bearer token with expiration date/time in the UTC time zone. Limited logging output is sent to the host only.
        .EXAMPLE
            PS C:\> New-OneLoginApiBearerToken -ClientID <client ID> -ClientSecret (<client secret> | ConvertTo-SecureString -AsPlainText -Force) -LogPath C:\Temp\log.txt -Verbose

            Returns a bearer token with expiration date/time in the UTC time zone. Limited logging output is sent to the host only. Verbose logging output is sent to the host and C:\Temp\log.txt
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$ClientId,

        [Parameter(Mandatory)]
        [securestring]$ClientSecret,

        [string]$EventLogSource,

        [string]$LogPath
    )

    $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    # Initialize variables.
    [System.Net.ServicePointManager]::SecurityProtocol = ([System.Net.SecurityProtocolType]'Tls11,Tls12')
    $baseUrl = 'https://api.us.onelogin.com'
    $resourcePath = '/auth/oauth2/v2/token'
    $httpVerb = "POST"
    $encodedCred = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(('{0}:{1}' -f $ClientId, ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret))))))
    $headers = @{
        'Authorization' = "Basic $encodedCred"
        'Content-Type'  = 'application/json'
    }
    $data = @{
        "grant_type" = "client_credentials"
    } | ConvertTo-Json

    #region generate oauth token
    $message = ("{0}: Generating bearer token." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    Try {
        $response = Invoke-RestMethod -Method $httpVerb -UseBasicParsing -Uri "$baseUrl$resourcePath" -Headers $headers -Body $data
    }
    Catch {
        $message = ("{0}: Unexpected error retrieving bearer token. Error: {1}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $_.Exception.Message)
        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

        Return "Error"
    }

    If ($response.'access_token'.Length -gt 1) {
        $message = ("{0}: Bearer token retrieved, adding expiration date property." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $response | Add-Member -MemberType NoteProperty -Name expires_at -Value ((Get-Date -Date $response.created_at).AddSeconds($($response.'expires_in'))).ToUniversalTime().ToString("yyyy-MM-dd`THH:mm:ss") -Force

        $response
    }
    Else {
        $message = ("{0}: No bearer token retrieved." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

        Return "Error"
    }
    #endregion generate oauth token
} #V1.0.0.1
Function Out-OneLoginApiPsLogging {
    <#
        .DESCRIPTION
            Logging function, for host, event log, or a log file.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 3 December 2019
                - Initial release.
            V1.0.0.1 date: 7 January 2020
            V1.0.0.2 date: 22 January 2020
            V1.0.0.3 date: 17 March 2020
            V1.0.0.4 date: 15 June 2020
            V1.0.0.5 date: 30 June 2020
            V1.0.0.6 date: 8 April 2021
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER EventLogSource
            Default parameter set. Represents the Windows Application log event source.
        .PARAMETER LogPath
            Path and file name of the target log file. If the file does not exist, the cmdlet will create it.
        .PARAMETER ScreenOnly
            When this switch parameter is included, the logging output is written only to the host.
        .PARAMETER Message
            Message to output.
        .PARAMETER MessageType
            Type of message to output. Valid values are "Info", "Warning", "Error", and "Verbose". When writing to a log file, all output is "info" but will be written to the host, with the appropriate message type.
        .PARAMETER BlockStdErr
            When set to $True, the cmdlet will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .EXAMPLE
            PS C:\> Out-PsLogging -Message "Test" -MessageType Info -LogPath C:\Temp\log.txt

            In this example, the message, "Test" will be written to the host and appended to C:\Temp\log.txt. If the path does not exist, or the user does not have write access, the message will only be written to the host.
        .EXAMPLE
            PS C:\> Out-PsLogging -Message "Test" -MessageType Warning -EventLogSource TestScript

            In this example, the message, "Test" will be written to the host and to the Windows Application log, as a warning and with the event log source/event ID "TestScript"/5417.
            If the event source does not exist and the session is elevated, the event source will be created.
            If the event source does not exist and the session is not elevated, the message will only be written to the host.
        .EXAMPLE
            PS C:\> Out-PsLogging -Message "Test" -MessageType Verbose -ScreenOnly

            In this example, the message, "Test" will be written to the host as a verbose message.
    #>
    [CmdletBinding(DefaultParameterSetName = 'SessionOnly')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'EventLog')]
        [string]$EventLogSource,

        [ValidateScript( {
                If (-NOT ($_ | Split-Path -Parent | Test-Path) ) {
                    Throw "Path does not exist."
                }
                If (-NOT ($_ | Test-Path) ) {
                    "" | Add-Content -Path $_
                }
                If (-NOT ($_ | Test-Path -PathType Leaf) ) {
                    Throw "The LogPath argument must be a file."
                }
                Return $true
            })]
        [Parameter(Mandatory, ParameterSetName = 'File')]
        [System.IO.FileInfo]$LogPath,

        [switch]$ScreenOnly,

        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter(Mandatory)]
        [ValidateSet('Info', 'Warning', 'Error', 'Verbose', 'First')]
        [string]$MessageType,

        [boolean]$BlockStdErr
    )

    # Initialize variables.
    $elevatedSession = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    If ($PsCmdlet.ParameterSetName -eq "EventLog") {
        If ([System.Diagnostics.EventLog]::SourceExists("$EventLogSource")) {
            # The event source does not exists, nothing else to do.

            $logType = "EventLog"
        }
        ElseIf (-NOT ([System.Diagnostics.EventLog]::SourceExists("$EventLogSource")) -and $elevatedSession) {
            # The event source does not exist, but the session is elevated, so create it.
            Try {
                New-EventLog -LogName Application -Source $EventLogSource -ErrorAction Stop

                $logType = "EventLog"
            }
            Catch {
                Write-Error ("{0}: Unable to create the event source ({1}). No logging will be done." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $EventLogSource)

                $logType = "SessionOnly"
            }
        }
        ElseIf (-NOT $elevatedSession) {
            # The event source does not exist, and the session is not elevated.
            Write-Error ("{0}: The event source ({1}) does not exist and the command was not run in an elevated session, unable to create the event source. No logging will be done." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $EventLogSource)

            $logType = "SessionOnly"
        }
    }
    ElseIf ($PsCmdlet.ParameterSetName -eq "File") {
        # Check if we have rights to the path in $LogPath.
        Try {
            [System.Io.File]::OpenWrite($LogPath).Close()
        }
        Catch {
            Write-Error ("{0}: Unable to write to the log file path ({1}). No logging will be done." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $LogPath)

            $logType = "SessionOnly"
        }

        $logType = "LogFile"
    }
    Else {
        $logType = "SessionOnly"
    }

    Switch ($logType) {
        "SessionOnly" {
            Switch ($MessageType) {
                "Info" { Write-Host $Message }
                "Warning" { Write-Warning $Message }
                "Error" { If ($BlockStdErr) { Write-Host $message -ForegroundColor Red } Else { Write-Error $Message } }
                "Verbose" { Write-Verbose $Message -Verbose }
                "First" { Write-Verbose $Message -Verbose }
            }
        }
        "EventLog" {
            Switch ($MessageType) {
                "Info" { Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $Message -EventId 5417; Write-Host $Message }
                "Warning" { Write-EventLog -LogName Application -Source $EventLogSource -EntryType Warning -Message $Message -EventId 5417; Write-Warning $Message }
                "Error" { Write-EventLog -LogName Application -Source $EventLogSource -EntryType Error -Message $Message -EventId 5417; If ($BlockStdErr) { Write-Host $message -ForegroundColor Red } Else { Write-Error $Message } }
                "Verbose" { Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $Message -EventId 5417; Write-Verbose $Message -Verbose }
                "First" { Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $Message -EventId 5417; Write-Verbose $Message -Verbose }
            }
            If ($BlockStdErr) {

            }
        }
        "LogFile" {
            Switch ($MessageType) {
                "Info" { [System.IO.File]::AppendAllLines([string]$LogPath, [string[]]$Message, [Text.Encoding]::Unicode); Write-Host $Message }
                "Warning" { [System.IO.File]::AppendAllLines([string]$LogPath, [string[]]$Message, [Text.Encoding]::Unicode); Write-Warning $Message }
                "Error" { [System.IO.File]::AppendAllLines([string]$LogPath, [string[]]$Message, [Text.Encoding]::Unicode); If ($BlockStdErr) { Write-Host $message -ForegroundColor Red } Else { Write-Error $Message } }
                "Verbose" { [System.IO.File]::AppendAllLines([string]$LogPath, [string[]]$Message, [Text.Encoding]::Unicode); Write-Verbose $Message -Verbose }
                "First" { [System.IO.File]::WriteAllLines($LogPath, $Message, [Text.Encoding]::Unicode); Write-Verbose $Message -Verbose }
            }
        }
    }
} #1.0.0.6

Function Update-OneLoginApiUserProperty {
    <#
        .DESCRIPTION
            Accepts a hashtable of user properties and user identifier (ID, username, or samaccountname) and updates the property(ies).
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 13 July 2021
                - Initial release
                - https://developers.onelogin.com/api-docs/1/users/update-user
        .LINK
            https://github.com/wetling23/Public.OneLoginApi.PowerShellModule
        .PARAMETER AccessToken
            Represents a valid (not expired) OneLogin OATH token (https://developers.onelogin.com/api-docs/2/oauth20-tokens/generate-tokens-2).
        .PARAMETER Username
            Represents a OneLogin user name, for a user to update. If provided, the command will query OneLogin to retrieve the ID.
        .PARAMETER Id
            Represents a OneLogin ID, for a user to update.
        .PARAMETER SamAccountName
            Represents a OneLogin samaccountname, for a user to update. If provided, the command will query OneLogin to retrieve the ID.
        .PARAMETER QueryLimit
            Represents the maximum number of objects the API will return in a single call.
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Update-OneLoginApiUser -AccessToken <access token> -Username jsmith@domain.com -Properties @{ "group_id" = 123 }

            Add the user "jsmith@synoptek.com" to the OneLogin group with ID 123. Note that the group_id property must be an integer (not enclosed in quotes). Limited logging output is written to the host only.
        .EXAMPLE
            PS C:\> Update-OneLoginApiUser -AccessToken <access token> -SamAccountName jsmith -Properties @{ "group_id" = '' }

            Remove the user "jsmith@synoptek.com" from the OneLogin group. Limited logging output is written to the host only.
        .EXAMPLE
            PS C:\> Update-OneLoginApiUser -AccessToken <access token> -Id 123456 -Properties @{ "notes" = "mike is great"; "group_id" = 123 } -Verbose -LogPath C:\Temp\log.txt

            Add the user "jsmith@synoptek.com" to the OneLogin group with ID 123 and add a note with the value, "mike is great". Note that the group_id property MUST be an integer (not enclosed in quotes) and the notes properties MUST be a string (enclosed in double quotes). Verbose logging will be written to C:\Temp\log.txt and written to the host.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [securestring]$AccessToken,

        [Parameter(Mandatory, ParameterSetName = 'username')]
        [string]$Username,

        [Parameter(Mandatory, ParameterSetName = 'id')]
        [int]$Id,

        [Parameter(Mandatory, ParameterSetName = 'samaccountname')]
        [string]$SamAccountName,

        [hashtable]$Properties,

        [string]$EventLogSource,

        [string]$LogPath
    )

    $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    #region Setup
    # Initialize variables.
    [System.Net.ServicePointManager]::SecurityProtocol = ([System.Net.SecurityProtocolType]'Tls11,Tls12')
    $errorState = 0
    $baseUrl = 'https://api.us.onelogin.com/api/1'
    $httpVerb = "PUT"
    $headers = @{
        "Authorization" = "bearer $([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken)))"
        "Content-Type"  = "application/json"
    }
    $body = $Properties | ConvertTo-Json -Depth 10

    # Setup parameters for splatting.
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') {
        If ($EventLogSource -and (-NOT $LogPath)) {
            $commandParams = @{
                Verbose        = $true
                EventLogSource = $EventLogSource
            }
        } ElseIf ($LogPath -and (-NOT $EventLogSource)) {
            $commandParams = @{
                Verbose = $true
                LogPath = $LogPath
            }
        } Else {
            $commandParams = @{
                Verbose = $true
            }
        }
    } Else {
        If ($EventLogSource -and (-NOT $LogPath)) {
            $commandParams = @{
                Verbose        = $False
                EventLogSource = $EventLogSource
            }
        } ElseIf ($LogPath -and (-NOT $EventLogSource)) {
            $commandParams = @{
                Verbose = $False
                LogPath = $LogPath
            }
        } Else {
            $commandParams = @{
                Verbose = $false
            }
        }
    }

    Switch ($PsCmdlet.ParameterSetName) {
        { $_ -in ("username", "samaccountname") } {
            $message = ("{0}: Attempting to retrieve user ID." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
        }
        "username" {
            $id = (Get-OneLoginApiUser -AccessToken $AccessToken -Username $Username @commandParams).id
        }
        "samaccountname" {
            $id = (Get-OneLoginApiUser -AccessToken $AccessToken -SamAccountName $SamAccountName @commandParams).id
        }
    }

    If ($id -as [int]) {
        $message = ("{0}: The user's ID is: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $id)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $resourcePath = "/users/{0}" -f $id
    }
    Else {
        $message = ("{0}: Unable to locate the user. {1} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

        Return "Error"
    }
    #endregion Setup

    $message = ("{0}: Attempting to update the user: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Id)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    Try {
        $response = Invoke-RestMethod -Method $httpVerb -UseBasicParsing -Uri "$baseUrl$resourcePath" -Headers $headers -Body $body -ErrorAction Stop
    }
    Catch {
        $message = ("{0}: Unexpected error updating user. If available, the body is:`r`n{1}`r`n`r`nError: {2}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), ($body | Out-String), $_.Exception.Message)
        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

        Return "Error"
    }

    If ($response.status.error -eq $false) {
        $message = ("{0}: Successfully updated the user." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
    }
    Else {
        $message = ("{0}: Failed to update user: {1}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $_.Exception.Message)
        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

        $message = ("{0}: If available, the following was returned:`r`n`tError: {1}`r`n`tCode: {2}`r`n`tType: {3}`r`n`tMessages: {4}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $response.status.error, $response.status.code, $response.status.type, $response.status.message)
        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

        $errorState = 1
    }

    If ($errorState -eq 1) {
        Return "Error"
    }
    Else {
        Return "Success"
    }
} #V1.0.0.0
Export-ModuleMember -Alias * -Function *
