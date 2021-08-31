Function Get-OneLoginApiEvent {
    <#
        .DESCRIPTION
            Accept various filters and returns matching events.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 31 August 2021
                - Initial release
        .LINK
            https://github.com/wetling23/Public.OneLoginApi.PowerShellModule
        .PARAMETER AccessToken
            Represents a valid (not expired), secure string OneLogin OATH token (https://developers.onelogin.com/api-docs/2/oauth20-tokens/generate-tokens-2).
        .PARAMETER Username
            Represents a OneLogin user name, for which to return matching events. When excluded, events for all users will be returned.
        .PARAMETER UserId
            Represents a OneLogin user ID, for which to return matching events. When excluded, events for all users will be returned.
        .PARAMETER EventTypeId
            Event type ID, for which to search. When ommitted, all events are returned. Only a single event type ID is allowed per call. For a list of event type IDs, see https://developers.onelogin.com/api-docs/1/events/event-resource.
        .PARAMETER Since
            Date/time, representing the beginning of the search period. When ommitted, events will be returned, back to the maximuim retention date.
        .PARAMETER Until
            Date/time, representing the end of the search period. When ommitted, events will be returned to the current date/time.
        .PARAMETER ClientId
            Represents the ID of the desired OneLogin client.
        .PARAMETER DirectoryId
            Represents the ID of the desired OneLogin directory.
        .PARAMETER EventId
            Represents the ID of the a specific OneLogin event.
        .PARAMETER Resolution
            Represents the value of the desired event resolution.
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-OneLoginApiEvent -AccessToken <access token>

            In this example, the command will return the maximum number of OneLogin events. Limited output logging will be written only to the host.
        .EXAMPLE
            PS C:\> Get-OneLoginApiEvent -AccessToken <access token> -Username user@domain.com -Since 01-01-2020 -Until 01-02-2020T20:00Z -Verbose

            In this example, the command will return all OneLogin events for user@domain.com, which occurred between 01-01-2020 and 01-02-2020 at 20:00 Zulu. Verbose output logging will be written only to the host.
        .EXAMPLE
            PS C:\> Get-OneLoginApiEvent -AccessToken <access token> -UserId 12345 -Since 01-01-2020 -LogPath C:\Temp\log.txt

            In this example, the command will return all OneLogin events for the user with ID 12345, which occurred between 01-01-2020 and the current date. Limited output logging will be written to the host and C:\Temp\log.txt.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [securestring]$AccessToken,

        [string]$Username,

        [int]$EventTypeId,

        [datetime]$Since,

        [datetime]$Until,

        [int]$UserId,

        [int]$ClientId,

        [int]$DirectoryId,

        [int]$EventId,

        [string]$Resolution,

        [string]$EventLogSource,

        [string]$LogPath
    )

    $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    #region Setup
    # Initialize variables.
    $events = [System.Collections.Generic.List[PSObject]]::new()
    [System.Net.ServicePointManager]::SecurityProtocol = ([System.Net.SecurityProtocolType]'Tls11,Tls12')
    $baseUrl = 'https://api.us.onelogin.com/api/1'
    $resourcePath = '/events'
    $httpVerb = "GET"
    $queryLimit = 50 # As of 30 August 2021, the maximum items returned by a call to this endpoint is 50. Chaninging this value higher results in HTTP 400.
    $headers = @{
        "Authorization" = "bearer $([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken)))"
    }

    # Setup parameters for log splatting.
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
        }
        Else {
            $commandParams = @{
                Verbose = $false
            }
        }
    }
    #endregion Setup

    #region Generate URL
    $message = ("{0}: Generating URL filters." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    If ($Username) {
        $message = ("{0}: Attempting to retrieve the ID of {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Username)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $user = Get-OneLoginApiUser -AccessToken $AccessToken -Username $Username @commandParams

        If ($user.id) {
            $UserId = $user.id
        }
        Else {
            $message = ("{0}: User, {1} not found, skipping user filter." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Warning -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Warning -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Warning -Message $message }
        }
    }

    If ($ClientId) {
        $clientIdFilter = 'client_id={0}' -f $ClientId
    } Else {
        $clientIdFilter = 'client_id='
    }

    If ($DirectoryId) {
        $directoryFilter = 'directory_id={0}' -f $DirectoryId
    } Else {
        $directoryFilter = 'directory_id='
    }

    If ($EventId) {
        $eventIdFilter = 'id={0}' -f $EventId
    } Else {
        $eventIdFilter = 'id='
    }

    If ($Resolution) {
        $resolutionFilter = 'resolution={0}' -f $Resolution
    } Else {
        $resolutionFilter = 'resolution='
    }

    If ($UserId) {
        $userIdFilter = 'user_id={0}' -f $UserId
    } Else {
        $userIdFilter = 'user_id='
    }

    If ($Since) {
        $sinceFilter = 'since={0}' -f (([DateTime]$Since).ToUniversalTime()).ToString("yyyy-MM-dd`THH:mm:ssZ")
    }
    Else {
        $sinceFilter = 'since='
    }

    If ($Until) {
        $untilFilter = 'until={0}' -f (([DateTime]$Until).ToUniversalTime()).ToString("yyyy-MM-dd`THH:mm:ssZ")
    }
    Else {
        $untilFilter = 'until='
    }

    If ($EventTypeId) {
        $eventTypeIdFilter = 'event_type_id={0}' -f $EventTypeId
    }
    Else {
        $eventTypeIdFilter = 'event_type_id='
    }

    $queryParams = "?$eventTypeIdFilter&$sinceFilter&$untilFilter&$clientIdFilter&$directoryFilter&$eventIdFilter&$resolutionFilter&$userIdFilter&limit=$queryLimit"
    $url = "$baseUrl$resourcePath$queryParams"

    $message = ("{0}: The URL is: {1}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $url)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
    #endregion Generate URL

    #region get list of events - api v1
    Do {
        $message = ("{0}: Getting a page of events." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        Try {
            $response = Invoke-RestMethod -Method $httpVerb -UseBasicParsing -Uri $url -Headers $headers
        }
        Catch {
            $message = ("{0}: Unexpected error getting user. Error: {1}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $_.Exception.Message)
            If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

            Exit 1
        }

        $message = ("{0}: Adding {1} events to the list." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $response.data.Count)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $events.AddRange([System.Collections.Generic.List[PSObject]]@($response.data))

        $message = ("{0}: There are {1} events in `$events." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $events.Count)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $url = $response.pagination.next_link
    }
    Until ($response.pagination.next_link -eq $null)
    #endregion get list of events - api v1

    $message = ("{0}: Returning {1} events." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $events.id.Count)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    $events
} #V1.0.0.0