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