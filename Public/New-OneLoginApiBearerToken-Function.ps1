
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