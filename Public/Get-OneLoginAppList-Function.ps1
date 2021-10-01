Function Get-OneLoginAppList {
    <#
        .DESCRIPTION
            Returns apps configured in OneLogin.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 1 October 2021
                - Initial release
        .LINK
            https://github.com/wetling23/Public.OneLoginApi.PowerShellModule
        .PARAMETER AccessToken
            Represents a valid (not expired), secure string OneLogin OATH token (https://developers.onelogin.com/api-docs/2/oauth20-tokens/generate-tokens-2).
        .PARAMETER Username
            Represents a OneLogin user name, for which to return matching events. When excluded, events for all users will be returned.
        .PARAMETER AuthMethod
            Represents a OneLogin authentication method value. Valid options are: Password, OpenId, Saml, Api, Google, Forms, WsFed, and OpenIdConnect. Note that this value is not the same as "auth_method_description".
        .PARAMETER Name
            Represents the name of the desired application.
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-OneLoginApiEvent -AccessToken <access token> -Name <app name> -Verbose

            In this example, the command will get all instances of apps called "<app name>". Verbose logging output will be written only to the host.
        .EXAMPLE
            PS C:\> Get-OneLoginApiEvent -AccessToken <access token> -Name <app name>* -LogPath C:\Temp\log.txt

            In this example, the command will get all instances of apps matching <app name>*, where "*" is a wildcard. Limited logging output will be written to C:\Temp\log.txt
        .EXAMPLE
            PS C:\> Get-OneLoginApiEvent -AccessToken <access token> -AuthMethod Password

            In this example, the command will get all instances of apps with auth_method "Password". Limited logging output will be written only to the host.
        .EXAMPLE
            PS C:\> Get-OneLoginApiEvent -AccessToken <access token> -Name <app name> -AuthMethod Password

            In this example, the command will get all instances of apps with auth_method "Password" and called "<app name>". Limited logging output will be written only to the host.
    #>
    [CmdletBinding(DefaultParameterSetName = 'NoFilter')]
    param (
        [Parameter(Mandatory)]
        [securestring]$AccessToken,

        [ValidateSet('Password', 'OpenId', 'Saml', 'Api', 'Google', 'Forms', 'WsFed', 'OpenIdConnect')]
        [string]$AuthMethod,

        [string]$Name,

        [string]$EventLogSource,

        [string]$LogPath
    )

    $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    #region Setup
    # Initialize variables.
    $apps = [System.Collections.Generic.List[PSObject]]::new()
    [System.Net.ServicePointManager]::SecurityProtocol = ([System.Net.SecurityProtocolType]'Tls11,Tls12')
    $baseUrl = 'https://api.us.onelogin.com/api/2'
    $resourcePath = '/apps'
    $httpVerb = "GET"
    $page = 1
    $queryLimit = 1000 # As of 1 October 2021, the maximum items returned by a call to this endpoint is 1000. Chaninging this value higher results in HTTP 400.
    $queryFilter = $null
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
    $message = ("{0}: Generating URL filter." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    If ($AuthMethod) {
        Switch ($AuthMethod) {
            "Password" { $queryFilter = "auth_method=0" }
            "OpenId" { $queryFilter = "auth_method=1" }
            "Saml" { $queryFilter = "auth_method=2" }
            "Api" { $queryFilter = "auth_method=3" }
            "Google" { $queryFilter = "auth_method=4" }
            "Forms" { $queryFilter = "auth_method=6" }
            "Wsfed" { $queryFilter = "auth_method=7" }
            "OpenIdConnect" { $queryFilter = "auth_method=8" }
        }
    }

    If ($Name) {
        If ($queryFilter) {
            $queryFilter += "&name=$Name"
        }
        Else {
            $queryFilter = "name=$Name"
        }
    }

    $message = ("{0}: The URL is: {1}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), "$baseUrl$resourcePath$queryParams")
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
    #endregion Generate URL

    #region get all apps - api v2 - ps v7
    Do {
        $message = ("{0}: Getting page {1} of apps." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $page)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        If ($queryFilter) {
            $queryParams = "?$queryFilter&limit=$queryLimit&page=$page"
        }
        Else {
            $queryParams = "?limit=$queryLimit&page=$page"
        }

        Try {
            $response = Invoke-RestMethod -Method $httpVerb -UseBasicParsing -Uri "$baseUrl$resourcePath$queryParams" -Headers $headers -ResponseHeadersVariable responseHead -ErrorAction Stop
        }
        Catch {
            $message = ("{0}: Unexpected error getting apps. The specific error is: {1}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $_.Exception.Message)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr } }

            Return "Error"
        }

        $message = ("{0}: There are {1} pages of apps. Adding this batch to the list." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $page)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $apps.AddRange([System.Collections.Generic.List[PSObject]]@($response))

        $message = ("{0}: There are {1} apps in `$apps." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $apps.id.Count)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $page++
    }
    While ($apps.Count -ne ($responseHead.'Total-Count').Trim())
    #endregion get all apps - api v2 - ps v7

    $message = ("{0}: Returning {1} apps." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $apps.id.Count)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    $apps
} #V1.0.0.0