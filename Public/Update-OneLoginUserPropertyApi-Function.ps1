
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