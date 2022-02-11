# The location of the file that we'll store the Access Token SecureString
# which cannot/should not roam with the user.
[string] $script:MFCredentialPath = [System.IO.Path]::Combine(
    [System.Environment]::GetFolderPath('LocalApplicationData'),
    'krymtkts',
    'PSMFAttendance',
    'credential')

$script:Mfc = 'https://attendance.moneyforward.com/'
$script:LocaleEN = New-Object System.Globalization.CultureInfo("en-US") #English (US) Locale

class MFCredentialStore {
    [string] $OfficeAccountName
    [string] $AccountNameOrEmail
    [SecureString] $Password
    MFCredentialStore(
        [string] $OfficeAccountName,
        [string] $AccountNameOrEmail,
        [SecureString] $Password
    ) {
        $this.OfficeAccountName = $OfficeAccountName
        $this.AccountNameOrEmail = $AccountNameOrEmail
        $this.Password = $Password
    }
}

$script:MFCredential = $null
$script:MFSession = $null
$script:MySession = $null

function Set-MFAuthentication {
    [CmdletBinding(SupportsShouldProcess)]
    [CmdletBinding(DefaultParameterSetName = 'Cache')]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'Cache')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Session')]
        [string] $OfficeAccountName,
        [Parameter(Mandatory = $false, ParameterSetName = 'Cache')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Session')]
        [PSCredential] $Credential
    )

    if (-not $OfficeAccountName) {
        $OfficeAccountName = Read-Host -Prompt "Please provide your MF office account.`n"
    }
    if (-not $Credential) {
        $message = 'Please provide your MF user and password.'
        if ($PsCmdlet.ParameterSetName -eq "Cache") {
            $message = $message + 'These credential is being cached across PowerShell sessions. To clear caching, call Clear-MFAuthentication.'
        }
        $Credential = Get-Credential -Message $message
    }
    $script:MFCredential = [MFCredentialStore]::new(
        $OfficeAccountName, $Credential.UserName, $Credential.Password)

    if ( $PsCmdlet.ParameterSetName -ne "Cache") {
        return;
    }
    $store = @{
        OfficeAccountName  = $OfficeAccountName;
        AccountNameOrEmail = $Credential.UserName;
        Password           = $Credential.Password | ConvertFrom-SecureString;
    }

    if ($PSCmdlet.ShouldProcess($script:MFCredentialPath)) {
        New-Item -Path $script:MFCredentialPath -Force | Out-Null
        $store | ConvertTo-Json -Compress | Set-Content -Path $script:MFCredentialPath -Force
    }
}

function Get-MFAuthentication {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
    )

    if ( $script:MFCredential) {
        return
    }
    $content = Get-Content -Path $script:MFCredentialPath -ErrorAction Ignore
    if ([String]::IsNullOrEmpty($content)) {
        Set-MFAuthentication
    }
    else {
        try {
            $cred = $content | ConvertFrom-Json
            $script:MFCredential = [MFCredentialStore]::new(
                $cred.OfficeAccountName, $cred.AccountNameOrEmail, ($cred.PassWord | ConvertTo-SecureString)
            )
            return
        }
        catch {
            Write-Error "Invalid SecureString stored for this module. Use Set-MFAuthentication to update it."
        }
    }
}

function Clear-MFAuthentication {
    [CmdletBinding(SupportsShouldProcess)]
    param(
    )

    $script:MFCredential = $null
    Remove-Item -Path $script:MFCredentialPath -Force -ErrorAction SilentlyContinue
}

function Get-DateForDisplay {
    [CmdletBinding()]
    param (
        [Parameter(HelpMessage = 'The value of date time to format.')]
        [DateTime]
        $Date = (Get-Date)
    )

    $Date.ToLocalTime().ToString("yyyy-MM-dd(ddd) HH:mm:ss K", $script:LocaleEN)
}


function Find-CsrfToken {
    [CmdletBinding()]
    [OutputType([String])]
    param (
        [Parameter(Mandatory)]
        [String]
        $Content
    )

    process {
        $Content -match '<meta name="csrf-token" content="(?<token>\S+)" />' | Out-Null
        $CsrfToken = $matches['token']
        if (!$CsrfToken) {
            throw "Cannot scrape csrf token."
        }
        return $CsrfToken
    }
}

function Get-RecordTime {
    process {
        $Now = Get-Date -AsUTC
        [PSCustomObject]@{
            Raw        = $Now
            Date       = $Now.ToString("MM/dd/yyyy")
            RecordTime = $Now.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        }
    }
}

function Connect-MFCloudAttendance {
    begin {
        Write-Host "Trying to connect MF Attendance..."
    }

    process {
        $Login = "$script:Mfc/email_employee_session/"
        $NewSession = "$Login/new"
        $NewSessionParams = @{
            Method          = 'Get'
            Uri             = $NewSession
            SessionVariable = 'script:MySession'
        }
        Write-Verbose ($NewSessionParams | Out-String)
        try {
            $Res = Invoke-WebRequest @NewSessionParams
            $CsrfToken = Find-CsrfToken -Content $Res.Content
            Write-Verbose $CsrfToken
        }
        catch {
            Write-Error "Failed to connect $Login . $_"
            Write-Verbose ($NewSessionParams | Out-String)
            throw
        }

        $LoginParams = @{
            Method     = 'Post'
            Uri        = $Login
            WebSession = $script:MySession
            Body       = @{
                authenticity_token                             = $CsrfToken
                'employee_session_form[office_account_name]'   = $script:MFCredential.OfficeAccountName
                'employee_session_form[account_name_or_email]' = $script:MFCredential.AccountNameOrEmail
                'employee_session_form[password]'              = $script:MFCredential.Password | ConvertFrom-SecureString -AsPlainText
            }
        }
        try {
            $Res = Invoke-WebRequest @LoginParams
            $TmpMFSession = [PSCustomObject]@{
                SessionId  = ''
                EmployeeId = ''
                LocationId = ''
            }
            $TmpMFSession.SessionId = $MySession.Cookies.GetCookies($script:Mfc).Value
            $Res.Content -match '<meta.+content="(?<uid>\d+)"' | Out-Null # dirty hack. id is numeric value.
            $TmpMFSession.EmployeeId = $matches['uid']
            if (!$TmpMFSession.EmployeeId) {
                throw "Cannot scrape employee id from response of $Login."
            }
            $Res.Content -match '<input (data-target="my-page--web-time-recorders.inputOfficeLocationId"|id="web_time_recorder_form_office_location_id").+value="(?<lid>\d+)"' | Out-Null # dirty hack. id is numeric value.
            $TmpMFSession.LocationId = $matches['lid']
            if (!$TmpMFSession.EmployeeId) {
                throw "Cannot scrape employee id from response of $Login."
            }
            $script:MFSession = $TmpMFSession
        }
        catch {
            Write-Error "Failed to login $Login. $_"
            throw
        }
    }

    end {
        if ($script:MFSession) {
            Write-Host "Login succeed. $(Get-DateForDisplay)"
        }
        else {
            Write-Error "Login failed. $(Get-DateForDisplay)"
        }
    }
}

function Find-AttendanceRecord {
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param (
        [Parameter(Mandatory)]
        [String]
        $Content
    )

    process {
        $DatePattern = [regex]'<span class="attendance-table-text-day">(?<date>\d+)</span>'
        $DateMatches = $DatePattern.Matches($Content)
        if (!$DateMatches) {
            throw "No attendance found."
        }
        Write-Verbose ($DateMatches | Out-String)
        $Dates = $DateMatches | ForEach-Object { [int]$_.Groups['date'].Value } | Sort-Object
        $TimePattern = [regex]'<td class="column-attendance attendance-text-align-center attendance-table-column-">(?<time>(\d{2}:\d{2})?)</td>'
        $Times = $TimePattern.Matches($Content)
        if (!$Times) {
            throw "Cannot scrape attendance time entries."
        }
        $Result = @{}
        $i = 0
        foreach ($Date in $Dates) {
            $Result.Add($Date, [PSCustomObject]@{
                    Start = $Null
                    End   = $Null
                })
            if ($Times[$i] -and $Times[$i].Groups['time']) {
                $Result[$Date].Start = $Times[$i].Groups['time'].Value
            }
            $i = $i + 1
            if ($Times[$i] -and $Times[$i].Groups['time']) {
                $Result[$Date].End = $Times[$i].Groups['time'].Value
            }
            $i = $i + 1
        }
        return $Result
    }
}

function Get-AttendanceRecord {
    [CmdletBinding()]
    param (
    )

    begin {
        Write-Verbose ($script:MySession | Out-String)
        Write-Verbose ($script:MFSession | Out-String)
    }

    process {
        $MyPage = "$script:Mfc/my_page"
        $NewSessionParams = @{
            Method     = 'Get'
            Uri        = $MyPage
            WebSession = $script:MySession
        }
        Write-Verbose ($NewSessionParams | Out-String)
        try {
            $Res = Invoke-WebRequest @NewSessionParams
            $CsrfToken = Find-CsrfToken -Content $Res.Content
            Write-Verbose $CsrfToken
        }
        catch {
            Write-Error "Failed to connect $MyPage. $_"
            throw
        }
        $Attendances = "$MyPage/attendances"
        $LoginParams = @{
            Method     = 'Get'
            Uri        = $Attendances
            WebSession = $MySession
        }
        Write-Verbose ($LoginParams | Out-String)
        try {
            $Res = Invoke-WebRequest @LoginParams
            Write-Host "Succeed to get content. $(Get-DateForDisplay (Get-Date))"
            if (!$Res) {
                Write-Error "Failed to get content from  $Attendances."
                return
            }
            $Records = Find-AttendanceRecord -Content $Res.Content
            return $Records
        }
        catch {
            Write-Error "Failed to send time record."
            throw
        }
    }
}

function Test-CanRecord {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet("clock_in", "clock_out")]
        $TimeRecordEvent
    )
    process {
        $Today = (Get-Date).Day
        $Records = Get-AttendanceRecord
        switch ($TimeRecordEvent) {
            "clock_in" {
                return -not [boolean] $Records[$Today].Start
            }
            "clock_out" {
                return -not [boolean] $Records[$Today].End
            }
        }
    }
}

function Send-TimeRecord {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet("clock_in", "clock_out")]
        $TimeRecordEvent
    )

    begin {
        Write-Verbose ($script:MySession | Out-String)
        Write-Verbose ($script:MFSession | Out-String)
    }

    process {
        $MyPage = "$script:Mfc/my_page"
        $NewSessionParams = @{
            Method     = 'Get'
            Uri        = $MyPage
            WebSession = $script:MySession
        }
        Write-Verbose ($NewSessionParams | Out-String)
        try {
            $Res = Invoke-WebRequest @NewSessionParams
            $CsrfToken = Find-CsrfToken -Content $Res.Content
            Write-Verbose $CsrfToken
        }
        catch {
            Write-Error "Failed to connect $MyPage. $_"
            throw
        }
        $TimeRecorder = "$MyPage/web_time_recorder"
        $Now = Get-RecordTime

        $Body = @{
            authenticity_token                           = $CsrfToken
            'web_time_recorder_form[event]'              = $TimeRecordEvent
            'web_time_recorder_form[date]'               = $Now.Date
            'web_time_recorder_form[user_time]'          = $Now.RecordTime
            'web_time_recorder_form[office_location_id]' = $script:MFSession.LocationId
        }
        $LoginParams = @{
            Method     = 'Post'
            Uri        = $TimeRecorder
            WebSession = $MySession
            Body       = $Body
            # Headers    = $MockHeaders
        }
        Write-Verbose ($LoginParams | Out-String)
        Write-Verbose ($Body | Out-String)
        try {
            $Res = Invoke-WebRequest @LoginParams
            Write-Host "Succeed to send time record. $TimeRecordEvent $(Get-DateForDisplay $Now.Raw)"
        }
        catch {
            Write-Error "Failed to send time record. $TimeRecorder. $TimeRecordEvent"
            throw
        }
    }
}


function Send-BeginningWork {
    begin {
        Write-Host 'try to begin work.'
    }

    process {
        Get-MFAuthentication
        Connect-MFCloudAttendance
        $Recordable = Test-CanRecord clock_in
        if ($Recordable) {
            Send-TimeRecord -TimeRecordEvent clock_in
        }
    }

    end {
        if ($Recordable) {
            Write-Host 'began work!! 😪'
        }
        else {
            Write-Host "Cannot record. It's already begun. 😅"
        }
    }
}

function Send-FinishingWork {
    begin {
        Write-Host 'try to finish work.'
    }

    process {
        Get-MFAuthentication
        Connect-MFCloudAttendance
        $Recordable = Test-CanRecord clock_out
        if ($Recordable) {
            Send-TimeRecord -TimeRecordEvent clock_out
        }
    }

    end {
        if ($Recordable) {
            Write-Host 'finished work!! 🍻'
        }
        else {
            Write-Host "Cannot record. It was already over. 😅"
        }
    }
}

function Get-MFAttendance {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param (
    )

    begin {
        Write-Host 'try to get attendances.'
    }

    process {
        Get-MFAuthentication
        Connect-MFCloudAttendance
        $Records = Get-AttendanceRecord
        $Keys = $Records.Keys | Sort-Object
        $Result = @()
        foreach ($Date in $Keys) {
            $Result += [PSCustomObject]@{
                Date  = $Date
                Start = $Records[$Date].Start
                End   = $Records[$Date].End
            }
        }
        $Result
    }
}
