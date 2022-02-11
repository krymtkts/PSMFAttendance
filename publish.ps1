Param (
    [String]$ApiKey,
    [ValidateSet('Publish', 'DryRun')]$Mode = 'DryRun'
)

$ModuleName = Get-ChildItem -File -Path ./ -Recurse -Name '*.psd1' | Split-Path -Parent
$ArtifactPath = ".\$ModuleName\"
Write-Host "Checking modules under $ArtifactPath"

$report = Invoke-ScriptAnalyzer -Path "$ArtifactPath" -Recurse -Settings PSGallery
if ($report) {
    Write-Host "Violation found."
    $report
    exit
}
Write-Host "Check OK."

switch ($Mode) {
    'Publish' {
        Write-Host "Publishing module: $ModuleName"
        Publish-Module -Path $ArtifactPath -NugetAPIKey $ApiKey -Verbose
    }
    'DryRun' {
        Write-Host "[DRY-RUN]Publishing module: $ModuleName"
        Publish-Module -Path $ArtifactPath -NugetAPIKey $ApiKey -Verbose -WhatIf
    }
}
if ($?) {
    Write-Host 'publishing succeed.'
}
else {
    Write-Error 'publishing failed.'
}
