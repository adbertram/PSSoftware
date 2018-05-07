$provParams = @{
	Name = 'NuGet'
	MinimumVersion = '2.8.5.208'
	Force = $true
}

$null = Install-PackageProvider @provParams
$null = Install-Module -Name PowerShellGet -Force -Confirm:$false -SkipPublisherCheck
$provParams.Name = 'PowerShellGet'
$provParams.MinimumVersion = '1.6.0'
$null = Import-PackageProvider @provParams

$requiredModules = @('Pester','PSScriptAnalyzer')
foreach ($m in $requiredModules) {
	Write-Host "Installing module [$($m)]..."
	Install-Module -Name $m -Force -Confirm:$false -SkipPublisherCheck
	Remove-Module -Name $m -Force -ErrorAction Ignore
	Import-Module -Name $m
}