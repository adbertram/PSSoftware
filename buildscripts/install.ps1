$provParams = @{
	Name = 'NuGet'
	MinimumVersion = '2.8.5.208'
	Force = $true
}

$null = Install-PackageProvider @provParams
$null = Import-PackageProvider @provParams

$requiredModules = @('Pester','PowerShellGet','PSScriptAnalyzer')
foreach ($m in $requiredModules) {
	Write-Host "Installing module [$($m)]..."
	Install-Module -Name $m -Force -Confirm:$false
	Remove-Module -Name $m -Force -ErrorAction Ignore
	Import-Module -Name $m
}