$ErrorActionPreference = 'Stop'

## To silence the progress bar for Publish-Module
$ProgressPreference = 'SilentlyContinue'

try {
	## Don't upload the build scripts and appveyor.yml to PowerShell Gallery
	$moduleFolderPath = "$env:APPVEYOR_BUILD_FOLDER\SoftwareInstallManager"
	$null = mkdir $moduleFolderPath

	$excludeFromPublish = @(
		'buildscripts'
		'appveyor\.yml'
		'^\.git'
		'README\.md'
	)
	$exclude = $excludeFromPublish -join '|'
	Get-ChildItem -Recurse -Path $env:APPVEYOR_BUILD_FOLDER | where { $_.Name -notmatch $exclude } | Copy-Item -Destination $moduleFolderPath

	## Publish module to PowerShell Gallery
	$publishParams = @{
		Path = $moduleFolderPath
		NuGetApiKey = $env:nuget_apikey
		Repository = 'PSGallery'
		Force = $true
		Confirm = $false
	}
	Publish-Module @publishParams

} catch {
	$host.SetShouldExit($LastExitCode)
}