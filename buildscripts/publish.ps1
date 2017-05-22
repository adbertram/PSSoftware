$ErrorActionPreference = 'Stop'

## To silence the progress bar for Publish-Module
$ProgressPreference = 'SilentlyContinue'

try {
	## Don't upload the build scripts and appveyor.yml to PowerShell Gallery
	$moduleFolderPath = "$env:APPVEYOR_BUILD_FOLDER\PSPostMan"
	$null = mkdir $moduleFolderPath
	Get-ChildItem -Path $env:APPVEYOR_BUILD_FOLDER | where { $_.Name -notmatch 'buildscripts|appveyor\.yml'} | Copy-Item -Destination $moduleFolderPath

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