$ErrorActionPreference = 'Stop'

try {
	## Don't upload the build scripts and appveyor.yml to PowerShell Gallery
	$tempmoduleFolderPath = "$env:Temp\PSSoftware"
	$null = mkdir $tempmoduleFolderPath

	## Move all of the files/folders to exclude out of the main folder
	$excludeFromPublish = @(
		'PSSoftware\\buildscripts'
		'PSSoftware\\appveyor\.yml'
		'PSSoftware\\\.git'
		'PSSoftware\\README\.md'
	)
	$exclude = $excludeFromPublish -join '|'
	Get-ChildItem -Path $env:APPVEYOR_BUILD_FOLDER -Recurse | where { $_.FullName -match $exclude } | Move-Item -Destination $env:temp

	## Copy only the package contents to the module folder
	Get-ChildItem -Path $env:APPVEYOR_BUILD_FOLDER -Recurse | Copy-Item -Destination $tempmoduleFolderPath

	## Publish module to PowerShell Gallery
	$publishParams = @{
		Path = $tempmoduleFolderPath
		NuGetApiKey = $env:nuget_apikey
		Repository = 'PSGallery'
		Force = $true
		Confirm = $false
	}
	Publish-Module @publishParams

} catch {
	Write-Error -Message $_.Exception.Message
	$host.SetShouldExit($LastExitCode)
}