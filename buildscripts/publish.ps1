$ErrorActionPreference = 'Stop'

## To silence the progress bar for Publish-Module
$ProgressPreference = 'SilentlyContinue'

try {
	## Don't upload the build scripts and appveyor.yml to PowerShell Gallery
	$moduleFolderPath = "$env:APPVEYOR_BUILD_FOLDER\SoftwareInstallManager"
	$null = mkdir $moduleFolderPath

	$excludeFromPublish = @(
		'SoftwareInstallManager\\buildscripts'
		'SoftwareInstallManager\\appveyor\.yml'
		'SoftwareInstallManager\\\.git'
		'SoftwareInstallManager\\README\.md'
	)
	$exclude = $excludeFromPublish -join '|'
	Get-ChildItem -Recurse -Path $moduleFolderPath | where { $_.FullName -notmatch $exclude }

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