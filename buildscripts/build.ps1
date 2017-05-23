$ErrorActionPreference = 'Stop'

try {

	$manifestFilePath = "$env:APPVEYOR_BUILD_FOLDER\PSSoftware.psd1"
	$manifestContent = Get-Content -Path $manifestFilePath -Raw

	$functionsToExport = @(
		'Compare-FilePath',
		'Compare-FolderPath',
		'Convert-CompressedGuidToGuid',
		'Convert-GuidToCompressedGuid',
		'Convert-ToUncPath',
		'Copy-FileWithHashCheck',
		'Find-InTextFile',
		'Get-32BitProgramFilesPath',
		'Get-32BitRegistrySoftwarePath',
		'Get-AllUsersDesktopFolderPath',
		'Get-AllUsersProfileFolderPath',
		'Get-AllUsersRegistryValue',
		'Get-AllUsersRegistryKey',
		'Get-AllUsersStartMenuFolderPath',
		'Get-Architecture',
		'Get-ChildProcess',
		'Get-DriveFreeSpace',
		'Get-FileVersion',
		'Get-InstalledSoftware',
		'Get-InstallerType',
		'Get-InstallshieldInstallString',
		'Get-LoggedOnUserSID',
		'Get-MyFileHash',
		'Get-OperatingSystem',
		'Get-RegistryValue',
		'Get-RootUserProfileFolderPath',
		'Get-Shortcut',
		'Get-SystemTempFolderPath',
		'Get-UserProfile',
		'Get-UserProfilePath',
		'Import-Certificate',
		'Import-RegistryFile',
		'Install-Software',
		'Get-MsiexecInstallString',
		'New-Shortcut',
		'Register-File',
		'Remove-MyService',
		'Remove-ProfileItem',
		'Remove-RegistryKey',
		'Remove-Software',
		'Set-AllUserStartupAction',
		'Set-MyFileSystemAcl',
		'Set-AllUsersRegistryValue',
		'Start-Log',
		'Stop-MyProcess',
		'Stop-SoftwareProcess',
		'Test-Process',
		'Test-InstalledSoftware',
		'Uninstall-InstallShieldPackage',
		'Uninstall-ViaMsizap',
		'Uninstall-WindowsInstallerPackage',
		'Uninstall-WindowsInstallerPackageWithMsiexec',
		'Uninstall-WindowsInstallerPackageWithMsiModule',
		'Wait-MyProcess',
		'Wait-WindowsInstaller',
		'Write-Log'
	)

	## Update the module version based on the build version and limit exported functions
	$replacements = @{
		"ModuleVersion = '.*'" = "ModuleVersion = '$env:APPVEYOR_BUILD_VERSION'"
		"FunctionsToExport = '\*'" = 'FunctionsToExport = @({0})' -f "'$($functionsToExport -join "','")'"
	}		

	$replacements.GetEnumerator() | foreach {
		$manifestContent = $manifestContent -replace $_.Key,$_.Value
	}

	$manifestContent | Set-Content -Path $manifestFilePath

	Write-Host '=============================================='
	Write-Host 'Manifest to publish'
	Write-Host '=============================================='
	Write-Host (Get-Content -Path $manifestFilePath -Raw)
	Write-Host '=============================================='

} catch {
	$host.SetShouldExit($LastExitCode)
}