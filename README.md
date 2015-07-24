# SoftwareInstallManager

> A single way to install, uninstall, upgrade and configure software with a single framework.

SoftwareInstallManager is a PowerShell module born from necessity. It was built to create a single tool deploy and manage software. No longer do you have to remember:

```
msiexec.exe /i somemsi.msi /qn /Lvx* C:\Windows\Temp\install.log 
```

...just to deploy a single MSI. SoftwareInstallManager simplifies that complexity to just:

```
Install-Software -MsiInstallerFilePath somemsi.msi
```

This is what SoftwareInstallManager is all about. Removing the complexities of software management.

## Version Support

| PSv1 | PSv2 | PSv3 | PSv4 | PSv5 
|-----|------|------|--------|-------|---------|-
| No   | Yes    | Yes    | Yes      | Untested

## Getting Started

### Download

You can [download](https://github.com/adbertram/SoftwareInstallManager/archive/master.zip)
this repository.

### Import the Module

Once you've downloaded the repo place the SoftwareInstallManager folder in any path in your ``$PSModulePath``. I recommend copying it to either ``C:\Program Files\WindowsPowerShell\Modules`` or ``C:\Users\<Username>\Documents\WindowsPowerShell\Modules``.

Once it's in one of those paths you can either import it manually by ``Import-Module SoftwareInstallManager`` or rely on auto-module loading.


### What's included

In the repo you'll find the following files.

| File     | Provides                                       |
|-----------------|------------------------------------------------|
| SoftwareInstallManager.psm1 | The PowerShell module                   |
| SofwareInstallManager.psd1            | The PowerShell module manifest.              |
| README.md       | Details for quickly understanding the project. |

## Function Categories

The SoftwareInstallManager module is made up of four rough categories of functions with subcategories in each major category.

### Install Functions
1. Install-Software

### Uninstall Functions

1. Uninstall-Software
2. Uninstall-ViaMsiZap
3. Uninstall-InstallshieldPackage
4. Uninstall-WindowsInstallerPackage
5. Uninstall-WindowsInstallerPackageWithMsiModule
6. Uninstall-WindowsInstallerPackageWithMsiExec

### Detection Functions

1. Get-InstalledSoftware
2. Test-InstalledSoftware
3. Compare-FilePath
4. Compare-FolderPath
5. Compare-RegistryFileToRegistry
6. Get-FileVersion
7. Get-MyFileHash

### Configuration Functions

#### Registry

1. Get-RegistryValue
2. Get-RegistryValueForAllUsers
3. Import-RegistryFile
4. Set-RegistryValueForAllUsers
5. Register-File

#### FileSystem

1. Copy-FileWithHashCheck
2. Find-InTextFile
3. Set-MyFileSystemAcl

#### Shortcuts

1. Get-Shortcut
2. New-Shortcut

#### Processes

1. Test-Process
2. Get-ChildProcess
3. Stop-MyProcess
4. Wait-MyProcess
5. Wait-WindowsInstaller

#### Services

1. Remove-MyService

#### Certificates

1. Import-Certificate

#### User Profiles

1. Get-AllUsersDesktopFolderPath
2. Get-AllUsersProfileFolderPath
3. Get-AllUsersStartMenuFolderPath
4. Get-UserProfile
5. Get-RootUserProfileFolderPath
6. Get-UserProfilePath
7. Remove-ProfileItem
8. Set-AllUserStartupAction


