function Uninstall-ViaMsizap
{
	<#
	.SYNOPSIS
		This function runs the MSIzap utility to forcefully remove and cleanup MSI-installed software		
	.DESCRIPTION
		This function runs msizap to remove software.
	.EXAMPLE
		Uninstall-ViaMsizap -MsizapFilePath C:\msizap.exe -Guid {XXXX-XXX-XXX}
		This example would attempt to remove the software registered with the GUID {XXXX-XXX-XXX}.
	.PARAMETER MsizapFilePath
		The file path where the msizap utility exists.  This can be a local or UNC path.
	.PARAMETER Guid
		The GUID of the registered software you'd like removed
	.PARAMETER Params
		Non-default params you'd like passed to msizap.  By default, "TWG!" is used to remove in all user
		profiles.  This typically doesn't need to be changed.
	.PARAMETER LogFilePath
		The file path to where msizap will generate output
	#>
	[CmdletBinding()]
	param (
		[ValidatePattern('\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b')]
		[Parameter(Mandatory = $true)]
		[string]$Guid,
		
		[string]$Params = 'TWG!',
		
		[ValidateScript({ Test-Path $_ -PathType 'Leaf' })]
		[string]$MsizapFilePath = "C:\MyDeployment\msizap.exe",
		
		[Parameter()]
		[string]$LogFilePath = "$(Get-SystemTempFolderPath)\msizap.log"
	)
	process
	{
		try
		{
			Write-Log -Message "$($MyInvocation.MyCommand) - BEGIN"
			Write-Log -Message "-Starting the process `"$MsiZapFilePath $Params $Guid`"..."
			$NewProcess = Start-Process $MsiZapFilePath -ArgumentList "$Params $Guid" -Wait -NoNewWindow -PassThru -RedirectStandardOutput $LogFilePath
			Wait-MyProcess -ProcessId $NewProcess.Id
			Write-Log -Message "$($MyInvocation.MyCommand) - END"
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			Write-Log -Message "$($MyInvocation.MyCommand) - END"
			$false
		}
	}
}

function Uninstall-WindowsInstallerPackage
{
	<#
	.SYNOPSIS
		This function runs an uninstall for a Windows Installer package
	.PARAMETER Name
		The software title of the Windows installer package you'd like to uninstall.  Use either the Name
		param or the Guid param to find the Windows installer package.
	.PARAMETER MsiExecSwitches
		Specify a string of switches you'd like msiexec.exe to run when it attempts to uninstall the software. By default,
		it already uses "/x GUID /qn".  You can specify any additional parameters here.
	.PARAMETER Guid
		The GUID of the Windows Installer package
	#>
	[CmdletBinding(DefaultParameterSetName = 'Guid')]
	param (
		[Parameter(ParameterSetName = 'Name')]
		[string]$Name,
		
		[Parameter(ParameterSetName = 'Guid')]
		[ValidatePattern('\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b')]
		[string]$Guid,
		
		[string]$MsiExecSwitches
	)
	process
	{
		try
		{
			$Params = @{ }
			if ($Name)
			{
				Write-Log -Message "Attempting to uninstall Windows Installer using name '$Name'..."
				$params.Name = $Name
			}
			elseif ($Guid)
			{
				Write-Log -Message "Attempting to uninstall Windows Installer using GUID '$Guid'..."
				$params.Guid = $Guid
			}
			if ($PSBoundParameters.ContainsKey('MsiExecSwitches'))
			{
				$params.MsiExecSwitches = $MsiExecSwitches
			}
			
			Uninstall-WindowsInstallerPackageWithMsiexec @params
			Write-Log -Message "$($MyInvocation.MyCommand) - END"
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			Write-Log -Message "$($MyInvocation.MyCommand) - END"
			$false
		}
	}
}

function Uninstall-WindowsInstallerPackageWithMsiexec
{
	<#
	.SYNOPSIS
		This function runs an uninstall for a Windows Installer package using msiexec.exe /x
	.PARAMETER Name
		The software title of the Windows installer package you'd like to uninstall.  Use either the Name
		param or the Guid param to find the Windows installer package.
	.PARAMETER Guid
		The GUID of the Windows Installer package
	.PARAMETER MsiExecSwitches
		Specify a string of switches you'd like msiexec.exe to run when it attempts to uninstall the software. By default,
		it already uses "/x GUID /qn".  You can specify any additional parameters here.
	#>
	[CmdletBinding(DefaultParameterSetName = 'Guid')]
	param (
		[Parameter(ParameterSetName = 'Name')]
		[string]$Name,
		
		[Parameter(ParameterSetName = 'Guid')]
		[ValidatePattern('\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b')]
		[string]$Guid,
		
		[string]$MsiExecSwitches
	)
	process
	{
		Write-Log -Message "$($MyInvocation.MyCommand) - BEGIN"
		if ($Name)
		{
			Write-Log -Message "Attempting to uninstall Windows Installer with msiexec.exe using name '$Name'..."
			$Params = @{ 'Name' = $Name }
			$software = Get-InstalledSoftware @Params
			if (-not $software)
			{
				throw 'Name specified for uninstall but could not find GUID to remove'
			}
			else
			{
				## Sometimes multiple instances are returned. 1 having no GUID and 1 having a GUID.
				## Cisco AnyConnect is an example where if the one with the GUID is removed both are removed.
				$Guid = $software | Where-Object { $_.GUID }
				if (-not $Guid)
				{
					throw 'Required GUID could not be found for software'
				}
				else
				{
					$Guid = $Guid.GUID
					Write-Log -Message "Using GUID [$Guid] for the uninstall"
				}
			}
		}
		
		$switches = @("/x `"$Guid`"")
		if ($PSBoundParameters.ContainsKey('MsiExecSwitches'))
		{
			$switches += $MsiExecSwitches
		}
		$switches += @('REBOOT=ReallySuppress', '/qn')
		$switchString = $switches -join ' '
		
		Write-Log -Message "Initiating msiexec.exe with arguments [$($switchString)]"
		$Process = Start-Process 'msiexec.exe' -ArgumentList $switchString -PassThru -Wait -NoNewWindow
		Wait-WindowsInstaller
		Test-Process $Process
		if (!(Test-InstalledSoftware -Guid $Guid))
		{
			Write-Log -Message "Successfully uninstalled MSI package with msiexec.exe"
			$true
		}
		else
		{
			Write-Log -Message "Failed to uninstall MSI package with msiexec.exe" -LogLevel '3'
			$false
		}
		Write-Log -Message "$($MyInvocation.MyCommand) - END"
	}
}

function Uninstall-WindowsInstallerPackageWithMsiModule
{
	<#
	.SYNOPSIS
		This function runs an uninstall for a Windows Installer package using the Windows Installer Powershell module
		https://psmsi.codeplex.com
	.PARAMETER Name
		The software title of the Windows installer package you'd like to uninstall.  Use either the Name
		param or the Guid param to find the Windows installer package.
	.PARAMETER Guid
		The GUID of the Windows Installer package
	#>
	[CmdletBinding(DefaultParameterSetName = 'Guid')]
	param (
		[Parameter(ParameterSetName = 'Name')]
		[string]$Name,
		
		[Parameter(ParameterSetName = 'Guid')]
		[ValidatePattern('\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b')]
		[string]$Guid
	)
	process
	{
		try
		{
			Write-Log -Message "$($MyInvocation.MyCommand) - BEGIN"
			if (!(Test-Path 'C:\MyDeployment\MSI'))
			{
				Write-Log -Message "Required MSI module is not available" -LogLevel '2'
				$false
			}
			elseif (((Get-OperatingSystem) -notmatch 'XP') -and ((Get-OperatingSystem) -notmatch 'Server'))
			{
				Write-Log -Message "Importing MSI module..."
				Import-Module 'C:\MyDeployment\MSI'
				Write-Log -Message "MSI module imported."
				$UninstallParams = @{
					'Log' = $script:LogFilePath
					'Chain' = $true
					'Force' = $true
					'ErrorAction' = 'SilentlyContinue'
					'Properties' = 'REBOOT=ReallySuppress'
				}
				
				if ($Name)
				{
					$MsiProductParams = @{ 'Name' = $Name }
				}
				elseif ($Guid)
				{
					$MsiProductParams = @{ 'ProductCode' = $Guid }
				}
				
				Get-MSIProductInfo @MsiProductParams | Uninstall-MsiProduct @UninstallParams
				if (!(Test-InstalledSoftware @MsiProductParams))
				{
					Write-Log -Message "Successfully uninstalled MSI package '$Name' with MSI module"
					$true
				}
				else
				{
					Write-Log -Message "Failed to uninstall MSI package '$Name' with MSI module" -LogLevel '2'
					$false
				}
			}
			Write-Log -Message "$($MyInvocation.MyCommand) - END"
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			Write-Log -Message "$($MyInvocation.MyCommand) - END"
			$false
		}
	}
}

function Wait-WindowsInstaller
{
	<#
	.SYNOPSIS
		This function should be called immediately after the Uninstall-WindowsInstallerPackage function.  This is a specific
		process waiting function especially for msiexec.exe.  It was built because the Wait-MyProcess function will sometimes
		not work with msiexec installs/uninstalls.  This is because msiexec.exe creates a process tree which does not necessarily
		mean child processes.  Using this function will ensure your script always wait for the msiexec.exe process you
		kicked off to complete before continuing.
	#>
	[CmdletBinding()]
	param ()
	process
	{
		try
		{
			Write-Log -Message "$($MyInvocation.MyCommand) - BEGIN"
			Write-Log -Message 'Looking for any msiexec.exe processes...'
			$MsiexecProcesses = Get-WmiObject -Class Win32_Process -Filter "Name = 'msiexec.exe'" | Where-Object { $_.CommandLine -ne 'C:\Windows\system32\msiexec.exe /V' }
			if ($MsiExecProcesses)
			{
				Write-Log -Message "Found '$($MsiexecProcesses.Count)' Windows installer processes.  Waiting..."
				## Wait for each msiexec.exe process to finish before proceeding
				foreach ($Process in $MsiexecProcesses)
				{
					Wait-MyProcess -ProcessId $Process.ProcessId
				}
				## When all msiexec.exe processes finish, recursively call this function again to ensure no
				## other installs have begun.
				Wait-WindowsInstaller
			}
			else
			{
				Write-Log -Message 'No Windows installer processes found'
			}
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
		finally
		{
			Write-Log -Message "$($MyInvocation.MyCommand) - END"
		}
	}
}