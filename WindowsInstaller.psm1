Set-StrictMode -Version Latest

function Get-MsiexecInstallString
{
	[OutputType([string])]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$InstallerFilePath,
	
		[Parameter()]
		[AllowNull()]
		[string]$MstFilePath,
	
		[Parameter()]
		[AllowNull()]
		[string]$MspFilePath,
	
		[Parameter()]
		[AllowNull()]
		[string]$ExtraSwitches,
	
		[Parameter()]
		[AllowNull()]
		[string]$LogFilePath
	)
	begin {
		$ErrorActionPreference = 'Stop'
	}
	process {
		try
		{
			## We're creating common msiexec switches here.  /i specifies I want to run an install, /qn
			## says I want that install to be quiet (no prompts) and n means no UI so no progress bars
			$InstallArgs = @()
			$InstallArgs += "/i `"$InstallerFilePath`" /qn"
			if ($MstFilePath)
			{
				$InstallArgs += "TRANSFORMS=`"$MstFilePath`""
			}
			if ($MspFilePath)
			{
				$InstallArgs += "PATCH=`"$MspFilePath`""
			}
			if ($ExtraSwitches)
			{
				$InstallArgs += $ExtraSwitches
			}
			
			## Once we've added all of the custom syntax elements we'll then add a few more default
			## switches.  REBOOT=ReallySuppress prevents the computer from rebooting if it exists with an
			## exit code of 3010, ALLUSERS=1 means that we'd like to make this software for all users
			## on the machine and /Lvx* is the most verbose way to specify a log file path and to log as
			## much information as possible.
			if (-not $PSBoundParameters.ContainsKey('LogFilePath'))
			{
				$LogFilePath = "$(Get-SystemTempFolderPath)\$($InstallerFilePath | Split-Path -Leaf).log"
			}
			$InstallArgs += "REBOOT=ReallySuppress ALLUSERS=1 /Lvx* `"$LogFilePath`""
			$InstallArgs = $InstallArgs -join ' '
			$InstallArgs
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

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
	[OutputType()]
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
			Write-Log -Message "-Starting the process `"$MsiZapFilePath $Params $Guid`"..."
			$NewProcess = Start-Process $MsiZapFilePath -ArgumentList "$Params $Guid" -Wait -NoNewWindow -PassThru -RedirectStandardOutput $LogFilePath
			Wait-MyProcess -ProcessId $NewProcess.Id	
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
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
	[OutputType()]
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
			
			if (Uninstall-WindowsInstallerPackageWithMsiexec @params)
			{
				Write-Log -Message 'Successfull uninstall.'
			}
			else
			{
				throw "Failed to uninstall."
			}
			
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
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
	[OutputType()]
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
		try {
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
			if (-not (Test-InstalledSoftware -Guid $Guid))
			{
				Write-Log -Message 'Successfully uninstalled MSI package with msiexec.exe'
			}
			else
			{
				throw 'Failed to uninstall MSI package with msiexec.exe'
			}
		}
		catch 
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
		
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
	[OutputType()]
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
			if (-not (Get-Module -ListAvailable -Name 'MSI'))
			{
				throw 'Required MSI module is not available'
			}
			
			if (((Get-OperatingSystem) -notmatch 'XP') -and ((Get-OperatingSystem) -notmatch 'Server'))
			{
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
				if (-not (Test-InstalledSoftware @MsiProductParams))
				{
					Write-Log -Message "Successfully uninstalled MSI package '$Name' with MSI module"
				}
				else
				{
					throw "Failed to uninstall MSI package '$Name' with MSI module"
				}
			}
			
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
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
	[OutputType()]
	[CmdletBinding()]
	param ()
	process
	{
		try
		{
			
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
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}