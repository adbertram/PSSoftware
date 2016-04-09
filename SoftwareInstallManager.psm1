Set-StrictMode -Version Latest

function Test-InstalledSoftware
{
	<#
	.SYNOPSIS
		This function is used as a quick check to see if a specific software product is installed on the local host.
	.PARAMETER Name
	 	The name of the software you'd like to query as displayed by the Get-InstalledSoftware function
	.PARAMETER Version
		The version of the software you'd like to query as displayed by the Get-InstalledSofware function.
	.PARAMETER Guid
		The GUID of the installed software
	#>
	[CmdletBinding(DefaultParameterSetName = 'Name')]
	param (
		[Parameter(ParameterSetName = 'Name')]
		[ValidateNotNullOrEmpty()]
		[string]$Name,
		
		[Parameter(ParameterSetName = 'Name')]
		[ValidateNotNullOrEmpty()]
		[string]$Version,
		
		[Parameter(ParameterSetName = 'Guid')]
		[ValidateNotNullOrEmpty()]
		[Alias('ProductCode')]
		[string]$Guid
	)
	process
	{
		try
		{
			
			if ($PSBoundParameters.ContainsKey('Name'))
			{
				if ($PSBoundParameters.ContainsKey('Version'))
				{
					$SoftwareInstances = Get-InstalledSoftware -Name $Name | Where-Object { $_.Version -eq $Version }
				}
				else
				{
					$SoftwareInstances = Get-InstalledSoftware -Name $Name
				}
			}
			elseif ($PSBoundParameters.ContainsKey('Guid'))
			{
				$SoftwareInstances = Get-InstalledSoftware -Guid $Guid
			}
			
			
			if (-not $SoftwareInstances)
			{
				Write-Log -Message 'The software is NOT installed.'
				$false
			}
			else
			{
				Write-Log -Message 'The software IS installed.'
				$true
			}
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Get-InstalledSoftware
{
	<#
	.SYNOPSIS
		Retrieves a list of all software installed
	.EXAMPLE
		Get-InstalledSoftware
		
		This example retrieves all software installed on the local computer
	.PARAMETER Name
		The software title you'd like to limit the query to.
	.PARAMETER Guid
		The software GUID you'e like to limit the query to
	#>
	[CmdletBinding()]
	param (
		[string]$Name,
		
		[ValidatePattern('\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b')]
		[string]$Guid
	)
	process
	{
		try
		{
			
			$UninstallKeys = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
			New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
			$UninstallKeys += Get-ChildItem HKU: | Where-Object { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } | ForEach-Object { "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
			if (-not $UninstallKeys)
			{
				Write-Log -Message 'No software registry keys found' -LogLevel '2'
			}
			else
			{
				foreach ($UninstallKey in $UninstallKeys)
				{
					$friendlyNames = @{
						'DisplayName' = 'Name'
						'DisplayVersion' = 'Version'
					}
					Write-Log -Message "Checking uninstall key [$($UninstallKey)]"
					if ($PSBoundParameters.ContainsKey('Name'))
					{
						$WhereBlock = { $_.GetValue('DisplayName') -like "$Name*" }
					}
					elseif ($PSBoundParameters.ContainsKey('GUID'))
					{
						$WhereBlock = { $_.PsChildName -eq $Guid }
					}
					else
					{
						$WhereBlock = { $_.GetValue('DisplayName') }
					}
					$SwKeys = Get-ChildItem -Path $UninstallKey -ErrorAction SilentlyContinue | Where-Object $WhereBlock
					if (-not $SwKeys)
					{
						Write-Log -Message "No software keys in uninstall key $UninstallKey"
					}
					else
					{
						foreach ($SwKey in $SwKeys)
						{
							$output = @{ }
							foreach ($ValName in $SwKey.GetValueNames())
							{
								if ($ValName -ne 'Version')
								{
									$output.InstallLocation = ''
									if ($ValName -eq 'InstallLocation' -and ($SwKey.GetValue($ValName)) -and (@('C:', 'C:\Windows', 'C:\Windows\System32', 'C:\Windows\SysWOW64') -notcontains $SwKey.GetValue($ValName).TrimEnd('\')))
									{
										$output.InstallLocation = $SwKey.GetValue($ValName).TrimEnd('\')
									}
									[string]$ValData = $SwKey.GetValue($ValName)
									if ($friendlyNames[$ValName])
									{
										$output[$friendlyNames[$ValName]] = $ValData.Trim() ## Some registry values have trailing spaces.
									}
									else
									{
										$output[$ValName] = $ValData.Trim() ## Some registry values trailing spaces
									}
								}
							}
							$output.GUID = ''
							if ($SwKey.PSChildName -match '\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b')
							{
								$output.GUID = $SwKey.PSChildName
							}
							New-Object –TypeName PSObject -Property $output
						}
					}
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

function Install-Software
{
	<#
	.SYNOPSIS

	.NOTES
		Created on: 	6/23/2014
		Created by: 	Adam Bertram
		Filename:		Install-Software.ps1
		Credits:		
		Requirements:	The installers executed via this script typically need "Run As Administrator"
		Todos:			Allow multiple software products to be installed	
	.EXAMPLE
		Install-Software -MsiInstallerFilePath install.msi -InstallArgs "/qn "	
	.PARAMETER InstallShieldInstallerFilePath
	 	This is the file path to the EXE InstallShield installer.
	.PARAMETER MsiInstallerFilePath
	 	This is the file path to the MSI installer.
	.PARAMETER OtherInstallerFilePath
	 	This is the file path to any other EXE installer.
	.PARAMETER MsiExecSwitches
		This is a string of arguments that are passed to the installer. If this param is
		not used, it will default to the standard REBOOT=ReallySuppress and the ALLUSERS=1 switches. If it's 
		populated, it will be concatenated with the standard silent arguments.  Use the -Verbose switch to discover arguments used.
		Do NOT use this to pass TRANSFORMS or PATCH arguments.  Use the MstFilePath and MspFilePath params for that.
	.PARAMETER MstFilePath
		Use this param if you've created a TRANSFORMS file and would like to pass this to the installer
	.PARAMETER MspFilePath
		Use this param if you have a patch to apply to the install
	.PARAMETER InstallShieldInstallArgs
		This is a string of arguments that are passed to the InstallShield installer.  Default arguments are
		"/s /f1$IssFilePath /SMS"
	.PARAMETER OtherInstallerArgs
		This is a string of arguments that are passed to any other EXE installer.  There is no default.
	.PARAMETER KillProcess
		A list of process names that will be terminated prior to attempting the install.  This is useful
		in upgrade scenarios where you need to terminate the previous version's processes.
	.PARAMETER ProcessTimeout
		A value (in seconds) that the installer script will wait for the installation process to complete.  If the installation
		goes over this value, any processes (parent or child) will be terminated.
	.PARAMETER LogFilePath
		This is the path where the installer log file will be written.  If not passed, it will default
		to being named install.log in the system temp folder.

	#>
	[CmdletBinding(DefaultParameterSetName = 'MSI')]
	param (
		[Parameter(ParameterSetName = 'InstallShield', Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[ValidatePattern('\.exe$')]
		[ValidateNotNullOrEmpty()]
		[string]$InstallShieldInstallerFilePath,
		
		[Parameter(ParameterSetName = 'Other', Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[ValidatePattern('\.exe$')]
		[ValidateNotNullOrEmpty()]
		[string]$OtherInstallerFilePath,
		
		[Parameter(ParameterSetName = 'InstallShield', Mandatory = $true)]
		[ValidatePattern('\.iss$')]
		[ValidateNotNullOrEmpty()]
		[string]$IssFilePath,
		
		[Parameter(ParameterSetName = 'MSI', Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[ValidateNotNullOrEmpty()]
		[string]$MsiInstallerFilePath,
		
		[Parameter(ParameterSetName = 'MSI')]
		[ValidateNotNullOrEmpty()]
		[string]$MsiExecSwitches,
		
		[Parameter(ParameterSetName = 'MSI')]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[ValidatePattern('\.msp$')]
		[ValidateNotNullOrEmpty()]
		[string]$MspFilePath,
		
		[Parameter(ParameterSetName = 'MSI')]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[ValidatePattern('\.mst$')]
		[ValidateNotNullOrEmpty()]
		[string]$MstFilePath,
		
		[Parameter(ParameterSetName = 'InstallShield')]
		[ValidateNotNullOrEmpty()]
		[string]$InstallShieldInstallArgs,
		
		[Parameter(ParameterSetName = 'Other')]
		[ValidateNotNullOrEmpty()]
		[Alias('OtherInstallerArguments')]
		[string]$OtherInstallerArgs,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string[]]$KillProcess,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[int]$ProcessTimeout = 600,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$LogFilePath
	)
	
	process
	{
		try
		{
			
			
			## Common Start-Process parameters across all installers. We'll add to this hashtable as we go
			$ProcessParams = @{
				'NoNewWindow' = $true;
				'Passthru' = $true
			}
			
			
			if ($PSBoundParameters.ContainsKey('MsiInstallerFilePath'))
			{
				$InstallerFilePath = $MsiInstallerFilePath
				Write-Log -Message 'Creating the msiexec install string'
				
				$InstallArgs = New-MsiexecInstallString -InstallerFilePath $InstallerFilePath -MspFilePath $MspFilePath -MstFilePath $MstFilePath -LogFilePath $LogFilePath
				
				## Add Start-Process parameters
				$ProcessParams['FilePath'] = 'msiexec.exe'
				$ProcessParams['ArgumentList'] = $InstallArgs
			}
			elseif ($PSBoundParameters.ContainsKey('InstallShieldInstallerFilePath'))
			{
				$InstallerFilePath = $InstallShieldInstallerFilePath
				
				$InstallArgs = New-InstallshieldInstallString -InstallerFilePath $InstallerFilePath -LogFilePath $LogFilePath -ExtraSwitches $InstallShieldInstallArgs -IssFilePath $IssFilePath
				
				$ProcessParams['FilePath'] = $InstallerFilePath
				$ProcessParams['ArgumentList'] = $InstallArgs
			}
			elseif ($PSBoundParameters.ContainsKey('OtherInstallerFilePath'))
			{
				$InstallerFilePath = $OtherInstallerFilePath
				Write-Log -Message 'Creating a generic setup install string'
				
				## Nothing fancy here. Since we don't know any common switches to run I'll just take whatever
				## arguments are provided as a parameter.
				if ($PSBoundParameters.ContainsKey('OtherInstallerArgs'))
				{
					$ProcessParams['ArgumentList'] = $OtherInstallerArgs
				}
				$ProcessParams['FilePath'] = $OtherInstallerFilePath
				
			}
			
			## Thiw was added for upgrade scenarios where the previous version would be running and the installer
			## itself isn't smart enough to kill it.
			if ($PSBoundParameters.ContainsKey('KillProcess'))
			{
				Write-Log -Message 'Killing existing processes'
				$KillProcess | ForEach-Object { Stop-MyProcess -ProcessName $_ }
			}
			
			Write-Log -Message "Starting the command line process `"$($ProcessParams['FilePath'])`" $($ProcessParams['ArgumentList'])..."
			$Result = Start-Process @ProcessParams
			
			## This is required because sometimes depending on how the MSI is packaged, the parent process will exit
			## but will leave child processes running and the function will exit before the install is finished.
			if ($PSBoundParameters.ContainsKey('MsiInstallerFilePath'))
			{
				Wait-WindowsInstaller
			}
			else
			{
				## No special msiexec.exe waiting here.  We'll just use Wait-MyProcess to report on the waiting
				## process.
				Write-Log "Waiting for process ID $($Result.Id)"
				
				$WaitParams = @{
					'ProcessId' = $Result.Id
					'ProcessTimeout' = $ProcessTimeout
				}
				Wait-MyProcess @WaitParams
			}
			
			$outputProps = @{ }
			if ($Result.ExitCode -notin @(0, 3010))
			{
				Write-Log "Failed to install software. Installer exited with exit code [$($Result.ExitCode)]"
				$outputProps.Success = $false
			}
			else
			{
				$outputProps.Success = $true
			}
			$outputProps.ExitCode = $Result.ExitCode
			New-Object –TypeName PSObject -Property $outputProps
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Remove-Software
{
	<#
	.SYNOPSIS
		This function removes any software registered via Windows Installer from the local computer    
	.NOTES
		Created on:   	6/4/2014
		Created by:   	Adam Bertram
		Requirements:   The msizap utility (if user would like to run)
	.DESCRIPTION
		This function searches a local computer for a specified application matching a name.  Based on the
		parameters given, it can either remove services, kill proceseses and if the software is
		installed, it uses the locally cached MSI to initiate an uninstall and has the option to 
		ensure the software is completely removed by running the msizap.exe utility.
	.EXAMPLE
		Remove-Software -Name 'Adobe Reader' -KillProcess 'proc1','proc2'
		This example would remove any software with 'Adobe Reader' in the name and look for and stop both the proc1 
		and proc2 processes
	.EXAMPLE
	    Remove-Software -Name 'Adobe Reader'
		This example would remove any software with 'Adobe Reader' in the name.
	.EXAMPLE
	    Remove-Software -Name 'Adobe Reader' -RemoveService 'servicename' -Verbose
		This example would remove any software with 'Adobe Reader' in the name, look for, stop and remove any service with a 
		name of servicename. It will output all verbose logging as well.
	.EXAMPLE
	    Remove-Software -Name 'Adobe Reader' -RemoveFolder 'C:\Program Files Files\Install Folder'
		This example would remove any software with 'Adobe Reader' in the name, look for and remove the 
		C:\Program Files\Install Folder, attempt to uninstall the software cleanly via msiexec using 
		the syntax msiexec.exe /x PRODUCTMSI /qn REBOOT=ReallySuppress which would attempt to not force a reboot if needed.
		If it doesn't uninstall cleanly, it would run copy the msizap utility from the default path to 
		the local computer, execute it with the syntax msizap.exe TW! PRODUCTGUID and remove itself when done.
	.PARAMETER Name
		This is the name of the application to search for. This can be multiple products.  Each product will be removed in the
		order you specify.
	.PARAMETER MsiExecSwitches
		Specify a string of switches you'd like msiexec.exe to run when it attempts to uninstall the software. By default,
		it already uses "/x GUID /qn".  You can specify any additional parameters here.
	.PARAMETER LogFilePath
		The file path where the msiexec uninstall log will be created.  This defaults to the name of the product being
		uninstalled in the system temp directory
	.PARAMETER InstallshieldLogFilePath
		The file path where the Installshield log will be created.  This defaults to the name of the product being
		uninstalled in the system temp directory
	.PARAMETER RunMsizap
		Use this parameter to run the msizap.exe utility to cleanup any lingering remnants of the software
	.PARAMETER MsizapParams
		Specify the parameters to send to msizap if it is needed to cleanup the software on the remote computer. This
		defaults to "TWG!" which removes settings from all user profiles
	.PARAMETER MsizapFilePath
		Optionally specify where the file msizap utility is located in order to run a final cleanup
	.PARAMETER IssFilePath
		If removing an InstallShield application, use this parameter to specify the ISS file path where you recorded
		the uninstall of the application.
	.PARAMETER InstallShieldSetupFilePath
		If removing an InstallShield application, use this optional paramter to specify where the EXE installer is for
		the application you're removing.  This is only used if no cached installer is found.
	#>
	[CmdletBinding(DefaultParameterSetName = 'MSI')]
	param (
		[Parameter(ValueFromPipeline = $true, Mandatory = $true, ParameterSetName = 'FromPipeline')]
		[ValidateNotNullOrEmpty()]
		[object]$Software,
	
		[Parameter(Mandatory = $true,
				   ValueFromPipelineByPropertyName = $true)]
		[string]$Name,
		
		[Parameter(ParameterSetName = 'MSI')]
		[string]$MsiExecSwitches,
		
		[Parameter()]
		[string]$LogFilePath,
		
		[Parameter(ParameterSetName = 'ISS')]
		[string]$InstallshieldLogFilePath,
		
		[Parameter(ParameterSetName = 'Msizap')]
		[switch]$RunMsizap,
		
		[Parameter(ParameterSetName = 'Msizap')]
		[string]$MsizapParams = 'TWG!',
		
		[Parameter(ParameterSetName = 'Msizap')]
		[ValidateScript({ Test-Path $_ -PathType 'Leaf' })]
		[string]$MsizapFilePath = 'C:\MyDeployment\msizap.exe',
		
		[Parameter(ParameterSetName = 'ISS',
				   Mandatory = $true)]
		[ValidateScript({ Test-Path $_ -PathType 'Leaf' })]
		[ValidatePattern('\.iss$')]
		[string]$IssFilePath,
		
		[Parameter(ParameterSetName = 'ISS')]
		[ValidateScript({ Test-Path $_ -PathType 'Leaf' })]
		[string]$InstallShieldSetupFilePath
	)
	process
	{
		try
		{
			
			
			if ($PSCmdlet.ParameterSetName -ne 'FromPipeline')
			{
				$Software = Get-InstalledSoftware -Name $Name
			}
			
			if (-not $Software)
			{
				Write-Log -Message "The software [$($Name)]	was not found"
			}
			else
			{
				try
				{
					if ($Software.InstallLocation)
					{
						Write-Log -Message "Stopping all processes under the install folder $($Software.InstallLocation)..."
						Stop-SoftwareProcess -Software $Software
					}
					
					if ($Software.UninstallString)
					{
						$InstallerType = Get-InstallerType $Software.UninstallString
					}
					else
					{
						Write-Log -Message "Uninstall string for $Name not found" -LogLevel '2'
					}
					if (-not $PsBoundParameters['LogFilePath'])
					{
						$script:LogFilePath = "$(Get-SystemTempFolderPath)\$Name.log"
						Write-Log -Message "No log file path specified.  Defaulting to $script:LogFilePath..."
					}
					if (-not $InstallerType -or ($InstallerType -eq 'Windows Installer'))
					{
						Write-Log -Message "Installer type detected to be Windows Installer or unknown for $Name. Attempting Windows Installer removal" -LogLevel '2'
						$params = @{ }
						if ($PSBoundParameters.ContainsKey('MsiExecSwitches'))
						{
							$params.MsiExecSwitches = $MsiExecSwitches
						}
						if ($Software.GUID)
						{
							$params.Guid = $Software.GUID
						}
						else
						{
							$params.Name = $Name
						}
						
						$null = Uninstall-WindowsInstallerPackage @params
						
					}
					elseif ($InstallerType -eq 'InstallShield')
					{
						Write-Log -Message "Installer type detected as Installshield."
						$Params = @{
							'IssFilePath' = $IssFilePath;
							'Name' = $Name;
							'SetupFilePath' = $InstallShieldSetupFilePath
						}
						if ($InstallshieldLogFilePath)
						{
							$Params.InstallshieldLogFilePath = $InstallshieldLogFilePath
						}
						$null = Uninstall-InstallShieldPackage @Params
					}
					if (Test-InstalledSoftware -Name $Name)
					{
						Write-Log -Message "$Name was not uninstalled via traditional uninstall" -LogLevel '2'
						if ($RunMsizap.IsPresent)
						{
							Write-Log -Message "Attempting Msizap..."
							$null = Uninstall-ViaMsizap -Guid $Software.GUID -MsizapFilePath $MsizapFilePath -Params $MsiZapParams
						}
						else
						{
							Write-Log -Message "$Name failed to uninstall successfully" -LogLevel '3'
						}
					}

					$outputProps = @{ }
					if (-not (Test-InstalledSoftware -Name $Name))
					{
						Write-Log -Message "Successfully removed $Name!"
						$outputProps.Success = $true
					}
					else
					{
						Write-Log -Message "Failed to remove $Name" -LogLevel 3
						$outputProps.Success = $false
					}
					$outputProps.ExitCode = $Result.ExitCode
					New-Object –TypeName PSObject -Property $outputProps
				}
				catch
				{
					Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
					$PSCmdlet.ThrowTerminatingError($_)
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