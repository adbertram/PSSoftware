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
	[OutputType([bool])]
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
	[OutputType([System.Management.Automation.PSObject])]
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
			$UninstallKeys += Get-ChildItem HKU: -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } | ForEach-Object { "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
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
					foreach ($SwKey in $SwKeys)
					{
						try {
							$output = @{ }
							foreach ($ValName in $SwKey.GetValueNames() | Where-Object { $_ })
							{
								if ($ValName -ne 'Version')
								{
									Write-Verbose -Message $ValName
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
						} catch {
							Write-Log -Message $_.Exception.Message -LogLevel '2'
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
	[OutputType([void])]
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
		[string[]]$MstFilePath,
		
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
				
				$InstallArgs = Get-MsiexecInstallString -InstallerFilePath $InstallerFilePath -MspFilePath $MspFilePath -MstFilePath $MstFilePath -LogFilePath $LogFilePath -ExtraSwitches $MsiExecSwitches
				
				## Add Start-Process parameters
				$ProcessParams['FilePath'] = 'msiexec.exe'
				$ProcessParams['ArgumentList'] = $InstallArgs
			}
			elseif ($PSBoundParameters.ContainsKey('InstallShieldInstallerFilePath'))
			{
				$InstallerFilePath = $InstallShieldInstallerFilePath
				
				$InstallArgs = Get-InstallshieldInstallString -InstallerFilePath $InstallerFilePath -LogFilePath $LogFilePath -ExtraSwitches $InstallShieldInstallArgs -IssFilePath $IssFilePath
				
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
	[OutputType([void])]
	[CmdletBinding(DefaultParameterSetName = 'None')]
	param (
		[Parameter(ValueFromPipeline = $true, Mandatory = $true, ParameterSetName = 'FromPipeline')]
		[ValidateNotNullOrEmpty()]
		[object]$Software,
	
		[Parameter(Mandatory = $true,
			 ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'FromValue')]
		[string]$Name,
		
		[Parameter(ParameterSetName = 'MSI')]
		[Parameter(ParameterSetName = 'FromPipeline')]
		[Parameter(ParameterSetName = 'FromValue')]
		[string]$MsiExecSwitches,
		
		[Parameter()]
		[Parameter(ParameterSetName = 'FromPipeline')]
		[Parameter(ParameterSetName = 'FromValue')]
		[string]$LogFilePath,
		
		[Parameter(ParameterSetName = 'ISS')]
		[Parameter(ParameterSetName = 'FromPipeline')]
		[Parameter(ParameterSetName = 'FromValue')]
		[string]$InstallshieldLogFilePath,
		
		[Parameter(ParameterSetName = 'Msizap')]
		[Parameter(ParameterSetName = 'FromPipeline')]
		[Parameter(ParameterSetName = 'FromValue')]
		[switch]$RunMsizap,
		
		[Parameter(ParameterSetName = 'Msizap')]
		[Parameter(ParameterSetName = 'FromPipeline')]
		[Parameter(ParameterSetName = 'FromValue')]
		[string]$MsizapParams = 'TWG!',
		
		[Parameter(ParameterSetName = 'Msizap')]
		[Parameter(ParameterSetName = 'FromPipeline')]
		[Parameter(ParameterSetName = 'FromValue')]
		[ValidateScript({ Test-Path $_ -PathType 'Leaf' })]
		[string]$MsizapFilePath = 'C:\MyDeployment\msizap.exe',
		
		[Parameter(ParameterSetName = 'ISS',
			 Mandatory = $true)]
		[Parameter(ParameterSetName = 'FromPipeline')]
		[Parameter(ParameterSetName = 'FromValue')]
		[ValidateScript({ Test-Path $_ -PathType 'Leaf' })]
		[ValidatePattern('\.iss$')]
		[string]$IssFilePath,
		
		[Parameter(ParameterSetName = 'ISS')]
		[Parameter(ParameterSetName = 'FromPipeline')]
		[Parameter(ParameterSetName = 'FromValue')]
		[ValidateScript({ Test-Path $_ -PathType 'Leaf' })]
		[string]$InstallShieldSetupFilePath
	)
	process
	{
		try
		{
			if ($PSCmdlet.ParameterSetName -eq 'FromValue')
			{
				Write-Debug -Message "Getting installed software matching [$($Name)]"
				$Software = Get-InstalledSoftware -Name $Name	
			}
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
				Write-Log -Message "Uninstall string for $($Software.Name) not found" -LogLevel '2'
			}
			if (-not $PsBoundParameters['LogFilePath'])
			{
				$script:LogFilePath = "$(Get-SystemTempFolderPath)\$($Software.Name).log"
				Write-Log -Message "No log file path specified.  Defaulting to $script:LogFilePath..."
			}
			if (-not $InstallerType -or ($InstallerType -eq 'Windows Installer'))
			{
				Write-Log -Message "Installer type detected to be Windows Installer or unknown for $($Software.Name). Attempting Windows Installer removal" -LogLevel '2'
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
					$params.Name = $Software.Name
				}
				
				Uninstall-WindowsInstallerPackage @params
				
			}
			elseif ($InstallerType -eq 'InstallShield')
			{
				Write-Log -Message "Installer type detected as Installshield."
				$Params = @{
					'IssFilePath' = $IssFilePath;
					'Name' = $Software.Name
					'SetupFilePath' = $InstallShieldSetupFilePath
				}
				if ($InstallshieldLogFilePath)
				{
					$Params.InstallshieldLogFilePath = $InstallshieldLogFilePath
				}
				Uninstall-InstallShieldPackage @Params
			}
			if (Test-InstalledSoftware -Name $Software.Name)
			{
				Write-Log -Message "$($Software.Name) was not uninstalled via traditional uninstall" -LogLevel '2'
				if ($RunMsizap.IsPresent)
				{
					Write-Log -Message "Attempting Msizap..."
					Uninstall-ViaMsizap -Guid $Software.GUID -MsizapFilePath $MsizapFilePath -Params $MsiZapParams
				}
				else
				{
					Write-Log -Message "$($Software.Name) failed to uninstall successfully" -LogLevel '3'
				}
			}

			$outputProps = @{ }
			if (-not (Test-InstalledSoftware -Name $Software.Name))
			{
				Write-Log -Message "Successfully removed $($Software.Name)"
			}
			else
			{
				throw "Failed to remove $($Software.Name)"
			}
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Import-Certificate
{
	<#
	.SYNOPSIS
		This function imports a certificate into any certificate store on a local computer
	.EXAMPLE
		PS> Import-Certificate -Context LocalMachine -StoreName My -FilePath C:\certificate.cer

		This example will import the certificate.cert certificate into the Personal store for the 
		local computer
	.EXAMPLE
		PS> Import-Certificate -Context CurrentUser -StoreName TrustedPublisher -FilePath C:\certificate.cer

		This example will import the certificate.cer certificate into the Trusted Publishers store for the 
		currently logged on user
	.PARAMETER Context
	 	This is the Context (either CurrentUser or LocalMachine) where the store is located which the certificate
		will go into.
	.PARAMETER StoreName
		This is the certificate store that the certificate will be placed into
	.PARAMETER FilePath
		This is the path to the certificate file that you'd like to import
	#>
	[OutputType([void])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateSet('CurrentUser', 'LocalMachine')]
		[string]$Context,
		
		[Parameter(Mandatory = $true)]
		[ValidateScript({
			if ($Context -eq 'CurrentUser')
			{
				(Get-ChildItem Cert:\CurrentUser | Select-Object -ExpandProperty name) -contains $_
			}
			else
			{
				(Get-ChildItem Cert:\LocalMachine | Select-Object -ExpandProperty name) -contains $_
			}
		})]
		[string]$StoreName,
		
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path $_ -PathType Leaf })]
		[string]$FilePath
	)
	
	begin
	{
		$ErrorActionPreference = 'Stop'
		try
		{
			[void][System.Reflection.Assembly]::LoadWithPartialName('System.Security')
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
	
	process
	{
		try
		{
			$Cert = Get-Item $FilePath
			$Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $Cert
			$X509Store = New-Object System.Security.Cryptography.X509Certificates.X509Store $StoreName, $Context
			$X509Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
			$X509Store.Add($Cert)
			$X509Store.Close()
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Test-Process
{
	<#
	.SYNOPSIS
		This function is called after the execution of an external CMD process to log the status of how the process was exited.
	.PARAMETER Process
		A System.Diagnostics.Process object type that is output by using the -Passthru parameter on the Start-Process cmdlet
	#>
	[OutputType([bool])]
	[CmdletBinding()]
	param (
		[Parameter()]
		[System.Diagnostics.Process]$Process
	)
	process
	{
		try
		{
			
			if (@(0, 3010) -notcontains $Process.ExitCode)
			{
				Write-Log -Message "Process ID $($Process.Id) failed. Return value was $($Process.ExitCode)" -LogLevel '2'
				$false
			}
			else
			{
				Write-Log -Message "Process ID $($Process.Id) exited with successfull exit code '$($Process.ExitCode)'."
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

function Get-ChildProcess
{
	<#
	.SYNOPSIS
		This function childs all child processes a parent process has spawned
	.PARAMETER ProcessId
		The potential parent process ID
	#>
	[OutputType([System.Management.ManagementObject])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]$ProcessId
	)
	process
	{
		try
		{
			Get-WmiObject -Class Win32_Process -Filter "ParentProcessId = '$ProcessId'"
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Stop-MyProcess
{
	<#
	.SYNOPSIS
		This function stops a process while provided robust logging of the activity
	.PARAMETER ProcessName
		One more process names
	#>
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess = $true)]
	param (
		[Parameter(Mandatory = $true)]
		[string[]]$ProcessName
	)
	process
	{
		try
		{
			
			$ProcessesToStop = Get-Process -Name $ProcessName -ErrorAction 'SilentlyContinue'
			if (-not $ProcessesToStop)
			{
				Write-Log -Message "-No processes to be killed found..."
			}
			else
			{
				foreach ($process in $ProcessesToStop)
				{
					Write-Log -Message "-Process $($process.Name) is running. Attempting to stop..."
					$WmiProcess = Get-WmiObject -Class Win32_Process -Filter "name='$($process.Name).exe'" -ErrorAction 'SilentlyContinue' -ErrorVariable WMIError
					if ($WmiError)
					{
						throw "process $($process.Name). WMI query errored with `"$($WmiError.Exception.Message)`""
					}
					elseif ($WmiProcess)
					{
						foreach ($p in $WmiProcess)
						{
							if ($PSCmdlet.ShouldProcess("Process ID: $($p.ProcessId)", 'Stop'))
							{
								$WmiResult = $p.Terminate()
								if ($WmiResult.ReturnValue -eq 1603)
								{
									Write-Log -Message "Process $($p.name) exited successfully but needs a reboot."
								}
								elseif ($WmiResult.ReturnValue -ne 0)
								{
									throw "-Unable to stop process $($p.name). Return value was $($WmiResult.ReturnValue)"
								}
								else
								{
									Write-Log -Message "-Successfully stopped process $($p.Name)..."
								}
							}
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

function Stop-SoftwareProcess
{
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true,ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[object]$Software
	)
	begin {
		$ErrorActionPreference = 'Stop'
	}
	process {
		try
		{
			$Processes = (Get-Process | Where-Object { $_.Path -like "$($Software.InstallLocation)*" } | Select-Object -ExpandProperty Name)
			if ($Processes)
			{
				Write-Log -Message "Sending processes: $Processes to Stop-MyProcess..."
				## Check to see if the process is still running.  It's possible the termination of other processes
				## already killed this one.
				$Processes = $Processes | Where-Object { Get-Process -Name $_ -ErrorAction 'SilentlyContinue' }
				if ($PSCmdlet.ShouldProcess("Process ID $($Processes)", 'Stop'))
				{
					Stop-MyProcess $Processes
				}
			}
			else
			{
				Write-Log -Message 'No processes running under the install folder path'
			}
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Wait-MyProcess
{
	<#
	.SYNOPSIS
		This function waits for a process and waits for all that process's children before releasing control
	.PARAMETER ProcessId
		A process Id
	.PARAMETER ProcessTimeout
		An interval (in seconds) to wait for the process to finish.  If the process hasn't exited within this timeout
		it will be terminated.  The default is 600 seconds (5 minutes) so no process will run longer than that.
	.PARAMETER ReportInterval
		The number of seconds between when it is logged that the process is still pending

	#>
	[OutputType([void])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[int]$ProcessId,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[int]$ProcessTimeout = 600,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[int]$ReportInterval = 15
		
	)
	process
	{
		try
		{
			Write-Log -Message "Finding the process ID '$ProcessId'..."
			$Process = Get-Process -Id $ProcessId -ErrorAction 'SilentlyContinue'
			if ($Process)
			{
				Write-Log -Message "Process '$($Process.Name)' ($($Process.Id)) found. Waiting to finish and capturing all child processes."

				## While waiting for the initial process to stop, collect all child IDs it spawns
				$ChildProcessesToLive = @()
				
				## Start the timer to ensure we have a point to get total time from
				$Timer = [Diagnostics.Stopwatch]::StartNew()
				$i = 0
				
				## Do this while the parent process is still running
				while (-not $Process.HasExited)
				{
					## Find any and all child processes the parent process spawned
					$ChildProcesses = Get-ChildProcess -ProcessId $ProcessId
					if ($ChildProcesses)
					{
						Write-Log -Message "Found [$(@($ChildProcesses).Count)] child process(es)"
						## If any child processes are found, collect them all
						$ChildProcessesToLive += $ChildProcesses
					}
					if ($Timer.Elapsed.TotalSeconds -ge $ProcessTimeout)
					{
						Write-Log -Message "The process '$($Process.Name)' ($($Process.Id)) has exceeded the timeout of $ProcessTimeout seconds.  Killing process."
						$Timer.Stop()
						Stop-MyProcess -ProcessName $Process.Name
					}
					elseif (($i % $ReportInterval) -eq 0) ## Use a modulus here to write to the log every X seconds
					{
						Write-Log "Still waiting for process '$($Process.Name)' ($($Process.Id)) after $([Math]::Round($Timer.Elapsed.TotalSeconds, 0)) seconds"
					}
					Start-Sleep -Milliseconds 100
					$i++
				}

				Write-Log "Process '$($Process.Name)' ($($Process.Id)) has finished after $([Math]::Round($Timer.Elapsed.TotalSeconds, 0)) seconds"
				if ($ChildProcessesToLive) ## If any child processes were spawned while the parent process was running
				{
					$ChildProcessesToLive = $ChildProcessesToLive | Select-Object -Unique ## Ensure we didn't accidently capture duplicate PIDs
					Write-Log -Message "Parent process '$($Process.Name)' ($($Process.Id)) has finished but still has $(@($ChildProcessesToLive).Count) child processes ($($ChildProcessesToLive.Name -join ',')) left.  Waiting on these to finish."
					foreach ($Process in $ChildProcessesToLive)
					{
						Wait-MyProcess -ProcessId $Process.ProcessId
					}
				}
				else
				{
					Write-Log -Message 'No child processes found spawned'
				}
				Write-Log -Message "Finished waiting for process '$($Process.Name)' and all child processes"
			}
			else
			{
				Write-Log -Message "Process ID '$ProcessId' not found.  No need to wait on it."
			}
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Get-InstallshieldInstallString
{
	[OutputType([string])]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$InstallerFilePath,
	
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$IssFilePath,
	
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$LogFilePath,
	
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$ExtraSwitches
	)
	begin {
		$ErrorActionPreference = 'Stop'
	}
	process {
		try
		{
			Write-Log -Message 'Creating the InstallShield setup install string'
			
			## We're adding common InstallShield switches here. -s is silent, -f1 specifies where the 
			## ISS file we createed previously lives, -f2 specifies a log file location and /SMS is a special
			## switch that prevents the setup.exe was exiting prematurely.
			if (-not $PSBoundParameters.ContainsKey('LogFilePath'))
			{
				$LogFilePath = "$(Get-SystemTempFolderPath)\$($InstallerFilePath | Split-Path -Leaf).log"
			}
			if (-not $ExtraSwitches)
			{
				$InstallArgs = "-s -f1`"$IssFilePath`" -f2`"$LogFilePath`" /SMS"
			}
			else
			{
				$InstallArgs = "-s -f1`"$IssFilePath`" $ExtraSwitches -f2`"$LogFilePath`" /SMS"
			}
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Uninstall-InstallShieldPackage
{
	<#
	.SYNOPSIS
		This function runs an uninstall for any InstallShield packaged software.  This function utilitizes an
		InstallShield ISS file to silently uninstall the application.
	.PARAMETER Name
		One or more software titles of the InstallShield package you'd like to uninstall.
	.PARAMETER IssFilePath
		The file path where the pre-built silent answer file (ISS) is located.
	.PARAMETER SetupFilePath
		The file path where the EXE InstallShield installer is located.
	.PARAMETER LogFilePath
		The log file path where the InstallShield installer will log results.  If not log file path
		is specified it will be created in the system temp folder.
	#>
	[OutputType([void])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string[]]$Name,
		
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[string]$IssFilePath,
		
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[string]$SetupFilePath,
		
		[ValidateScript({ Test-Path -Path ($_ | Split-Path -Parent) -PathType 'Container' })]
		[string]$LogFilePath = "(Get-SystemTempFolderPath)\IssSetupLog.log"
	)
	process
	{
		try
		{
			
			foreach ($Product in $Name)
			{
				Write-Log -Message "Beginning uninstall for Installshield product '$Name'"
				## Find the uninstall string to find the cached setup.exe
				$Products = Get-InstalledSoftware $Product
				## If multiple products are found, remove them all
				foreach ($p in $Products)
				{
					$UninstallString = $p.UninstallString
					## Check to ensure anything is in the UninstallString property
					if (-not $p.UninstallString)
					{
						Write-Log -Message "No uninstall string found for product $Title" -LogLevel '2'
					}
					elseif ($p.UninstallString -match '(\w:\\[a-zA-Z0-9 _.() { }-]+\\.*.exe)+')
					{
						## Test to ensure the cached setup.exe exists
						if (-not (Test-Path $Matches[0]))
						{
							Write-Log -Message "Installer file path not found in $($p.UninstallString) or cannot be found on the file system" -LogLevel '2'
						}
						else
						{
							$InstallerFilePath = $Matches[0]
							Write-Log -Message "Valid installer file path is $InstallerFilePath"
						}
					}
					if (-not $InstallerFilePath)
					{
						if (-not $SetupFilePath)
						{
							Write-Log -Message "No setup folder path specified. This software cannot be removed" -LogLevel '2'
							continue
						}
						else
						{
							$InstallerFilePath = $SetupFilePath
						}
					}
					## Run the setup.exe passing the ISS file to uninstall
					if ($InstallshieldLogFilePath)
					{
						$MyLogFilePath = $InstallshieldLogFilePath
					}
					else
					{
						$MyLogFilePath = $script:LogFilePath
					}
					$InstallArgs = "/s /f1`"$IssFilePath`" /f2`"$MyLogFilePath`" /SMS"
					Write-Log -Message "Running the install syntax `"$InstallerFilePath`" $InstallArgs"
					$Process = Start-Process "`"$InstallerFilePath`"" -ArgumentList $InstallArgs -Wait -NoNewWindow -PassThru
					if (-not (Test-InstalledSoftware $Title))
					{
						Write-Log -Message "The product $Title was successfully removed!"
					}
					else
					{
						Write-Log -Message "The product $Title was not removed.  Attempting secondary uninstall method" -LogLevel '2'
						## Parse out the EXE file path and arguments.  This regex could be improved on big time.
						$FilePathRegex = '(([a-zA-Z]\:|\\)\\([^\\]+\\)*[^\/:*?"<>|]+\.[a-zA-Z]{3})" (.+)'
						if ($UninstallString -match $FilePathRegex)
						{
							$InstallerFilePath = $matches[1]
							$InstallArgs = $matches[4]
							$InstallArgs = "$InstallArgs /s /f1`"$IssFilePath`" /f2`"$MyLogFilePath`" /SMS"
							Write-Log -Message "Running the install syntax `"$InstallerFilePath`" $InstallArgs"
							$Process = Start-Process "`"$InstallerFilePath`"" -ArgumentList $InstallArgs -Wait -NoNewWindow -PassThru
							if (-not (Test-InstalledSoftware $Title))
							{
								throw "The product '$Title' was not removed!"
							}
						}
						else
						{
							throw "Could not parse out the setup installer and arguments from uninstall string. The product '$Title' was not removed!"
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

function Start-Log
{
	<#
	.SYNOPSIS
		This function creates the initial log file and sets a few global variables
		that are common among the session.  Call this function at the very top of your
		installer script.

	.PARAMETER  FilePath
		The file path where you'd like to place the log file on the file system.  If no file path
		specified, it will create a file in the system's temp directory named the same as the script
		which called this function with a .log extension.

	.EXAMPLE
		PS C:\> Start-Log -FilePath 'C:\Temp\installer.log

	.NOTES

	#>
	[OutputType([void])]
	[CmdletBinding()]
	param (
		[ValidateScript({ Split-Path $_ -Parent | Test-Path })]
		[string]$FilePath = "$(Get-SystemTempFolderPath)\PSSoftware.log"
	)
	
	try
	{
		if (-not (Test-Path $FilePath))
		{
			## Create the log file
			New-Item $FilePath -ItemType File | Out-Null
		}
		
		## Set the global variable to be used as the FilePath for all subsequent Write-Log
		## calls in this session
		$global:ScriptLogFilePath = $FilePath
	}
	catch
	{
		Write-Error $_.Exception.Message
	}
}

function Write-Log
{
	<#
	.SYNOPSIS
		This function creates or appends a line to a log file

	.DESCRIPTION
		This function writes a log line to a log file in the form synonymous with 
		ConfigMgr logs so that tools such as CMtrace and SMStrace can easily parse 
		the log file.  It uses the ConfigMgr client log format's file section
		to add the line of the script in which it was called.

	.PARAMETER  Message
		The message parameter is the log message you'd like to record to the log file

	.PARAMETER  LogLevel
		The logging level is the severity rating for the message you're recording. Like ConfigMgr
		clients, you have 3 severity levels available; 1, 2 and 3 from informational messages
		for FYI to critical messages that stop the install. This defaults to 1.

	.EXAMPLE
		PS C:\> Write-Log -Message 'Value1' -LogLevel 'Value2'
		This example shows how to call the Write-Log function with named parameters.

	.NOTES

	#>
	[OutputType([void])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]$Message,
		
		[Parameter()]
		[ValidateSet(1, 2, 3)]
		[int]$LogLevel = 1
	)
	Set-StrictMode -Off
	try
	{
		$TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
		## Build the line which will be recorded to the log file
		$Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
		$LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel
		$Line = $Line -f $LineFormat
		
		if (-not (Test-Path Variable:\ScriptLogFilePath))
		{
			Write-Verbose -Message $Message
		}
		else
		{
			Add-Content -Value $Line -Path $ScriptLogFilePath
		}
	}
	catch
	{
		Write-Error $_.Exception.Message
	}
}

function New-TempFile
{
	<#
	.SYNOPSIS
		This function creates a temporary file

	.DESCRIPTION
		This function creates a file in the $env:TEMP directory. It's purpose is to create a file
		that doesn't conflict with other files so you don't lose data unintentionally.

	.EXAMPLE
		PS C:\> New-TempFile
		This example shows how to call the New-TempFile function.

	.NOTES

	#>
	[OutputType([System.IO.FileInfo])]
	[CmdletBinding()]
	param()
	if($PSVersionTable.PSVersion.Major -ge 5)
	{
		New-TemporaryFile
	}
	else
	{
		$temp = $env:TEMP
		do
		{
			$filename = "tmp$(Get-Random -max 0xffffff).tmp"
		} while (Test-Path "$temp\$filename")
		New-Item "$temp\$filename"
	}
}

function Convert-CompressedGuidToGuid
{
	<#
	.SYNOPSIS
		This converts a compressed GUID also known as a product code into a GUID.	
	.DESCRIPTION
		This function will typically be used to figure out the MSI installer GUID
		that matches up with the product code stored in the 'SOFTWARE\Classes\Installer\Products'
		registry path.
	.EXAMPLE
		Convert-CompressedGuidToGuid -CompressedGuid '2820F6C7DCD308A459CABB92E828C144'
	
		This example would output the GUID '{7C6F0282-3DCD-4A80-95AC-BB298E821C44}'
	.PARAMETER CompressedGuid
		The compressed GUID you'd like to convert.
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param (
		[Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
		[ValidatePattern('^[0-9a-fA-F]{32}$')]
		[string]$CompressedGuid
	)
	process
	{
		try
		{
			$Indexes = [ordered]@{
				0 = 8;
				8 = 4;
				12 = 4;
				16 = 2;
				18 = 2;
				20 = 2;
				22 = 2;
				24 = 2;
				26 = 2;
				28 = 2;
				30 = 2
			}
			$Guid = '{'
			foreach ($index in $Indexes.GetEnumerator())
			{
				$part = $CompressedGuid.Substring($index.Key, $index.Value).ToCharArray()
				[array]::Reverse($part)
				$Guid += $part -join ''
			}
			$Guid = $Guid.Insert(9, '-').Insert(14, '-').Insert(19, '-').Insert(24, '-')
			$Guid + '}'
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Convert-GuidToCompressedGuid
{
	<#
	.SYNOPSIS
		This converts a GUID to a compressed GUID also known as a product code.	
	.DESCRIPTION
		This function will typically be used to figure out the product code
		that matches up with the product code stored in the 'SOFTWARE\Classes\Installer\Products'
		registry path to a MSI installer GUID.
	.EXAMPLE
		Convert-GuidToCompressedGuid -Guid '{7C6F0282-3DCD-4A80-95AC-BB298E821C44}'
	
		This example would output the compressed GUID '2820F6C7DCD308A459CABB92E828C144'
	.PARAMETER Guid
		The GUID you'd like to convert.
	#>
	[OutputType([string])]
	[CmdletBinding()]
	param (
		[Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
		[string]$Guid
	)
	begin
	{
		$Guid = $Guid.Replace('-', '').Replace('{', '').Replace('}', '')
	}
	process
	{
		try
		{
			
			$Groups = @(
			$Guid.Substring(0, 8).ToCharArray(),
			$Guid.Substring(8, 4).ToCharArray(),
			$Guid.Substring(12, 4).ToCharArray(),
			$Guid.Substring(16, 16).ToCharArray()
			)
			$Groups[0..2] | ForEach-Object {
				[array]::Reverse($_)
			}
			$CompressedGuid = ($Groups[0..2] | ForEach-Object { $_ -join '' }) -join ''
			
			$chararr = $Groups[3]
			for ($i = 0; $i -lt $chararr.count; $i++)
			{
				if (($i % 2) -eq 0)
				{
					$CompressedGuid += ($chararr[$i + 1] + $chararr[$i]) -join ''
				}
			}
			$CompressedGuid
			
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Convert-ToUncPath
{
	<#
	.SYNOPSIS
		A simple function to convert a local file path and a computer name to a network UNC path.
	.PARAMETER LocalFilePath
		A file path ie. C:\Windows\somefile.txt
	.PARAMETER Computername
		The computer in which the file path exists on
	#>
	[OutputType([string])]
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]$LocalFilePath,
		
		[Parameter()]
		[string]$Computername
	)
	process
	{
		try
		{
			
			$RemoteFilePathDrive = ($LocalFilePath | Split-Path -Qualifier).TrimEnd(':')
			"\\$Computername\$RemoteFilePathDrive`$$($LocalFilePath | Split-Path -NoQualifier)"
			
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Get-32BitProgramFilesPath
{
	<#
	.SYNOPSIS
		On x64 machines the x86 program files path is Program Files (x86) while on x86 machines it's just Program Files.  This function
		does that decision for you and just outputs the x86 program files path regardless of OS architecture
	#>
	[OutputType([string])]
	[CmdletBinding()]
	param ()
	process
	{
		try
		{
			
			if ((Get-Architecture) -eq 'x64')
			{
				${env:ProgramFiles(x86)}
			}
			else
			{
				$env:ProgramFiles
			}
			
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Get-32BitRegistrySoftwarePath
{
	<#
	.SYNOPSIS
		On x64 machines the x86 Software registry key path is HKLM:\SOFTWARE\Wow6432Node while on x86 machines it's just 
		HKLM:\Software. This function does that decision for you and just outputs the x86 path regardless of OS architecture.
	.PARAMETER Scope
		Specify either HKLM or HKCU.  Defaults to HKLM.
	#>
	[OutputType([string])]
	[CmdletBinding()]
	param (
		[ValidateSet('HKLM', 'HKCU')]
		[string]$Scope = 'HKLM'
	)
	process
	{
		try
		{
			
			if ((Get-Architecture) -eq 'x64')
			{
				"$Scope`:\SOFTWARE\Wow6432Node"
			}
			else
			{
				"$Scope`:\SOFTWARE"
			}
			
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Get-Architecture
{
	<#
	.SYNOPSIS
		This simple function tells you whether the machine you're running on is either x64 or x86
	#>
	[OutputType([string])]
	[CmdletBinding()]
	param ()
	process
	{
		try
		{
			if ((Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty SystemType) -eq 'x64-based PC')
			{
				'x64'
			}
			else
			{
				'x86'
			}
			
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Get-DriveFreeSpace
{
	<#
	.SYNOPSIS
		This finds the total hard drive free space for one or multiple hard drive partitions
	.DESCRIPTION
		This finds the total hard drive free space for one or multiple hard drive partitions. It returns free space
		rounded to the nearest SizeOutputLabel parameter
	.PARAMETER  DriveLetter
		This is the drive letter of the hard drive partition you'd like to query. By default, all drive letters are queried.
	.PARAMETER  SizeOutputLabel
		In what size increments you'd like the size returned (KB, MB, GB, TB). Defaults to MB.
	.PARAMETER  Computername
		The computername(s) you'd like to find free space on.  This defaults to the local machine.
	.EXAMPLE
		PS C:\> Get-DriveFreeSpace -DriveLetter 'C','D'
		This example retrieves the free space on the C and D drive partition.
	#>
	[CmdletBinding()]
	[OutputType([array])]
	param
	(
		[string[]]$Computername = 'localhost',
		
		[Parameter(ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true)]
		[ValidatePattern('[A-Z]')]
		[string]$DriveLetter,
		
		[ValidateSet('KB', 'MB', 'GB', 'TB')]
		[string]$SizeOutputLabel = 'MB'
		
	)
	
	Begin
	{
		try
		{
			
			$WhereQuery = "SELECT FreeSpace,DeviceID FROM Win32_Logicaldisk"
			
			if ($PsBoundParameters.DriveLetter)
			{
				$WhereQuery += ' WHERE'
				$BuiltQueryParams = { @() }.Invoke()
				foreach ($Letter in $DriveLetter)
				{
					$BuiltQueryParams.Add("DeviceId = '$DriveLetter`:'")
				}
				$WhereQuery = "$WhereQuery $($BuiltQueryParams -join ' OR ')"
			}
			Write-Debug "Using WQL query $WhereQuery"
			$WmiParams = @{
				'Query' = $WhereQuery
			}
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
	Process
	{
		try
		{
			foreach ($Computer in $Computername)
			{
				try
				{
					$WmiParams.Computername = $Computer
					$WmiResult = Get-WmiObject @WmiParams
					if (-not $WmiResult)
					{
						throw "Drive letter does not exist on target system"
					}
					foreach ($Result in $WmiResult)
					{
						if ($Result.Freespace)
						{
							[pscustomobject]@{
								'Computername' = $Computer;
								'DriveLetter' = $Result.DeviceID;
								'Freespace' = [int]($Result.FreeSpace / "1$SizeOutputLabel")
							}
						}
					}
				}
				catch
				{
					throw $_
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

function Get-InstallerType
{
	<#
	.SYNOPSIS
		Based on the uninstall string retrieved from the registry this function will tell you what kind of installer was
		used to install the product.  This information is helpful when figuring out the best way to remove software.
	
	.PARAMETER UninstallString
		The uninstall string that's stored in the HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\%GUID% UninstallString
		registry value.
	#>
	[OutputType([string])]
	[CmdletBinding()]
	param (
		[string]$UninstallString
	)
	
	process
	{
		try
		{
			
			if ($UninstallString -imatch 'msiexec.exe')
			{
				'Windows Installer'
			}
			elseif ($UninstallString -imatch 'InstallShield Installation')
			{
				'InstallShield'
			}
			else
			{
				throw "Could not determine installer type for uninstall string [$($UninstallString)]"
			}
			
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Get-LoggedOnUserSID
{
	<#
	.SYNOPSIS
		This function queries the registry to find the SID of the user that's currently logged onto the computer interactively.
	#>
	[OutputType([string])]
	[CmdletBinding()]
	param ()
	process
	{
		try
		{
			
			
			if (-not (Get-PSDrive -Name 'HKU' -ErrorAction SilentlyContinue))
			{
				New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
				## Every user that's logged on has a registry key in HKU with their SID
				Get-ChildItem HKU: | Where-Object { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } | Select -ExpandProperty PSChildName
			}
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Get-OperatingSystem
{
	<#
	.SYNOPSIS
		This function queries the operating system name from WMI.
	.DESCRIPTION
		Using a WMI query, this function uses the Win32_OperatingSystem WMI class
		to output the operating system running on $Computername
	.PARAMETER Computername
		The name of the computer to query.  This defaults to the local host.
	.EXAMPLE
		PS C:\> Get-OperatingSystem -Computername MYCOMPUTER
		
		This example finds the operating system on a computer named MYCOMPUTER
	#>
	[OutputType([string])]
	[CmdletBinding()]
	param (
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Computername = 'localhost'
	)
	process
	{
		try
		{	
			(Get-WmiObject -ComputerName $Computername -Query 'SELECT Caption FROM Win32_OperatingSystem').Caption
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Get-SystemTempFolderPath
{
	<#
	.SYNOPSIS
		This function uses the TEMP system environment variable to easily discover the folder path
		to the system's temp folder
	#>
	[OutputType([string])]
	[CmdletBinding()]
	param ()
	process
	{
		try
		{
			[environment]::GetEnvironmentVariable('TEMP', 'Machine')
			
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Get-RegistryValue
{
	<#
	.SYNOPSIS
		This functions finds the typical registry value like Get-ItemProperty does but also returns
		the registry value type as well.
	.EXAMPLE
		PS> Get-MyRegistryValue -Path HKLM:\Software\7-Zip -Name 'Name'
	
		This example gets the registry data and type for the value 'Name' in the HKLM:\Software\7-Zip key
	.PARAMETER Path
	 	The path to the parent registry key
	.PARAMETER Name
		The name of the registry value
	#>
	[OutputType([PSObject])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidatePattern('^\w{4}:')]
		[string]$Path,
		
		[Parameter(Mandatory = $true)]
		[string]$Name
	)
	process
	{
		try
		{
			$Key = Get-Item -Path $Path -ErrorAction 'SilentlyContinue'
			if (-not $Key)
			{
				throw "The registry key $Path does not exist"
			}
			$Value = $Key.GetValue($Name)
			if (-not $Value)
			{
				throw "The registry value $Name in the key $Path does not exist"
			}
			[pscustomobject]@{ 'Path' = $Path; 'Value' = $Value; 'Type' = $key.GetValueKind($Name) }
			
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Get-AllUsersRegistryValue
{
    <#
	.SYNOPSIS
		This function finds all of the user profile registry hives, mounts them and retrieves a registry value for each user.
	.EXAMPLE
		PS> Get-AllUsersRegistryValue -RegistryInstance @{'Name' = 'Setting'; 'Path' = 'SOFTWARE\Microsoft\Windows\Something'}
	
		This example would get the string registry value 'Type' in the path 'SOFTWARE\Microsoft\Windows\Something'
		for every user registry hive.
	.PARAMETER RegistryInstance
	 	A hash table containing key names of 'Name' designating the registry value name and 'Path' designating the parent 
		registry key the registry value is in.
	#>
	[OutputType([System.Management.Automation.PSCustomObject])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[hashtable[]]$RegistryInstance
	)
	try
	{
		
		New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
		
		## Find the registry values for the currently logged on user
		$LoggedOnSids = Get-LoggedOnUserSID
		Write-Log -Message "Found $(@($LoggedOnSids).Count) logged on user SIDs"
		foreach ($sid in $LoggedOnSids)
		{
			Write-Log -Message "Loading the user registry hive for the logged on SID $sid"
			foreach ($instance in $RegistryInstance)
			{
				$Value = Get-ItemProperty -Path "HKU:\$sid\$($instance.Path)" -Name $instance.Name -ErrorAction SilentlyContinue
				if (-not $Value)
				{
					Write-Log -Message "Registry value $($instance.name) does not exist in HKU:\$sid\$($instance.Path)" -LogLevel '2'
				}
				else
				{
					$Value
				}
			}
		}

		$loggedOffUsers = Get-UserProfile -ExcludeSystemProfiles | where { $LoggedOnSids -notcontains $_.SID } | Select -ExpandProperty UserName
		
		foreach ($user in $loggedOffUsers)
		{
			try {
				Write-Log -Message "Loading the user registry hive for user $user..."
				LoadRegistryHive -Username $user
				foreach ($instance in $RegistryInstance)
				{
					$Value = Get-ItemProperty -Path "HKU:\TempUserLoad\$($instance.Path)" -Name $instance.Name -ErrorAction SilentlyContinue
					if (-not $Value)
					{
						Write-Log -Message "Registry value $($instance.name) does not exist in HKU:\TempUserLoad\$($instance.Path)" -LogLevel '2'
					}
					else
					{
						$Value
					}
				}
				UnloadRegistryHive
			} catch {
				Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'		
			}
		}
		
	}
	catch
	{
		Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
		$PSCmdlet.ThrowTerminatingError($_)
	}
}

function Get-AllUsersRegistryKey
{
    <#
	.SYNOPSIS
		This function finds all of the user profile registry hives, mounts them and retrieves a registry key for each user.
	.EXAMPLE
		PS> Get-AllUsersRegistryKey -Path 'SOFTWARE\Microsoft\Windows\Something'
	
	.PARAMETER Path
	 	A string representing the path to the registry key.
	#>
	[OutputType([System.Management.Automation.PSCustomObject])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]$Path
	)
	try
	{
		
		New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
		
		$LoggedOnSids = Get-LoggedOnUserSID
		Write-Log -Message "Found $(@($LoggedOnSids).Count) logged on user SIDs"
		foreach ($sid in $LoggedOnSids)
		{
			try {
				Write-Log -Message "Loading the user registry hive for the logged on SID $sid"
				$key = Get-Item -Path "HKU:\$sid\$Path" -ErrorAction SilentlyContinue
				if (-not $key)
				{
					Write-Log -Message "Registry key does not exist at HKU:\$sid\$Path" -LogLevel '2'
				}
				else
				{
					$key
				}
			} catch {
				Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'		
			} finally {
				UnloadRegistryHive
			}
		}

		$loggedOffUsers = Get-UserProfile -ExcludeSystemProfiles | where { $LoggedOnSids -notcontains $_.SID } | Select -ExpandProperty UserName
		
		foreach ($user in $loggedOffUsers)
		{
			try {
				Write-Log -Message "Loading the user registry hive for user $user..."
				LoadRegistryHive -Username $user
				$key = Get-Item -Path "HKU:\TempUserLoad\$Path" -ErrorAction SilentlyContinue
				if (-not $key)
				{
					Write-Log -Message "Registry key does not exist at HKU:\TempUserLoad\$Path" -LogLevel '2'
				}
				else
				{
					$key
				}
			} catch {
				Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'		
			} finally {
				UnloadRegistryHive
			}
		}
		
	}
	catch
	{
		Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
		$PSCmdlet.ThrowTerminatingError($_)
	}
}

function LoadRegistryHive
{
	[OutputType([System.IO.FileInfo])]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$UserName		
	)
	try {
		$regExePath = GetRegExePath
		$profilePath = Get-UserProfilePath -Username $UserName
		Write-Log -Message "Loading registry hive [$profilePath\NtUser.dat]..."
		$Process = Start-Process -FilePath $regExePath -ArgumentList "load HKU\TempUserLoad `"$profilePath\NTuser.dat`"" -Wait -NoNewWindow -PassThru
		Test-Process $Process | Out-Null
	} catch {
		Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
		$PSCmdlet.ThrowTerminatingError($_)
	}
	
}

function UnloadRegistryHive
{
	[CmdletBinding()]
	param
	()

	$regExePath = GetRegExePath
	Write-Log -Message "Unloading HKU\TempUserLoad..."
	$Process = Start-Process -FilePath $regExePath -ArgumentList "unload HKU\TempUserLoad" -Wait -NoNewWindow -PassThru
	## TODO This seems to work but returns 1. Commenting out for now
	# Test-Process $Process | Out-Null
}

function GetRegExePath
{
	[OutputType([string])]
	[CmdletBinding()]
	param
	()

	if ((Get-Architecture) -eq 'x64')
	{
		$RegPath = 'syswow64'
	}
	else
	{
		$RegPath = 'System32'
	}

	"$($env:Systemdrive)\Windows\$RegPath\reg.exe"
	
}

function Import-RegistryFile
{
	<#
	.SYNOPSIS
		A function that uses the utility reg.exe to do a bulk import of registry changes.
	.DESCRIPTION
		This function allows the user to import registry changes in bulk by means of a .reg file.  This
		.reg file should only contain 1 set of registry keys such as HKLM or HKCU.  If the .reg file
		contains HKLM, HKCU, HKCR or HKCC key references, the file will be imported directly with no modification.  If the 
		.reg file contains HKCU references, it will be modified to account for the currently logged on interactive
		user, copied to a location on the computer and will be imported under each HKCU hive when another user
		logs on.
	.PARAMETER FilePath
		The file path to the .reg file
	#>
	[OutputType([void])]
	[CmdletBinding()]
	param (
		[Parameter()]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[string]$FilePath
	)
	begin
	{
		try
		{
			
			## Detect if this is a registry file for HKCU, HKLM, HKU, HKCR or HKCC keys
			$Regex = 'HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_LOCAL_MACHINE|HKEY_USERS|HKEY_CURRENT_CONFIG'
			$HiveNames = Select-String -Path $FilePath -Pattern $Regex | ForEach-Object { $_.Matches.Value }
			$RegFileHive = $HiveNames | Select-Object -Unique
			if ($RegFileHive -is [array])
			{
				throw "The registry file at '$FilePath' contains more than one hive reference."
			}
			else
			{
				Write-Log -Message "Detected hive type as $RegFileHive"
			}
			if ((Get-Architecture) -eq 'x64')
			{
				$RegPath = 'syswow64'
			}
			else
			{
				$RegPath = 'System32'
			}
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
		
	}
	process
	{
		try
		{
			if ($RegFileHive -ne 'HKEY_CURRENT_USER')
			{
				Write-Log -Message "Starting registry import of reg file $FilePath..."
				$tempFile = New-TempFile
				($Result = Start-Process "$($env:Systemdrive)\Windows\$RegPath\reg.exe" -ArgumentList "import `"$FilePath`"" -Wait -NoNewWindow -PassThru -RedirectStandardError $tempFile)  | Out-Null
				Remove-Item $tempFile
				Test-Process -Process $Result
				Write-Log -Message 'Registry file import done'
			}
			else
			{
				#########
				## Import the registry file for the currently logged on user
				#########
				$LoggedOnSids = Get-LoggedOnUserSID
				if ($LoggedOnSids.Count -gt 0)
				{
					Write-Log -Message "Found $($LoggedOnSids.Count) logged on user SIDs"
					foreach ($sid in $LoggedOnSids)
					{
						## Replace all HKEY_CURRENT_USER references to HKCU\%SID% so that it can be applied to HKCU while not
						## actually running under that context.  Create a new reg file with the replacements in the system's temp folder
						$HkcuRegFilePath = "$(Get-SystemTempFolderPath)\$($FilePath | Split-Path -Leaf)"
						Write-Log -Message "Replacing HKEY_CURRENT_USER references with HKEY_USERS\$sid and placing temp file in $HkcuRegFilePath"
						Find-InTextFile -FilePath $FilePath -Find $RegFileHive -Replace "HKEY_USERS\$sid" -NewFilePath $HkcuRegFilePath -Force
						
						## Perform a recursive function call to itself to import the newly created reg file
						Write-Log -Message "Importing reg file $HkcuRegFilePath"
						Import-RegistryFile -FilePath $HkcuRegFilePath
						Write-Log -Message "Removing temporary registry file $HkcuRegFilePath"
						Remove-Item $HkcuRegFilePath -Force
					}
				}
				else
				{
					Write-Log -Message 'No users currently logged on.  Skipping current user registry import'
				}
				
				########
				## Use Active Setup to create a registry value to perform an import of the registry file for each logged on user
				########
				Write-Log -Message "Copying $FilePath to systemp temp folder for later user"
				Copy-Item -Path $FilePath -Destination "$(Get-SystemTempFolderPath)\$($FilePath | Split-Path -Leaf)"
				Write-Log -Message "Setting Everyone full control on temp registry file so all users can import it"
				$Params = @{
					'Path' = "$(Get-SystemTempFolderPath)\$($FilePath | Split-Path -Leaf)"
					'Identity' = 'Everyone'
					'Right' = 'Modify';
					'InheritanceFlags' = 'None';
					'PropagationFlags' = 'NoPropagateInherit';
					'Type' = 'Allow';
				}
				Set-MyFileSystemAcl @Params
				
				Write-Log -Message "Setting registry file to import for each user"
				
				## This isn't the *best* way to do this because this doesn't prevent a user from clearing out all the temp files
				Set-AllUserStartupAction -CommandLine "reg import `"$(Get-SystemTempFolderPath)\$($FilePath | Split-Path -Leaf)`""
				
			}
			
			
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Remove-RegistryKey
{
	[OutputType([void])]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string[]]$Path
	)
	begin {
		$ErrorActionPreference = 'Stop'
	}
	process {
		try
		{
			foreach ($key in $Path)
			{
				if (($key | Split-Path -Qualifier) -eq 'HKLM:')
				{
					Write-Log -Message "Removing HKLM registry key '$key' for system"
					Remove-Item -Path $key -Recurse -Force -ErrorAction 'SilentlyContinue'
				}
				elseif (($key | Split-Path -Qualifier) -eq 'HKCU:')
				{
					Write-Log -Message "Removing HKCU registry key '$key' for all users"
					Set-AllUsersRegistryValue -RegistryInstance @{ 'Path' = $key.Replace('HKCU:\', '') } -Remove
				}
				else
				{
					Write-Log -Message "Registry key '$key' not in recognized format" -LogLevel '2'
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

function Set-AllUsersRegistryValue
{
    <#
	.SYNOPSIS
		This function sets a registry value in every user profile hive.
	.EXAMPLE
		PS> Set-AllUsersRegistryValue -RegistryInstance @{'Name' = 'Setting'; 'Type' = 'String'; 'Value' = 'someval'; 'Path' = 'SOFTWARE\Microsoft\Windows\Something'}
	
		This example would modify the string registry value 'Type' in the path 'SOFTWARE\Microsoft\Windows\Something' to 'someval'
		for every user registry hive.
	.PARAMETER RegistryInstance
	 	A hash table containing key names of 'Name' designating the registry value name, 'Type' to designate the type
		of registry value which can be 'String,Binary,Dword,ExpandString or MultiString', 'Value' which is the value itself of the
		registry value and 'Path' designating the parent registry key the registry value is in.
	.PARAMETER Remove
		A switch parameter that overrides the default setting to only change or add registry values.  This removes one of more registry keys instead.
		If this parameter is used the only required key in the RegistryInstance parameter is Path.  This will automatically remove both
		the x86 and x64 paths if the key is a child under the SOFTWARE key.  There's no need to specify the WOW6432Node path also.
	.PARAMETER Force
		A switch parameter that is used if the registry value key path doesn't exist will create the entire parent/child key hierachy and creates the 
		registry value.  If this parameter is not used, if the key the value is supposed to be in does not exist the function will skip the value.
	#>
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess = $true)]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[hashtable[]]$RegistryInstance,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[switch]$Remove
	)
	process
	{
		try
		{
			
			
			## By default, the HKU provider is not added
			if (-not (Get-PSDrive -Name 'HKU' -ErrorAction SilentlyContinue))
			{
				$null = New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS
			}
			
			## Change the registry values for the currently logged on user
			$LoggedOnSids = Get-LoggedOnUserSID
			Write-Log -Message "Found $(@($LoggedOnSids).Count) logged on user SIDs"
			foreach ($sid in $LoggedOnSids)
			{
				Write-Log -Message "Loading the user registry hive for the logged on SID $sid"
				foreach ($instance in $RegistryInstance)
				{
					if ($Remove.IsPresent)
					{
						if ($PSCmdlet.ShouldProcess($instance.Path, 'Remove'))
						{
							Write-Log -Message "Removing registry key '$($instance.path)'"
							Remove-Item -Path "HKU:\$sid\$($instance.Path)" -Recurse -Force -ErrorAction 'SilentlyContinue'
						}
					}
					else
					{
						if (-not (Get-Item -Path "HKU:\$sid\$($instance.Path)" -ErrorAction 'SilentlyContinue'))
						{
							if ($PSCmdlet.ShouldProcess($instance.Path, 'New'))
							{
								Write-Log -Message "The registry key HKU:\$sid\$($instance.Path) does not exist.  Creating..."
								New-Item -Path "HKU:\$sid\$($instance.Path | Split-Path -Parent)" -Name ($instance.Path | Split-Path -Leaf) -Force | Out-Null
							}
						}
						else
						{
							Write-Log -Message "The registry key HKU:\$sid\$($instance.Path) already exists. No need to create."
						}
						if ($PSCmdlet.ShouldProcess($instance.Path, 'New property'))
						{
							Write-Log -Message "Setting registry value $($instance.Name) at path HKU:\$sid\$($instance.Path) to $($instance.Value)"
							New-ItemProperty -Path "HKU:\$sid\$($instance.Path)" -Name $instance.Name -Value $instance.Value -PropertyType $instance.Type -Force
						}
					}
				}
			}
			
			foreach ($instance in $RegistryInstance)
			{
				if ($Remove.IsPresent)
				{
					if ($instance.Path.Split('\')[0] -eq 'SOFTWARE' -and ((Get-Architecture) -eq 'x64'))
					{
						$Split = $instance.Path.Split('\')
						$x86Path = "HKCU\SOFTWARE\Wow6432Node\{0}" -f ($Split[1..($Split.Length)] -join '\')
						$CommandLine = "reg delete `"{0}`" /f && reg delete `"{1}`" /f" -f "HKCU\$($instance.Path)", $x86Path
					}
					else
					{
						$CommandLine = "reg delete `"{0}`" /f" -f "HKCU\$($instance.Path)"
					}
				}
				else
				{
					## Convert the registry value type to one that reg.exe can understand
					switch ($instance.Type)
					{
						'String' {
							$RegValueType = 'REG_SZ'
						}
						'Dword' {
							$RegValueType = 'REG_DWORD'
						}
						'Binary' {
							$RegValueType = 'REG_BINARY'
						}
						'ExpandString' {
							$RegValueType = 'REG_EXPAND_SZ'
						}
						'MultiString' {
							$RegValueType = 'REG_MULTI_SZ'
						}
						default
						{
							throw "Registry type '$($instance.Type)' not recognized"
						}
					}
					if (-not (Get-Item -Path "HKCU:\$($instance.Path)" -ErrorAction 'SilentlyContinue'))
					{
						if ($PSCmdlet.ShouldProcess($instance.Path, 'New'))
						{
							Write-Log -Message "The registry key 'HKCU:\$($instance.Path)'' does not exist.  Creating..."
							New-Item -Path "HKCU:\$($instance.Path) | Split-Path -Parent)" -Name ("HKCU:\$($instance.Path)" | Split-Path -Leaf) -Force | Out-Null
						}
					}
					$CommandLine = "reg add `"{0}`" /v {1} /t {2} /d {3} /f" -f "HKCU\$($instance.Path)", $instance.Name, $RegValueType, $instance.Value
				}
				if ($PSCmdlet.ShouldProcess($CommandLine,'set all user action')) {
					Set-AllUserStartupAction -CommandLine $CommandLine
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

function Get-MsiexecInstallString
{
	[OutputType([string])]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$InstallerFilePath,
	
		[Parameter()]
		[AllowNull()]
		[string[]]$MstFilePath,
	
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
				$MstFilePath = $MstFilePath -join ';'
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
			if (-not $LogFilePath)
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
	[OutputType([void])]
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
	[OutputType([void])]
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
			if ($PSBoundParameters.ContainsKey('Name'))
			{
				Write-Log -Message "Attempting to uninstall Windows Installer using name '$Name'..."
				$params.Name = $Name
			}
			if ($PSBoundParameters.ContainsKey('Guid'))
			{
				Write-Log -Message "Attempting to uninstall Windows Installer using GUID '$Guid'..."
				$params.Guid = $Guid
			}
			if ($PSBoundParameters.ContainsKey('MsiExecSwitches'))
			{
				$params.MsiExecSwitches = $MsiExecSwitches
			}
			
			Uninstall-WindowsInstallerPackageWithMsiexec @params
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
	[OutputType([void])]
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
			if ($PSBoundParameters.ContainsKey('Name'))
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
	[OutputType([void])]
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
	[OutputType([void])]
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
				Write-Log -Message "Found '$(@($MsiexecProcesses).Count)' Windows installer processes.  Waiting..."
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

function Get-AllUsersDesktopFolderPath
{
	<#
	.SYNOPSIS
		Because sometimes the all users desktop folder path can be different this function is a placeholder to find
		the all users desktop folder path. It uses a shell object to find this path.
	#>
	[OutputType([bool])]
	[CmdletBinding()]
	param ()
	process
	{
		try
		{
			$Shell = New-Object -ComObject "WScript.Shell"
			$Shell.SpecialFolders.Item('AllUsersDesktop')
			
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Get-AllUsersProfileFolderPath
{
	<#
	.SYNOPSIS
		Because sometimes the all users profile folder path can be different this function is a placeholder to find
		the all users profile folder path ie. C:\ProgramData or C:\Users\All Users. It uses an environment variable
		to find this path.
	#>
	[OutputType([string])]
	[CmdletBinding()]
	param ()
	process
	{
		try
		{
			$env:ALLUSERSPROFILE	
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Get-AllUsersStartMenuFolderPath
{
	<#
	.SYNOPSIS
		Because sometimes the all users profile folder path can be different this function is a placeholder to find
		the start menu in the all users profile folder path ie. C:\ProgramData or C:\Users\All Users.
	#>
	[OutputType([string])]
	[CmdletBinding()]
	param ()
	process
	{
		try
		{
			
			if (((Get-OperatingSystem) -match 'XP') -or ((Get-OperatingSystem) -match '2003'))
			{
				"$(Get-AllUsersProfileFolderPath)\Start Menu"
			}
			else
			{
				"$(Get-AllUsersProfileFolderPath)\Microsoft\Windows\Start Menu"
			}
			
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Get-UserProfile
{
	<#
	.SYNOPSIS
		This function queries the registry to find all of the user profiles
	#>
	[OutputType([System.Management.Automation.PSCustomObject])]
	[CmdletBinding()]
	param (
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[switch]$ExcludeSystemProfiles
	)
	process
	{
		try
		{
			if ($ExcludeSystemProfiles.IsPresent) {
				$whereFilter = { $_.SID.Length -ge 45 }
			} else {
				$whereFilter = { '*' }
			}
			
			$profiles = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\*'
			
			$selectProps = @(
				'*', 
				@{ n = 'SID'; e = { $_.PSChildName }}, @{ n = 'Username'; e = { $_.ProfileImagePath | Split-Path -Leaf }}
			)
			$profiles | Select-Object -ExcludeProperty SID -Property $selectProps | Where -FilterScript $whereFilter
			
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Get-RootUserProfileFolderPath
{
	<#
	.SYNOPSIS
		Because sometimes the root user profile folder path can be different this function is a placeholder to find
		the root user profile folder path ie. C:\Users or C:\Documents and Settings for any OS.  It queries a registry value
		to find this path.
	#>
	[OutputType([string])]
	[CmdletBinding()]
	param ()
	process
	{
		try
		{
			(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name ProfilesDirectory).ProfilesDirectory	
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Get-UserProfilePath
{
	<#
	.SYNOPSIS
		This function find the folder path of a user profile based off of a number of different criteria.  If no criteria is
		used, it will return all user profile paths.
	.EXAMPLE
		PS> .\Get-UserProfilePath -Sid 'S-1-5-21-350904792-1544561288-1862953342-32237'
	
		This example finds the user profile path based on the user's SID
	.EXAMPLE
		PS> .\Get-UserProfilePath -Username 'bob'
	
		This example finds the user profile path based on the username
	.PARAMETER Sid
	 	The user SID
	.PARAMETER Username
		The username
	#>
	[OutputType([string])]
	[CmdletBinding(DefaultParameterSetName = 'None')]
	param (
		[Parameter(ParameterSetName = 'SID')]
		[string]$Sid,
		
		[Parameter(ParameterSetName = 'Username')]
		[string]$Username
	)
	
	process
	{
		try
		{
			if ($Sid)
			{
				$WhereBlock = { $_.PSChildName -eq $Sid }
			}
			elseif ($Username)
			{
				$WhereBlock = { $_.GetValue('ProfileImagePath').Split('\')[-1] -eq $Username }
			}
			else
			{
				$WhereBlock = { $null -ne $_.PSChildName }
			}
			Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList' | Where-Object $WhereBlock | ForEach-Object { $_.GetValue('ProfileImagePath') }
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Remove-ProfileItem
{
	<#
	.SYNOPSIS
		This function removes a file(s) or folder(s) with the same path in all user profiles including
		system profiles like SYSTEM, NetworkService and AllUsers.
	.EXAMPLE
		PS> .\Remove-ProfileItem -Path 'AppData\Adobe'
	
		This example will remove the folder path 'AppData\Adobe' from all user profiles
	.PARAMETER Path
		The path(s) to the file or folder you'd like to remove.
	#>
	[OutputType([void])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string[]]$Path
	)
	
	process
	{
		try
		{
			
			$AllUserProfileFolderPath = Get-AllUsersProfileFolderPath
			$UserProfileFolderPaths = Get-UserProfilePath
			
			foreach ($p in $Path)
			{
				if (-not (Test-Path "$AllUserProfileFolderPath\$p"))
				{
					Write-Log -Message "The folder '$AllUserProfileFolderPath\$p' does not exist"
				}
				else
				{
					Remove-Item -Path "$AllUserProfileFolderPath\$p" -Force -Recurse
				}
				
				
				foreach ($ProfilePath in $UserProfileFolderPaths)
				{
					if (-not (Test-Path "$ProfilePath\$p"))
					{
						Write-Log -Message "The folder '$ProfilePath\$p' does not exist"
					}
					else
					{
						Remove-Item -Path "$ProfilePath\$p" -Force -Recurse
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

function Set-AllUserStartupAction
{
	<#
	.SYNOPSIS
		A function that executes a command line for the any current logged on user and uses the Active Setup registry key to set a 
		registry value that contains a command line	EXE with arguments that will be executed once for every user that logs in.
	.PARAMETER CommandLine
		The command line string that will be executed once at every user logon
	#>
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess = $true)]
	param (
		[Parameter(Mandatory = $true)]
		[string]$CommandLine
	)
	process
	{
		try
		{
			if ($PSCmdlet.ShouldProcess($CommandLine,'set all startup action')) {
				## Create the Active Setup registry key so that the reg add cmd will get ran for each user
				## logging into the machine.
				## http://www.itninja.com/blog/view/an-active-setup-primer
				$Guid = [guid]::NewGuid().Guid
				Write-Log -Message "Created GUID '$Guid' to use for Active Setup"
				$ActiveSetupRegParentPath = 'HKLM:\Software\Microsoft\Active Setup\Installed Components'
				New-Item -Path $ActiveSetupRegParentPath -Name $Guid -Force | Out-Null
				$ActiveSetupRegPath = "HKLM:\Software\Microsoft\Active Setup\Installed Components\$Guid"
				Write-Log -Message "Using registry path '$ActiveSetupRegPath'"
				Write-Log -Message "Setting command line registry value to '$CommandLine'"
				Set-ItemProperty -Path $ActiveSetupRegPath -Name '(Default)' -Value 'Active Setup Test' -Force
				Set-ItemProperty -Path $ActiveSetupRegPath -Name 'Version' -Value '1' -Force
				Set-ItemProperty -Path $ActiveSetupRegPath -Name 'StubPath' -Value $CommandLine -Force
			}
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Compare-File
{
	<#
	.SYNOPSIS
		This function checks the hash of 2 files see if they are the same
	.EXAMPLE
		PS> Compare-File -ReferenceFile 'C:\Windows\file.txt' -DifferenceFile '\\COMPUTER\c$\Windows\file.txt'
	
		This example checks to see if the file C:\Windows\file.txt is exactly the same as the file \\COMPUTER\c$\Windows\file.txt
	.PARAMETER ReferenceFile
		The first file path to compare
	.PARAMETER DifferenceFile
		The second file path to compare
	#>
	[OutputType([bool])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
		[string]$ReferenceFilePath,
		
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
		[string]$DifferenceFilePath
	)
	process
	{
		try
		{
			$ReferenceHash = Get-MyFileHash -Path $ReferenceFilePath
			$DifferenceHash = Get-MyFileHash -Path $DifferenceFilePath
			$ReferenceHash.SHA256 -eq $DifferenceHash.SHA256
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Compare-FilePath
{
	<#
	.SYNOPSIS
		This function checks the hash of 2 files see if they are the same. Returned $true if they are *not* equal.
	.EXAMPLE
		PS> Compare-FilePath -ReferencePath 'C:\Windows\file.txt' -DifferencePath '\\COMPUTER\c$\Windows\file.txt'
	
		This example checks to see if the file C:\Windows\file.txt is exactly the same as the file \\COMPUTER\c$\Windows\file.txt
	.PARAMETER ReferencePath
		The first file path to compare
	.PARAMETER DifferencePath
		The second file path to compare
	#>
	[OutputType([bool])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
		[string]$ReferenceFilePath,
		
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
		[string]$DifferenceFilePath
	)
	process
	{
		Write-warning "Compare-FilePath is deprecated. May be removed in the future. Use Compare-File instead."
		-Not (Compare-File -ReferenceFilePath $ReferenceFilePath -DifferenceFilePath $DifferenceFilePath)
	}
}

function Compare-FolderPath
{
	<#
	.SYNOPSIS
		This function checks all files inside of a folder against another folder to see if they are the same
	.EXAMPLE
		PS> Compare-FilePath -ReferencePath 'C:\Windows' -DifferencePath '\\COMPUTER\c$\Windows'
	
		This example checks to see if the contents in C:\Windows is exactly the same as the contents in \\COMPUTER\c$\Windows
	.PARAMETER ReferencePath
		The first folder path to compare
	.PARAMETER DifferencePath
		The second folder path to compare
	#>
	[OutputType([bool])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType Container })]
		[string]$ReferenceFolderPath,
		
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType Container })]
		[string]$DifferenceFolderPath
	)
	process
	{
		try
		{
			$ReferenceFiles = Get-ChildItem -Path $ReferenceFolderPath -Recurse | Where-Object { -not $_.PsIsContainer }
			$DifferenceFiles = Get-ChildItem -Path $DifferenceFolderPath -Recurse | Where-Object { -not $_.PsIsContainer }
			if ($ReferenceFiles.Count -ne $DifferenceFiles.Count)
			{
				Write-Log -Message "Folder path '$ReferenceFolderPath' and '$DifferenceFolderPath' file counts are different" -LogLevel '2'
				$false
			}
			elseif (Compare-Object -ReferenceObject ($ReferenceFiles | Get-MyFileHash) -DifferenceObject ($DifferenceFiles | Get-MyFileHash))
			{
				Write-Log -Message "Folder path '$ReferenceFolderPath' and '$DifferenceFolderPath' file hashes are different" -LogLevel '2'
				$false
			}
			else
			{
				Write-Log -Message "Folder path '$ReferenceFolderPath' and '$DifferenceFolderPath' have equal contents"
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

function Copy-FileWithHashCheck
{
	<#
	.SYNOPSIS
		This function copies a file and then verifies the copy was successful by comparing the source and destination
		file hash values.
	.EXAMPLE
		PS> Copy-FileWithHashCheck -SourceFilePath 'C:\Windows\file1.txt' -DestinationFolderPath '\\COMPUTER\c$\Windows\file2.txt'
	
		This example copied the file from C:\Windows\file1.txt to \\COMPUTER\c$\Windows and then checks the hash for the
		source file and destination file to ensure the copy was successful.
	.PARAMETER SourceFilePath
		The source file path
	.PARAMETER DestinationFolderPath
		The destination folder path
	.PARAMETER Force
		Overwrite the destination file if one exists
	#>
	[OutputType([void])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $True)]
		[Alias('Fullname')]
		[string]$SourceFilePath,
		
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType Container })]
		[string]$DestinationFolderPath,
		
		[Parameter()]
		[switch]$Force
	)
	process
	{
		try
		{
			$CopyParams = @{ 'Path' = $SourceFilePath; 'Destination' = $DestinationFolderPath }
			
			## If the file is already there, check to see if it's the one we're copying in the first place
			$DestFilePath = "$DestinationFolderPath\$($SourceFilePath | Split-Path -Leaf)"
			if (Test-Path -Path $DestFilePath -PathType 'Leaf')
			{
				if (Compare-FilePath -ReferenceFilePath $SourceFilePath -DifferenceFilePath $DestFilePath)
				{
					Write-Log -Message "The file $SourceFilePath is already in $DestinationFolderPath and is the same. No need to copy"
				}
				elseif (-not $Force.IsPresent)
				{
					throw "The file $SourceFilePath is already in $DestinationFolderPath but is not the same file being copied and -Force was not used."
				}
				else
				{
					$CopyParams.Force = $true
				}
			}
			Write-Log -Message "Copying [$($CopyParams.Path)] to [[$($CopyParams.Destination)]...."
			Copy-Item @CopyParams
			if (Compare-FilePath -ReferenceFilePath $SourceFilePath -DifferenceFilePath $DestFilePath)
			{
				Write-Log -Message "The file $SourceFilePath was successfully copied to $DestinationFolderPath."
			}
			throw "Attempted to copy the file $SourceFilePath to $DestinationFolderPath but failed the hash check"
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Find-InTextFile
{
	<#
	.SYNOPSIS
		Performs a find (or replace) on a string in a text file or files.
	.EXAMPLE
		PS> Find-InTextFile -FilePath 'C:\MyFile.txt' -Find 'water' -Replace 'wine'
	
		Replaces all instances of the string 'water' into the string 'wine' in
		'C:\MyFile.txt'.
	.EXAMPLE
		PS> Find-InTextFile -FilePath 'C:\MyFile.txt' -Find 'water'
	
		Finds all instances of the string 'water' in the file 'C:\MyFile.txt'.
	.PARAMETER FilePath
		The file path of the text file you'd like to perform a find/replace on.
	.PARAMETER Find
		The string you'd like to replace.
	.PARAMETER Replace
		The string you'd like to replace your 'Find' string with.
	.PARAMETER UseRegex
		Use this switch parameter if you're finding strings using regex else the Find string will
		be escaped from regex characters
	.PARAMETER NewFilePath
		If a new file with the replaced the string needs to be created instead of replacing
		the contents of the existing file use this param to create a new file.
	.PARAMETER Force
		If the NewFilePath param is used using this param will overwrite any file that
		exists in NewFilePath.
	#>
	[OutputType('Microsoft.PowerShell.Commands.MatchInfo')]
	[CmdletBinding(DefaultParameterSetName = 'NewFile')]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[string[]]$FilePath,
		
		[Parameter(Mandatory = $true)]
		[string]$Find,
		
		[Parameter()]
		[string]$Replace,
		
		[Parameter()]
		[switch]$UseRegex,
		
		[Parameter(ParameterSetName = 'NewFile')]
		[ValidateScript({ Test-Path -Path ($_ | Split-Path -Parent) -PathType 'Container' })]
		[string]$NewFilePath,
		
		[Parameter(ParameterSetName = 'NewFile')]
		[switch]$Force
	)
	begin
	{
		if (-not $UseRegex.IsPresent)
		{
			$Find = [regex]::Escape($Find)
		}
	}
	process
	{
		try
		{
			foreach ($File in $FilePath)
			{
				if ($Replace)
				{
					if ($NewFilePath)
					{
						if ((Test-Path -Path $NewFilePath -PathType 'Leaf') -and $Force.IsPresent)
						{
							Remove-Item -Path $NewFilePath -Force
							(Get-Content $File) -replace $Find, $Replace | Add-Content -Path $NewFilePath -Force
						}
						elseif ((Test-Path -Path $NewFilePath -PathType 'Leaf') -and (-not $Force.IsPresent))
						{
							Write-Log -Message "The file at '$NewFilePath' already exists and the -Force param was not used" -LogLevel 2
						}
						else
						{
							(Get-Content $File) -replace $Find, $Replace | Add-Content -Path $NewFilePath -Force
						}
					}
					else
					{
						(Get-Content $File) -replace $Find, $Replace | Add-Content -Path "$File.tmp" -Force
						Remove-Item -Path $File
						Rename-Item -Path "$File.tmp" -NewName $File
					}
				}
				else
				{
					Select-String -Path $File -Pattern $Find
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

function Register-File
{
	<#
	.SYNOPSIS
		A function that uses the utility regsvr32.exe utility to register a file
	.PARAMETER FilePath
		The file path
	#>
	[OutputType([void])]
	[CmdletBinding()]
	param (
		[Parameter()]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[string]$FilePath
	)
	process
	{
		try
		{
			
			$Result = Start-Process -FilePath 'regsvr32.exe' -ArgumentList "/s `"$FilePath`"" -Wait -NoNewWindow -PassThru
			Wait-MyProcess -ProcessId $Result.Id
			if ($Result.ExitCode -ne '0')
			{
				throw "Process ID [$($Result.Id)] failed. Exit code was [$($Result.ExitCode)]"
			}
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Set-MyFileSystemAcl
{
	<#
	.SYNOPSIS
		This function allows an easy method to set a file system access ACE
	.PARAMETER Path
	 	The file path of a file
	.PARAMETER Identity
		The security principal you'd like to set the ACE to.  This should be specified like
		DOMAIN\user or LOCALMACHINE\User.
	.PARAMETER Right
		One of many file system rights.  For a list http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights(v=vs.110).aspx
	.PARAMETER InheritanceFlags
		The flags to set on how you'd like the object inheritance to be set.  Possible values are
		ContainerInherit, None or ObjectInherit. http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.inheritanceflags(v=vs.110).aspx
	.PARAMETER PropagationFlags
		The flag that specifies on how you'd permission propagation to behave. Possible values are
		InheritOnly, None or NoPropagateInherit. http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.propagationflags(v=vs.110).aspx
	.PARAMETER Type
		The type (Allow or Deny) of permissions to add. http://msdn.microsoft.com/en-us/library/w4ds5h86(v=vs.110).aspx
	#>
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess = $true)]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ })]
		[string]$Path,
		
		[Parameter(Mandatory = $true)]
		[string]$Identity,
		
		[Parameter(Mandatory = $true)]
		[string]$Right,
		
		[Parameter(Mandatory = $true)]
		[string]$InheritanceFlags,
		
		[Parameter(Mandatory = $true)]
		[string]$PropagationFlags,
		
		[Parameter(Mandatory = $true)]
		[string]$Type
	)
	
	process
	{
		try
		{
			$Acl = (Get-Item $Path).GetAccessControl('Access')
			$Ar = New-Object System.Security.AccessControl.FileSystemAccessRule($Identity, $Right, $InheritanceFlags, $PropagationFlags, $Type)
			$Acl.SetAccessRule($Ar)
			if ($PSCmdlet.ShouldProcess($Path, 'ACL Change'))
			{
				Set-Acl $Path $Acl
			}
			
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Get-FileVersion
{
	<#
	.SYNOPSIS
		This function finds the file version of a file.  This is useful for applications that don't
		register themselves properly with Windows Installer
	.PARAMETER FilePath
	 	A valid file path
	#>
	[OutputType([string])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[string]$FilePath
	)
	process
	{
		try
		{
			(Get-ItemProperty -Path $FilePath).VersionInfo.FileVersion	
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Get-MyFileHash
{
    <#
        .SYNOPSIS
            Calculates the hash on a given file based on the seleced hash algorithm.

        .DESCRIPTION
            Calculates the hash on a given file based on the seleced hash algorithm. Multiple hashing 
            algorithms can be used with this command.

        .PARAMETER Path
            File or files that will be scanned for hashes.

        .PARAMETER Algorithm
            The type of algorithm that will be used to determine the hash of a file or files.
            Default hash algorithm used is SHA256. More then 1 algorithm type can be used.
            
            Available hash algorithms:

            MD5
            SHA1
            SHA256 (Default)
            SHA384
            SHA512
            RIPEM160

        .NOTES
            Name: Get-FileHash
            Author: Boe Prox
            Created: 18 March 2013
            Modified: 28 Jan 2014
                1.1 - Fixed bug with incorrect hash when using multiple algorithms

        .OUTPUTS
            System.IO.FileInfo.Hash

        .EXAMPLE
            Get-FileHash -Path Test2.txt
            Path                             SHA256
            ----                             ------
            C:\users\prox\desktop\TEST2.txt 5f8c58306e46b23ef45889494e991d6fc9244e5d78bc093f1712b0ce671acc15      
            
            Description
            -----------
            Displays the SHA256 hash for the text file.   

        .EXAMPLE
            Get-FileHash -Path .\TEST2.txt -Algorithm MD5,SHA256,RIPEMD160 | Format-List
            Path      : C:\users\prox\desktop\TEST2.txt
            MD5       : cb8e60205f5e8cae268af2b47a8e5a13
            SHA256    : 5f8c58306e46b23ef45889494e991d6fc9244e5d78bc093f1712b0ce671acc15
            RIPEMD160 : e64d1fa7b058e607319133b2aa4f69352a3fcbc3

            Description
            -----------
            Displays MD5,SHA256 and RIPEMD160 hashes for the text file.

        .EXAMPLE
            Get-ChildItem -Filter *.exe | Get-FileHash -Algorithm MD5
            Path                               MD5
            ----                               ---
            C:\users\prox\desktop\handle.exe  50c128c5b28237b3a01afbdf0e546245
            C:\users\prox\desktop\PortQry.exe c6ac67f4076ca431acc575912c194245
            C:\users\prox\desktop\procexp.exe b4caa7f3d726120e1b835d52fe358d3f
            C:\users\prox\desktop\Procmon.exe 9c85f494132cc6027762d8ddf1dd5a12
            C:\users\prox\desktop\PsExec.exe  aeee996fd3484f28e5cd85fe26b6bdcd
            C:\users\prox\desktop\pskill.exe  b5891462c9ca5bddfe63d3bae3c14e0b
            C:\users\prox\desktop\Tcpview.exe 485bc6763729511dcfd52ccb008f5c59

            Description
            -----------
            Uses pipeline input from Get-ChildItem to get MD5 hashes of executables.

    #>
	[OutputType([PSObject])]
	[CmdletBinding()]
	Param (
		[Parameter(Position = 0, Mandatory = $true, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $True)]
		[Alias("PSPath", "FullName")]
		[string[]]$Path,
		
		[Parameter(Position = 1)]
		[ValidateSet("MD5", "SHA1", "SHA256", "SHA384", "SHA512", "RIPEMD160")]
		[string[]]$Algorithm = "SHA256"
	)
	Process
	{
		
		ForEach ($item in $Path)
		{
			try
			{
				$item = (Resolve-Path $item).ProviderPath
				If (-Not ([uri]$item).IsAbsoluteUri)
				{
					Write-Log -Message ("{0} is not a full path, using current directory: {1}" -f $item, $pwd)
					$item = (Join-Path $pwd ($item -replace "\.\\", ""))
				}
				If (Test-Path $item -PathType Container)
				{
					Write-Log -Message ("Cannot calculate hash for directory: {0}" -f $item) -LogLevel 2
					Return
				}
				$object = New-Object PSObject -Property @{
					Path = $item
				}
				#Open the Stream
				$stream = ([IO.StreamReader]$item).BaseStream
				foreach ($Type in $Algorithm)
				{
					switch ($Type) {
						'MD5' { [string]$hash = -join ([Security.Cryptography.MD5]::Create().ComputeHash($stream) |
							ForEach-Object { "{0:x2}" -f $_ }) }
						'SHA1' { [string]$hash = -join ([Security.Cryptography.SHA1]::Create().ComputeHash($stream) |
							ForEach-Object { "{0:x2}" -f $_ }) }
						'SHA256' { [string]$hash = -join ([Security.Cryptography.SHA256]::Create().ComputeHash($stream) |
							ForEach-Object { "{0:x2}" -f $_ }) }
						'SHA384' { [string]$hash = -join ([Security.Cryptography.SHA384]::Create().ComputeHash($stream) |
							ForEach-Object { "{0:x2}" -f $_ }) }
						'SHA512' { [string]$hash = -join ([Security.Cryptography.SHA512]::Create().ComputeHash($stream) |
							ForEach-Object { "{0:x2}" -f $_ }) }
						'RIPEMD160' { [string]$hash = -join ([Security.Cryptography.RIPEMD160]::Create().ComputeHash($stream) |
							ForEach-Object { "{0:x2}" -f $_ }) }
						Default {}
					}
					
					$null = $stream.Seek(0, 0)
					#If multiple algorithms are used, then they will be added to existing object
					$object = Add-Member -InputObject $Object -MemberType NoteProperty -Name $Type -Value $Hash -PassThru
				}
				$object.pstypenames.insert(0, 'System.IO.FileInfo.Hash')
				#Output an object with the hash, algorithm and path
				Write-Output $object
				
				#Close the stream
				$stream.Close()
				
			}
			catch
			{
				Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
				$PSCmdlet.ThrowTerminatingError($_)
			}
		}
	}
}

function Get-RootUserProfileFolderPath
{
	<#
	.SYNOPSIS
		Because sometimes the root user profile folder path can be different this function is a placeholder to find
		the root user profile folder path ie. C:\Users or C:\Documents and Settings for any OS.  It queries a registry value
		to find this path.
	#>
	[OutputType([string])]
	[CmdletBinding()]
	param ()
	process
	{
		try
		{
			(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name ProfilesDirectory).ProfilesDirectory	
		}
		catch
		{
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Get-Shortcut
{
	<#
	.SYNOPSIS
		This function searches for files matching a LNK and URL extension.
	.DESCRIPTION
		This function, by default, recursively searches for files matching a LNK and URL extensions containing
		a specific string inside the target path, name or both. If no folder path specified, it will 
		recursively search all user profiles and the all users profile.
	.NOTES
		Created on: 	6/23/2014
		Created by: 	Adam Bertram
	.EXAMPLE
		Get-Shortcut -MatchingTargetPath 'http:\\servername\local'
		This example would find all shortcuts (URL and LNK) in all user profiles that have a 
		target path that match 'http:\\servername\local'
	.EXAMPLE
		Get-Shortcut -MatchingTargetPath 'http:\\servername\local' -MatchingName 'name'
		This example would find all shortcuts (URL and LNK) in all user profiles that have a 
		target path that match 'http:\\servername\local' and have a name containing the string "name"
	.EXAMPLE
		Get-Shortcut -MatchingTargetPath 'http:\\servername\local' -MatchingFilePath 'C:\Users\abertram\Desktop'
		This example would find all shortcuts (URL and LNK) in the 'C:\Users\abertram\Desktop file path 
		that have a target path that match 'http:\\servername\local' and have a name containing the 
		string "name"
	.PARAMETER MatchingTargetPath
		The string you'd like to search for inside the shortcut's target path
	.PARAMETER MatchingName
		A string you'd like to search for inside of the shortcut's name
	.PARAMETER MatchingFilePath
		A string you'd like to search for inside of the shortcut's file path
	.PARAMETER FolderPath
		The folder path to search for shortcuts in.  You can specify multiple folder paths. This defaults to 
		the user profile root and the all users profile
	.PARAMETER NoRecurse
		This turns off recursion on the folder path specified searching subfolders of the FolderPath
	#>
	[OutputType([System.IO.FileInfo])]
	[CmdletBinding()]
	param (
		[string]$MatchingTargetPath,
		
		[string]$MatchingName,
		
		[string]$MatchingFilePath,
		
		[string[]]$FolderPath = ((Get-RootUserProfileFolderPath), $env:ALLUSERSPROFILE),
		
		[switch]$NoRecurse
	)
	process
	{
		try
		{	
			$Params = @{
				Include = @('*.url', '*.lnk')
				ErrorAction = 'SilentlyContinue'
				Force = $true
			}
			
			if (-not $NoRecurse)
			{
				$Params['Recurse'] = $true
			}
			
			$ShellObject = New-Object -ComObject Wscript.Shell
			
			foreach ($Path in $FolderPath)
			{
				try
				{
					Write-Verbose -Message "Searching for shortcuts in $Path..."
					$WhereConditions = @()
					$Params['Path'] = $Path
					if ($MatchingTargetPath)
					{
						$WhereConditions += '(($ShellObject.CreateShortcut($_.FullName)).TargetPath -like "*$MatchingTargetPath*")'
					}
					if ($MatchingName)
					{
						$WhereConditions += '($_.Name -like "*$MatchingName*")'
					}
					if ($MatchingFilePath)
					{
						$WhereConditions += '($_.FullName -like "*$MatchingFilePath*")'
					}
					if (@($WhereConditions).Count -gt 0)
					{
						$WhereBlock = [scriptblock]::Create($WhereConditions -join ' -and ')
						## TODO: Figure out a way to make this cleanly log access denied errors and continue
						Get-ChildItem @Params | Where-Object $WhereBlock
					}
					else
					{
						Get-ChildItem @Params
					}
					Write-Verbose -Message "Finished searching for shortcuts in $Path..."
				}
				catch
				{
					$PSCmdlet.ThrowTerminatingError($_)
				}
			}
			
		}
		catch
		{
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function New-Shortcut
{
	<#
	.SYNOPSIS
		This function creates a file shortcut   
	.NOTES
		Created on:   	07/19/2014
		Created by:   	Adam Bertram
	.EXAMPLE
		New-Shortcut -FolderPath 'C:\' -Name 'My Shortcut' -TargetFilePath 'C:\Windows\notepad.exe'
		This examples creates a shortcut in C:\ called 'My Shortcut.lnk' pointing to notepad.exe
	.EXAMPLE
		New-Shortcut -CommonLocation AllUsersDesktop -Name 'My Shortcut' -TargetFilePath 'C:\Windows\notepad.exe'
		This examples creates a shortcut on the all users desktop called 'My Shortcut.lnk' pointing to notepad.exe
	.PARAMETER FolderPath
		If a custom path is needed that's not included in the list of common locations in the CommonLocation parameter
		this parameter can be used to create a folder in the specified path.
	.PARAMETER CommonLocation
		This is a set of common locations shortcuts are typically created in.  Use this parameter if you'd like to 
		quickly specify where the shortcut needs to be created in.
	.PARAMETER Name
		The name of the shortcut (file)
	.PARAMETER TargetPath
		The file path or URL of the application you'd like the shortcut to point to
	.PARAMETER Arguments
		File arguments you'd like to append to the target file path
	#>
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess,DefaultParameterSetName = 'CommonLocation')]
	param (
		[Parameter(ParameterSetName = 'CustomLocation',Mandatory)]
		[ValidateScript({ Test-Path $_ -PathType 'Container' })]
		[string]$FolderPath,
		
		[Parameter(ParameterSetName = 'CommonLocation',Mandatory)]
		[ValidateSet('AllUsersDesktop')]
		[string]$CommonLocation,
		
		[Parameter(Mandatory)]
		[string]$Name,
		
		[Parameter(Mandatory)]
		[string]$TargetPath,
		
		[Parameter()]
		[string]$Arguments
	)
	begin
	{
		try
		{
			$ShellObject = New-Object -ComObject Wscript.Shell
		}
		catch
		{
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
	process
	{
		try
		{
			
			if ($TargetPath -notmatch '^\w{1}:\\')
			{
				$Extension = 'url'
			}
			else
			{
				$Extension = 'lnk'
			}
			if ($CommonLocation -eq 'AllUsersDesktop')
			{
				$FilePath = "$(Get-AllUsersDesktopFolderPath)\$Name.$Extension"
			}
			elseif ($FolderPath)
			{
				$FilePath = "$FolderPath\$Name.$Extension"
			}
			if (Test-Path -Path $FilePath -PathType Leaf)
			{
				throw "$FilePath already exists. New shortcut cannot be made here."
			}
			$Object = $ShellObject.CreateShortcut($FilePath)
			$Object.TargetPath = $TargetPath
			if ($TargetPath -notmatch '^\w{1}:\\')
			{
				$Extension = 'url'
			}
			else
			{
				$Extension = 'lnk'
				$Object.Arguments = $Arguments
				$Object.WorkingDirectory = ($TargetFilePath | Split-Path -Parent)
			}
			
			if ($PSCmdlet.ShouldProcess($FilePath,'New shortcut')) {
				Write-Verbose -Message "Creating shortcut at $FilePath using targetpath $TargetPath"
				$Object.Save()
				if (Test-Path -Path $FilePath -PathType Leaf)
				{
					Write-Verbose -Message "Shortcut at $FilePath was successfully created"
				}
			}
		}
		catch
		{
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function Remove-MyService
{
	<#
	.SYNOPSIS
		This function stops and removes a Windows service
	.EXAMPLE
		Remove-MyService -Name bnpagent
	.PARAMETER ServiceName
	 	The service name you'd like to stop and remove
	#>
	[OutputType([void])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Get-Service -Name $_ -ErrorAction 'SilentlyContinue' })]
		[string]$Name
	)
	process
	{
		try
		{
			$ServicesToRemove = Get-Service $Name
			if (-not $ServicesToRemove)
			{
				Write-Log -Message "-No services to be removed found..."
			}
			else
			{
				foreach ($Service in $ServicesToRemove)
				{
					try
					{
						Write-Log -Message "-Found service $($Service.DisplayName)."
						if ($Service.Status -ne 'Stopped')
						{
							Write-Log -Message "-Service $($Service.Displayname) is not stopped."
							Stop-Service $Service
						}
						else
						{
							Write-Log -Message "-Service $($Service.Displayname) is already stopped."
						}
						Write-Log -Message "-Attempting to remove service $($Service.DisplayName)..."
						$WmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$($Service.ServiceName)'" -ErrorAction 'SilentlyContinue' -ErrorVariable WMIError
						if ($WmiError)
						{
							Write-Log -Message "-Unable to remove service $($Service.DisplayName). WMI query errored with `"$($WmiError.Exception.Message)`"" -LogLevel '2'
						}
						else
						{
							$DeleteService = $WmiService.Delete()
							if ($DeleteService.ReturnValue -ne 0)
							{
								## Delete method error codes http://msdn.microsoft.com/en-us/library/aa389960(v=vs.85).aspx
								Write-Log -Message "-Service $($Service.DisplayName) failed to remove. Delete error code was $($DeleteService.ReturnValue).." -LogLevel '2'
							}
							else
							{
								Write-Log -Message "-Service $($Service.DisplayName) successfully removed..."
							}
						}
					}
					catch
					{
						Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
						$false
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
