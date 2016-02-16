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
			Write-Log -Message "$($MyInvocation.MyCommand) - BEGIN"
			if ($PSBoundParameters.ContainsKey('Name')) {
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
			$false
		}
		finally
		{
			Write-Log -Message "$($MyInvocation.MyCommand) - END"
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
			Write-Log -Message "$($MyInvocation.MyCommand) - BEGIN"
			$UninstallKeys = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
			New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
			$UninstallKeys += Get-ChildItem HKU: | where { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } | foreach { "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
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
					Write-Verbose -Message "Checking uninstall key [$($UninstallKey)]"
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
						Write-Verbose -Message "No software keys in uninstall key $UninstallKey"
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
							New-Object –TypeName PSObject –Prop $output
						}
					}
				}
			}
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
		}
		finally
		{
			Write-Log -Message "$($MyInvocation.MyCommand) - END"
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
		[Parameter(ParameterSetName = 'InstallShield',Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[ValidatePattern('\.exe$')]
		[ValidateNotNullOrEmpty()]
		[string]$InstallShieldInstallerFilePath,
		
		[Parameter(ParameterSetName = 'Other',Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[ValidatePattern('\.exe$')]
		[ValidateNotNullOrEmpty()]
		[string]$OtherInstallerFilePath,
		
		[Parameter(ParameterSetName = 'InstallShield',Mandatory = $true)]
		[ValidatePattern('\.iss$')]
		[ValidateNotNullOrEmpty()]
		[string]$IssFilePath,
		
		[Parameter(ParameterSetName = 'MSI',Mandatory = $true)]
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
			Write-Log -Message "$($MyInvocation.MyCommand) - BEGIN"
			
			## Common Start-Process parameters across all installers. We'll add to this hashtable as we go
			$ProcessParams = @{
				'NoNewWindow' = $true;
				'Passthru' = $true
			}
			
			if ($PSBoundParameters.ContainsKey('MsiInstallerFilePath')) {
				$InstallerFilePath = $MsiInstallerFilePath
				Write-Log -Message 'Creating the msiexec install string'
				
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
				if ($MsiExecSwitches)
				{
					$InstallArgs += $MsiExecSwitches
				}
				
				## Once we've added all of the custom syntax elements we'll then add a few more default
				## switches.  REBOOT=ReallySuppress prevents the computer from rebooting if it exists with an
				## exit code of 3010, ALLUSERS=1 means that we'd like to make this software for all users
				## on the machine and /Lvx* is the most verbose way to specify a log file path and to log as
				## much information as possible.
                if (-not $PSBoundParameters.ContainsKey('LogFilePath')) {
                    $LogFilePath = "$(Get-SystemTempFolderPath)\$($InstallerFilePath | Split-Path -Leaf).log"
                }
				$InstallArgs += "REBOOT=ReallySuppress ALLUSERS=1 /Lvx* `"$LogFilePath`""
				$InstallArgs = $InstallArgs -join ' '
				
				## Add Start-Process parameters
				$ProcessParams['FilePath'] = 'msiexec.exe'
				$ProcessParams['ArgumentList'] = $InstallArgs
			}
			elseif ($PSBoundParameters.ContainsKey('InstallShieldInstallerFilePath'))
			{
				$InstallerFilePath = $InstallShieldInstallerFilePath
				Write-Log -Message 'Creating the InstallShield setup install string'
				
				## We're adding common InstallShield switches here. -s is silent, -f1 specifies where the 
				## ISS file we createed previously lives, -f2 specifies a log file location and /SMS is a special
				## switch that prevents the setup.exe was exiting prematurely.
				if (-not $PSBoundParameters.ContainsKey('LogFilePath')) {
                    $LogFilePath = "$(Get-SystemTempFolderPath)\$($InstallerFilePath | Split-Path -Leaf).log"
                }
                if (-not $InstallShieldInstallArgs)
				{
					$InstallArgs = "-s -f1`"$IssFilePath`" -f2`"$LogFilePath`" /SMS"
				}
				else
				{
					$InstallArgs = "-s -f1`"$IssFilePath`" $InstallShieldInstallArgs -f2`"$LogFilePath`" /SMS"
				}
				## Add Start-Process parameters
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
				$KillProcess | foreach { Stop-MyProcess -ProcessName $_ }
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
			$false
		}
		finally
		{
			Write-Log -Message "$($MyInvocation.MyCommand) - END"
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
	.PARAMETER KillProcess
		One or more process names to attempt to kill prior to software uninstall.  By default, all EXEs in the installation 
		folder are found and all matching running processes are killed.  This would be for any additional processes you'd
		like to kill.
	.PARAMETER RemoveService
		One or more services to attempt to stop and remove prior to software uninstall
	.PARAMETER MsiExecSwitches
		Specify a string of switches you'd like msiexec.exe to run when it attempts to uninstall the software. By default,
		it already uses "/x GUID /qn".  You can specify any additional parameters here.
	.PARAMETER LogFilePath
		The file path where the msiexec uninstall log will be created.  This defaults to the name of the product being
		uninstalled in the system temp directory
	.PARAMETER InstallshieldLogFilePath
		The file path where the Installshield log will be created.  This defaults to the name of the product being
		uninstalled in the system temp directory
	.PARAMETER Shortcut
		By default, all LNK shortcuts in all user profile folders pointing to the install folder location of the software being removed and all
		LNK shortcuts pointing to any folder you're removing with the RemoveFolder parameter.  Use this parameter to specify any
		additional shortcuts you'd like to remove. Specify a hash table of search types and search values to match in all LNK and URL files in all 
		folders in all user profiles and have them removed. If the RemoveFolder param is specified, this will inherently be
		done matching the 'MatchingTargetPath' attribute on the folder specified there.
	
		The options for the keys in this hash table are MatchingTargetPath,MatchingName and MatchingFilePath.  Use each
		key along with the value of what you'd like to search for and remove.
	.PARAMETER RemoveFolder
		One or more folders to recursively remove after software uninstall. This is beneficial for those
		applications that do not clean up after themselves.  If this param is specified, all shortcuts related to this
		folder path will be removed in all user profile folders also.
	.PARAMETER RemoveRegistryKey
		One or more registry key paths to recursively remove after software install.  Use a Powershell-friendly registry
		key path like 'HKLM:\Software\SomeSoftware\DeleteThisKey' or 'HKCU:\Software\SomeSoftware\DeleteThisUserKey'.  The HKCU
		references will be converted to the appropriate paths to remove that key from all user registry hives.
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
		[Parameter(Mandatory = $true,
				   ValueFromPipelineByPropertyName = $true)]
		[string]$Name,
		
		[Parameter()]
		[string[]]$KillProcess,
		
		[Parameter()]
		[string[]]$RemoveService,
		
		[Parameter(ParameterSetName = 'MSI')]
		[string]$MsiExecSwitches,
		
		[Parameter()]
		[string]$LogFilePath,
		
		[Parameter(ParameterSetName = 'ISS')]
		[string]$InstallshieldLogFilePath,
		
		[Parameter()]
		[string[]]$RemoveFolder,
		
		[Parameter()]
		[string[]]$RemoveRegistryKey,
		
		[Parameter()]
		[hashtable]$Shortcut,
		
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
			Write-Log -Message "$($MyInvocation.MyCommand) - BEGIN"
			if ($KillProcess)
			{
				Stop-MyProcess $KillProcess
			}
			
			if ($RemoveService)
			{
				Remove-MyService $RemoveService
			}
			
			Write-Log -Message "Finding all software titles registered under the name '$Name'"
			$swInstance = Get-InstalledSoftware -Name $Name
			if (-not $swInstance)
			{
				Write-Log -Message "The software [$($Name)]	was not found"
			}
			else
			{
				foreach ($swEntry in $swInstance)
				{
					try
					{
						if ($swEntry.InstallLocation)
						{
							Write-Log -Message "Stopping all processes under the install folder $($swEntry.InstallLocation)..."
							$Processes = (Get-Process | where { $_.Path -like "$($swEntry.InstallLocation)*" } | select -ExpandProperty Name)
							if ($Processes)
							{
								Write-Log -Message "Sending processes: $Processes to Stop-MyProcess..."
								## Check to see if the process is still running.  It's possible the termination of other processes
								## already killed this one.
								$Processes = $Processes | where { Get-Process -Name $_ -ea 'SilentlyContinue' }
								Stop-MyProcess $Processes
							}
							else
							{
								Write-Log -Message 'No processes running under the install folder path'
							}
						}
						
						if ($swEntry.UninstallString)
						{
							$InstallerType = Get-InstallerType $swEntry.UninstallString
						}
						else
						{
							Write-Log -Message "Uninstall string for $Name not found" -LogLevel '2'
						}
						if (!$PsBoundParameters['LogFilePath'])
						{
							$script:LogFilePath = "$(Get-SystemTempFolderPath)\$Name.log"
							Write-Log -Message "No log file path specified.  Defaulting to $script:LogFilePath..."
						}
						if (!$InstallerType -or ($InstallerType -eq 'Windows Installer'))
						{
							Write-Log -Message "Installer type detected to be Windows Installer or unknown for $Name. Attempting Windows Installer removal" -LogLevel '2'
							$params = @{ }
							if ($PSBoundParameters.ContainsKey('MsiExecSwitches')) {
								$params.MsiExecSwitches = $MsiExecSwitches
							}
							if ($swEntry.GUID)
							{
								$params.Guid = $swEntry.GUID
							}
							else
							{
								$params.Name = $Name	
							}
							
							Uninstall-WindowsInstallerPackage @params
							
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
							Uninstall-InstallShieldPackage @Params
						}
						if (!(Test-InstalledSoftware -Name $Name))
						{
							Write-Log -Message "Successfully removed $Name!"
						}
						else
						{
							Write-Log -Message "$Name was not uninstalled via traditional uninstall" -LogLevel '2'
							if ($RunMsizap.IsPresent)
							{
								Write-Log -Message "Attempting Msizap..."
								Uninstall-ViaMsizap -Guid $swEntry.GUID -MsizapFilePath $MsizapFilePath -Params $MsiZapParams
							}
							else
							{
								Write-Log -Message "$Name failed to uninstall successfully" -LogLevel '3'
							}
						}
						if ($RemoveRegistryKey)
						{
							Write-Log -Message 'Beginning registry key removal...'
							foreach ($Key in $RemoveRegistryKey)
							{
								if (($Key | Split-Path -Qualifier) -eq 'HKLM:')
								{
									Write-Log -Message "Removing HKLM registry key '$Key' for system"
									Remove-Item -Path $Key -Recurse -Force -ea 'SilentlyContinue'
								}
								elseif (($Key | Split-Path -Qualifier) -eq 'HKCU:')
								{
									Write-Log -Message "Removing HKCU registry key '$Key' for all users"
									Set-RegistryValueForAllUsers -RegistryInstance @{ 'Path' = $Key.Replace('HKCU:\', '') } -Remove
								}
								else
								{
									Write-Log -Message "Registry key '$Key' not in recognized format" -LogLevel '2'
								}
							}
						}
						
						if ($InstallFolderPath)
						{
							Write-Log -Message "Removing any user profile shortcuts associated with the software if an install location was found"
							Get-Shortcut -MatchingTargetPath $InstallFolderPath | Remove-Item -Force
						}
						
						if ($Shortcut)
						{
							Write-Log -Message "Removing all shortcuts in all user profile folders"
							foreach ($key in $Shortcut.GetEnumerator())
							{
								$Params = @{ $key.Name = $key.value }
								Get-Shortcut $Params | Remove-Item -Force -ea 'Continue'
							}
						}
						
						if ($RemoveFolder)
						{
							Write-Log -Message "Starting folder removal..."
							foreach ($Folder in $RemoveFolder)
							{
								try
								{
									Write-Log -Message "Checking for $Folder existence..."
									if (Test-Path $Folder -PathType 'Container')
									{
										Write-Log -Message "Found folder $Folder.  Attempting to remove..."
										Remove-Item $Folder -Force -Recurse -ea 'Continue'
										if (!(Test-Path $Folder -PathType 'Container'))
										{
											Write-Log -Message "Successfully removed $Folder"
										}
										else
										{
											Write-Log -Message "Failed to remove $Folder" -LogLevel '2'
										}
									}
									else
									{
										Write-Log -Message "$Folder was not found..."
									}
									Get-Shortcut -MatchingTargetPath $Folder -ErrorAction 'SilentlyContinue' | Remove-Item -ea 'Continue' -Force
								}
								catch
								{
									Write-Log -Message "Error occurred: '$($_.Exception.Message)' attempting to remove folder" -LogLevel '3'
								}
							}
						}
					}
					catch
					{
						Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
					}
				}
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