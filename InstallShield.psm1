Set-StrictMode -Version Latest

function New-InstallshieldIntallString
{
	[OutputType([string])]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$InstallerFilePath,
	
		[Parameter(Mandatory)]
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
	[OutputType()]
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