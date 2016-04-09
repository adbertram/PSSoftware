Set-StrictMode -Version Latest

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
	[OutputType([Selected.System.Management.Automation.PSCustomObject])]
	[CmdletBinding()]
	param ()
	process
	{
		try
		{
			
			Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\*' |
			Select-Object -ExcludeProperty SID *, @{ n = 'SID'; e = { $_.PSChildName } }, @{ n = 'Username'; e = { $_.ProfileImagePath | Split-Path -Leaf } }
			
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
			#
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
				$WhereBlock = { $_.PSChildName -ne $null }
			}
			Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList' | Where-Object $WhereBlock | ForEach-Object { $_.GetValue('ProfileImagePath') }
			#
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
	[OutputType()]
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
				if (!(Test-Path "$AllUserProfileFolderPath\$p"))
				{
					Write-Log -Message "The folder '$AllUserProfileFolderPath\$p' does not exist"
				}
				else
				{
					Remove-Item -Path "$AllUserProfileFolderPath\$p" -Force -Recurse
				}
				
				
				foreach ($ProfilePath in $UserProfileFolderPaths)
				{
					if (!(Test-Path "$ProfilePath\$p"))
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
	[OutputType()]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]$CommandLine
	)
	process
	{
		try
		{
			
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
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}