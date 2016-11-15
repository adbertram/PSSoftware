Set-StrictMode -Version Latest

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