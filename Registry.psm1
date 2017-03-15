Set-StrictMode -Version Latest

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
				($Result = Start-Process "$($env:Systemdrive)\Windows\$RegPath\reg.exe" -ArgumentList "import `"$FilePath`"" -Wait -NoNewWindow -PassThru) | Out-Null
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