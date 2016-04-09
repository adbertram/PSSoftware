Set-StrictMode -Version Latest

function Compare-RegistryFileToRegistry
{
	<#
	.SYNOPSIS
		This function compares a .reg file against the local computer registry and returns
		either True or False depending on if every registry value inside the file
		is equal to what's in the registry.
	.EXAMPLE
		PS> Compare-RegistryFileToRegistry -FilePath myreg.reg
	
		This example would read all values inside the myreg.reg file and check the local registry for equality.
	.PARAMETER FilePath
	 	The file path to where the .reg file is located.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[string]$FilePath
	)
	begin
	{
		
		function Convert-Qualifier ($Path)
		{
			$Qualifier = $Path
			
			switch ($Qualifier)
			{
				'HKEY_LOCAL_MACHINE' {
					'HKLM'
				}
				'HKEY_CURRENT_USER' {
					New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
					$LoggedOnSids = Get-LoggedOnUserSID
					foreach ($sid in $LoggedOnSids)
					{
						"HKU:\$sid"
					}
				}
				'HKEY_CLASSES_ROOT' {
					New-PSDrive -Name HKCR -PSProvider Registry -Root Registry::HKEY_CLASSES_ROOT | Out-Null
					'HKCR'
				}
				'HKEY_USERS' {
					New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
					'HKU'
				}
				'HKEY_CURRENT_CONFIG' {
					New-PSDrive -Name HKCC -PSProvider Registry -Root Registry::HKEY_current_config | Out-Null
					'HKCC'
				}
			}
		}
	}
	process
	{
		try
		{
			$FileContents = Get-Content -Path $FilePath -Raw
			$Array = $FileContents -split "`n`r"
			$KeyContents = ($Array[1..$Array.Length]).Trim()
			$Keys = @()
			foreach ($Key in $KeyContents)
			{
				$KeyPath = [regex]::Match(($_ -split "`n")[0], '^\[(.*?)\\').Groups[1].Value
				$Keys += $Key.Replace($KeyPath, (Convert-Qualifier -Path $_))
			}
			
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
			if (!$Key)
			{
				throw "The registry key $Path does not exist"
			}
			$Value = $Key.GetValue($Name)
			if (!$Value)
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

function Get-RegistryValueForAllUsers
{
    <#
	.SYNOPSIS
		This function finds all of the user profile registry hives, mounts them and retrieves a registry value for each user.
	.EXAMPLE
		PS> Get-RegistryValueForAllUsers -RegistryInstance @{'Name' = 'Setting'; 'Path' = 'SOFTWARE\Microsoft\Windows\Something'}
	
		This example would get the string registry value 'Type' in the path 'SOFTWARE\Microsoft\Windows\Something'
		for every user registry hive.
	.PARAMETER RegistryInstance
	 	A hash table containing key names of 'Name' designating the registry value name and 'Path' designating the parent 
		registry key the registry value is in.
	#>
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
		Write-Log -Message "Found $($LoggedOnSids.Count) logged on user SIDs"
		foreach ($sid in $LoggedOnSids)
		{
			Write-Log -Message "Loading the user registry hive for the logged on SID $sid"
			foreach ($instance in $RegistryInstance)
			{
				$Value = Get-ItemProperty -Path "HKU:\$sid\$($instance.Path)" -Name $instance.Name -ErrorAction SilentlyContinue
				if (!$Value)
				{
					Write-Log -Message "Registry value $($instance.name) does not exist in HKU:\$sid\$($instance.Path)" -LogLevel '2'
				}
				else
				{
					$Value
				}
			}
		}
		
		## Read all ProfileImagePath values from all reg keys that match a SID pattern in the ProfileList key
		## Exclude all SIDs from the users that are currently logged on.  Those have already been processed.
		$ProfileSids = (Get-UserProfile).SID
		Write-Log -Message "Found $($ProfileSids.Count) SIDs for profiles"
		$ProfileSids = $ProfileSids | Where-Object { $LoggedOnSids -notcontains $_ }
		
		$ProfileFolderPaths = $ProfileSids | ForEach-Object { Get-UserProfilePath -Sid $_ }
		
		if ((Get-Architecture) -eq 'x64')
		{
			$RegPath = 'syswow64'
		}
		else
		{
			$RegPath = 'System32'
		}
		Write-Log -Message "Reg.exe path is $RegPath"
		
		## Load each user's registry hive into the HKEY_USERS\TempUserLoad key
		foreach ($prof in $ProfileFolderPaths)
		{
			Write-Log -Message "Loading the user registry hive in the $prof profile"
			$Process = Start-Process "$($env:Systemdrive)\Windows\$RegPath\reg.exe" -ArgumentList "load HKEY_USERS\TempUserLoad `"$prof\NTuser.dat`"" -Wait -NoNewWindow -PassThru
			if (Test-Process $Process)
			{
				foreach ($instance in $RegistryInstance)
				{
					Write-Log -Message "Finding property in the HKU\$($instance.Path) path"
					$Value = Get-ItemProperty -Path "HKU:\TempUserLoad\$($instance.Path)" -Name $instance.Name -ErrorAction SilentlyContinue
					if (!$Value)
					{
						Write-Log -Message "Registry value $($instance.name) does not exist in HKU:\TempUserLoad\$($instance.Path)" -LogLevel '2'
					}
					else
					{
						$Value
					}
				}
				$Process = Start-Process "$($env:Systemdrive)\Windows\$RegPath\reg.exe" -ArgumentList "unload HKEY_USERS\TempUserLoad" -Wait -NoNewWindow -PassThru
				Test-Process $Process | Out-Null
			}
			else
			{
				Write-Log -Message "Failed to load registry hive for the '$prof' profile" -LogLevel '3'
			}
		}
		
	}
	catch
	{
		Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
		$PSCmdlet.ThrowTerminatingError($_)
	}
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
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
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
					$null = Set-RegistryValueForAllUsers -RegistryInstance @{ 'Path' = $key.Replace('HKCU:\', '') } -Remove
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

function Set-RegistryValueForAllUsers
{
    <#
	.SYNOPSIS
		This function sets a registry value in every user profile hive.
	.EXAMPLE
		PS> Set-RegistryValueForAllUsers -RegistryInstance @{'Name' = 'Setting'; 'Type' = 'String'; 'Value' = 'someval'; 'Path' = 'SOFTWARE\Microsoft\Windows\Something'}
	
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
	[CmdletBinding()]
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
			Write-Log -Message "Found $($LoggedOnSids.Count) logged on user SIDs"
			foreach ($sid in $LoggedOnSids)
			{
				Write-Log -Message "Loading the user registry hive for the logged on SID $sid"
				foreach ($instance in $RegistryInstance)
				{
					if ($Remove.IsPresent)
					{
						Write-Log -Message "Removing registry key '$($instance.path)'"
						Remove-Item -Path "HKU:\$sid\$($instance.Path)" -Recurse -Force -ErrorAction 'SilentlyContinue'
					}
					else
					{
						if (-not (Get-Item -Path "HKU:\$sid\$($instance.Path)" -ErrorAction 'SilentlyContinue'))
						{
							Write-Log -Message "The registry key HKU:\$sid\$($instance.Path) does not exist.  Creating..."
							New-Item -Path "HKU:\$sid\$($instance.Path | Split-Path -Parent)" -Name ($instance.Path | Split-Path -Leaf) -Force | Out-Null
						}
						else
						{
							Write-Log -Message "The registry key HKU:\$sid\$($instance.Path) already exists. No need to create."
						}
						Write-Log -Message "Setting registry value $($instance.Name) at path HKU:\$sid\$($instance.Path) to $($instance.Value)"
						New-ItemProperty -Path "HKU:\$sid\$($instance.Path)" -Name $instance.Name -Value $instance.Value -PropertyType $instance.Type -Force
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
						Write-Log -Message "The registry key 'HKCU:\$($instance.Path)'' does not exist.  Creating..."
						New-Item -Path "HKCU:\$($instance.Path) | Split-Path -Parent)" -Name ("HKCU:\$($instance.Path)" | Split-Path -Leaf) -Force | Out-Null
					}
					$CommandLine = "reg add `"{0}`" /v {1} /t {2} /d {3} /f" -f "HKCU\$($instance.Path)", $instance.Name, $RegValueType, $instance.Value
				}
				Set-AllUserStartupAction -CommandLine $CommandLine
				
			}
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}