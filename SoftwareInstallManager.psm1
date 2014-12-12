#region SoftwareDetection
function Compare-FilePath {
	<#
	.SYNOPSIS
		This function checks the hash of 2 files see if they are the same
	.EXAMPLE
		PS> Compare-FilePath -ReferencePath 'C:\Windows\file.txt' -DifferencePath '\\COMPUTER\c$\Windows\file.txt'
	
		This example checks to see if the file C:\Windows\file.txt is exactly the same as the file \\COMPUTER\c$\Windows\file.txt
	.PARAMETER ReferencePath
		The first file path to compare
	.PARAMETER DifferencePath
		The second file path to compare
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
		[string]$ReferenceFilePath,
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
		[string]$DifferenceFilePath
	)
	process {
		try {
			$ReferenceHash = Get-MyFileHash -Path $ReferenceFilePath
			$DifferenceHash = Get-MyFileHash -Path $DifferenceFilePath
			if ($ReferenceHash.SHA256 -ne $DifferenceHash.SHA256) {
				$false
			} else {
				$true
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Compare-FolderPath {
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
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType Container })]
		[string]$ReferenceFolderPath,
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType Container })]
		[string]$DifferenceFolderPath
	)
	process {
		try {
			$ReferenceFiles = Get-ChildItem -Path $ReferenceFolderPath -Recurse | where { !$_.PsIsContainer }
			$DifferenceFiles = Get-ChildItem -Path $DifferenceFolderPath -Recurse | where { !$_.PsIsContainer }
			if ($ReferenceFiles.Count -ne $DifferenceFiles.Count) {
				Write-Log -Message "Folder path '$ReferenceFolderPath' and '$DifferenceFolderPath' file counts are different" -LogLevel '2'
				$false
			} elseif (Compare-Object -ReferenceObject ($ReferenceFiles | Get-MyFileHash) -DifferenceObject ($DifferenceFiles | Get-MyFileHash)) {
				Write-Log -Message "Folder path '$ReferenceFolderPath' and '$DifferenceFolderPath' file hashes are different" -LogLevel '2'
				$false
			} else {
				Write-Log -Message "Folder path '$ReferenceFolderPath' and '$DifferenceFolderPath' have equal contents"
				$true
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Compare-RegistryFileToRegistry {
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
	begin {
		function Convert-Qualifier ($Path) {
			$Qualifier = $Path
			
			switch ($Qualifier) {
				'HKEY_LOCAL_MACHINE' {
					'HKLM'
				}
				'HKEY_CURRENT_USER' {
					New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
					$LoggedOnSids = Get-LoggedOnUserSID
					foreach ($sid in $LoggedOnSids) {
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
	process {
		try {
			$FileContents = Get-Content -Path $FilePath -Raw
			$Array = $FileContents -split "`n`r"
			$KeyContents = ($Array[1..$Array.Length]).Trim()
			$Keys = @()
			foreach ($Key in $KeyContents) {
				$KeyPath = [regex]::Match(($_ -split "`n")[0], '^\[(.*?)\\').Groups[1].Value
				$Keys += $Key.Replace($KeyPath, (Convert-Qualifier -Path $_))
			}
			
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Get-FileVersion {
	<#
	.SYNOPSIS
		This function finds the file version of a file.  This is useful for applications that don't
		register themselves properly with Windows Installer
	.PARAMETER FilePath
	 	A valid file path
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[string]$FilePath
	)
	process {
		try {
			(Get-ItemProperty -Path $FilePath).VersionInfo.FileVersion
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Get-MyFileHash {
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
	[CmdletBinding()]
	Param (
		[Parameter(Position = 0, Mandatory = $true, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $True)]
		[Alias("PSPath", "FullName")]
		[string[]]$Path,
		
		[Parameter(Position = 1)]
		[ValidateSet("MD5", "SHA1", "SHA256", "SHA384", "SHA512", "RIPEMD160")]
		[string[]]$Algorithm = "SHA256"
	)
	Process {
		ForEach ($item in $Path) {
			try {
				$item = (Resolve-Path $item).ProviderPath
				If (-Not ([uri]$item).IsAbsoluteUri) {
					Write-Verbose ("{0} is not a full path, using current directory: {1}" -f $item, $pwd)
					$item = (Join-Path $pwd ($item -replace "\.\\", ""))
				}
				If (Test-Path $item -Type Container) {
					Write-Warning ("Cannot calculate hash for directory: {0}" -f $item)
					Return
				}
				$object = New-Object PSObject -Property @{
					Path = $item
				}
				#Open the Stream
				$stream = ([IO.StreamReader]$item).BaseStream
				foreach ($Type in $Algorithm) {
					[string]$hash = -join ([Security.Cryptography.HashAlgorithm]::Create($Type).ComputeHash($stream) |
					ForEach { "{0:x2}" -f $_ })
					$null = $stream.Seek(0, 0)
					#If multiple algorithms are used, then they will be added to existing object
					$object = Add-Member -InputObject $Object -MemberType NoteProperty -Name $Type -Value $Hash -PassThru
				}
				$object.pstypenames.insert(0, 'System.IO.FileInfo.Hash')
				#Output an object with the hash, algorithm and path
				Write-Output $object
				
				#Close the stream
				$stream.Close()
			} catch {
				Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
				$false
			}
		}
	}
}

function Validate-IsSoftwareInstalled {
	<#
	.SYNOPSIS
		This function is used as a quick check to see if a specific software product is installed on the local host.
	.PARAMETER ProductName
	 	The name of the software you'd like to query as displayed by the Get-InstalledSoftware function
	.PARAMETER Version
		The version of the software you'd like to query as displayed by the Get-InstalledSofware function.
	.PARAMETER Guid
		The GUID of the installed software
	#>
	[CmdletBinding(DefaultParameterSetName = 'Productname')]
	param (
		[Parameter(ParameterSetName = 'ProductName')]
		[Alias('Name')]
		[string]$ProductName,
		[Parameter(ParameterSetName = 'ProductName')]
		[string]$Version,
		[Parameter(ParameterSetName = 'Guid')]
		[Alias('ProductCode')]
		[string]$Guid
	)
	process {
		try {
			if ($ProductName) {
				$Params = @{ 'Name' = $ProductName }
				if ($Version) {
					$Params.Version = $Version
				}
			} elseif ($Guid) {
				$Params = @{ 'Guid' = $Guid }
			}
			$SoftwareInstances = Get-InstalledSoftware @Params
			if (!$SoftwareInstances) {
				Write-Log -Message "'$ProductName' is NOT installed."
				$false
			} else {
				Write-Log -Message "'$ProductName' IS installed."
				$true
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}
#endregion

#region Registry
function Get-MyRegistryValue {
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
	process {
		try {
			$Key = Get-Item -Path $Path -ea 'SilentlyContinue'
			if (!$Key) {
				throw "The registry key $Path does not exist"
			}
			$Value = $Key.GetValue($Name)
			if (!$Value) {
				throw "The registry value $Name in the key $Path does not exist"
			}
			[pscustomobject]@{ 'Path' = $Path; 'Value' = $Value; 'Type' = $key.GetValueKind($Name) }
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Get-RegistryValueForAllUsers {
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
	try {
		New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
		
		## Find the registry values for the currently logged on user
		$LoggedOnSids = Get-LoggedOnUserSID
		Write-Log -Message "Found $($LoggedOnSids.Count) logged on user SIDs"
		foreach ($sid in $LoggedOnSids) {
			Write-Log -Message "Loading the user registry hive for the logged on SID $sid"
			foreach ($instance in $RegistryInstance) {
				$Value = Get-ItemProperty -Path "HKU:\$sid\$($instance.Path)" -Name $instance.Name -ea SilentlyContinue
				if (!$Value) {
					Write-Log -Message "Registry value $($instance.name) does not exist in HKU:\$sid\$($instance.Path)" -LogLevel '2'
				} else {
					$Value
				}
			}
		}
		
		## Read all ProfileImagePath values from all reg keys that match a SID pattern in the ProfileList key
		## Exclude all SIDs from the users that are currently logged on.  Those have already been processed.
		$ProfileSids = Get-ProfileSids
		Write-Log -Message "Found $($ProfileSids.Count) SIDs for profiles"
		$ProfileSids = $ProfileSids | where { $LoggedOnSids -notcontains $_ }
		
		$ProfileFolderPaths = $ProfileSids | foreach { Get-UserProfilePath -Sid $_ }
		
		if ((Get-Architecture) -eq 'x64') {
			$RegPath = 'syswow64'
		} else {
			$RegPath = 'System32'
		}
		Write-Log -Message "Reg.exe path is $RegPath"
		
		## Load each user's registry hive into the HKEY_USERS\TempUserLoad key
		foreach ($prof in $ProfileFolderPaths) {
			Write-Log -Message "Loading the user registry hive in the $prof profile"
			$Process = Start-Process "$($env:Systemdrive)\Windows\$RegPath\reg.exe" -ArgumentList "load HKEY_USERS\TempUserLoad `"$prof\NTuser.dat`"" -Wait -NoNewWindow -PassThru
			if (Check-Process $Process) {
				foreach ($instance in $RegistryInstance) {
					Write-Log -Message "Finding property in the HKU\$($instance.Path) path"
					$Value = Get-ItemProperty -Path "HKU:\TempUserLoad\$($instance.Path)" -Name $instance.Name -ea SilentlyContinue
					if (!$Value) {
						Write-Log -Message "Registry value $($instance.name) does not exist in HKU:\TempUserLoad\$($instance.Path)" -LogLevel '2'
					} else {
						$Value
					}
				}
				$Process = Start-Process "$($env:Systemdrive)\Windows\$RegPath\reg.exe" -ArgumentList "unload HKEY_USERS\TempUserLoad" -Wait -NoNewWindow -PassThru
				Check-Process $Process | Out-Null
			} else {
				Write-Log -Message "Failed to load registry hive for the '$prof' profile" -LogLevel '3'
			}
		}
	} catch {
		Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
		$false
	}
}

function Import-RegistryFile {
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
	begin {
		try {
			## Detect if this is a registry file for HKCU, HKLM, HKU, HKCR or HKCC keys
			$Regex = 'HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_LOCAL_MACHINE|HKEY_USERS|HKEY_CURRENT_CONFIG'
			$HiveNames = Select-String -Path $FilePath -Pattern $Regex | foreach { $_.Matches.Value }
			$RegFileHive = $HiveNames | Select-Object -Unique
			if ($RegFileHive -is [array]) {
				throw "The registry file at '$FilePath' contains more than one hive reference."
			}
			if ((Get-Architecture) -eq 'x64') {
				$RegPath = 'syswow64'
			} else {
				$RegPath = 'System32'
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			return $false
		}
		
	}
	process {
		try {
			if ($RegFileHive -ne 'HKEY_CURRENT_USER') {
				Write-Log -Message "Detected registry file with $RegFileHive keys"
				Write-Log -Message 'Starting registry import...'
				$Result = Start-Process "$($env:Systemdrive)\Windows\$RegPath\reg.exe" -Args "import $FilePath" -Wait -NoNewWindow -PassThru
				Check-Process -Process $Result
				Write-Log -Message 'Registry file import done'
			} else {
				#########
				## Import the registry file for the currently logged on user
				#########
				Write-Log -Message "Detected registry file with $RegFileHive keys"
				$LoggedOnSids = Get-LoggedOnUserSID
				if ($LoggedOnSids.Count -gt 0) {
					Write-Log -Message "Found $($LoggedOnSids.Count) logged on user SIDs"
					foreach ($sid in $LoggedOnSids) {
						## Replace all HKEY_CURRENT_USER references to HKCU\%SID% so that it can be applied to HKCU while not
						## actually running under that context.  Create a new reg file with the replacements in the system's temp folder
						$HkcuRegFilePath = "$(Get-SystemTempFilePath)\$($FilePath | Split-Path -Leaf)"
						Write-Log -Message "Replacing HKEY_CURRENT_USER references with HKEY_USERS\$sid and placing temp file in $HkcuRegFilePath"
						Find-InTextFile -FilePath $FilePath -Find $RegFileHive -Replace "HKEY_USERS\$sid" -NewFilePath $HkcuRegFilePath -Force
						
						## Perform a recursive function call to itself to import the newly created reg file
						Write-Log -Message "Importing reg file $HkcuRegFilePath"
						Import-RegistryFile -FilePath $HkcuRegFilePath
						Write-Log -Message "Removing temporary registry file $HkcuRegFilePath"
						Remove-Item $HkcuRegFilePath -Force
					}
				} else {
					Write-Log -Message 'No users currently logged on.  Skipping current user registry import'
				}
				
				########
				## Use Active Setup to create a registry value to perform an import of the registry file for each logged on user
				########
				Write-Log -Message "Copying $FilePath to systemp temp folder for later user"
				Copy-Item -Path $FilePath -Destination "$(Get-SystemTempFilePath)\$($FilePath | Split-Path -Leaf)"
				Write-Log -Message "Setting Everyone full control on temp registry file so all users can import it"
				$Params = @{
					'Path' = "$(Get-SystemTempFilePath)\$($FilePath | Split-Path -Leaf)"
					'Identity' = 'Everyone'
					'Right' = 'Modify';
					'InheritanceFlags' = 'None';
					'PropagationFlags' = 'NoPropagateInherit';
					'Type' = 'Allow';
				}
				Set-MyFileSystemAcl @Params
				
				Write-Log -Message "Setting registry file to import for each user"
				
				## This isn't the *best* way to do this because this doesn't prevent a user from clearing out all the temp files
				Set-AllUserStartupAction -CommandLine "reg import `"$(Get-SystemTempFilePath)\$($FilePath | Split-Path -Leaf)`""
				
			}
			
			
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Set-RegistryValueForAllUsers {
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
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[hashtable[]]$RegistryInstance,
		[switch]$Remove
	)
	process {
		try {
			New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
			
			## Change the registry values for the currently logged on user
			$LoggedOnSids = Get-LoggedOnUserSID
			Write-Log -Message "Found $($LoggedOnSids.Count) logged on user SIDs"
			foreach ($sid in $LoggedOnSids) {
				Write-Log -Message "Loading the user registry hive for the logged on SID $sid"
				foreach ($instance in $RegistryInstance) {
					if ($Remove.IsPresent) {
						Write-Log -Message "Removing registry key '$($instance.path)'"
						Remove-Item -Path "HKU:\$sid\$($instance.Path)" -Recurse -Force -ea 'SilentlyContinue'
					} else {
						if (!(Get-Item -Path "HKU:\$sid\$($instance.Path)" -ea 'SilentlyContinue')) {
							Write-Log -Message "The registry key HKU:\$sid\$($instance.Path) does not exist.  Creating..."
							New-Item -Path "HKU:\$sid\$($instance.Path | Split-Path -Parent)" -Name ($instance.Path | Split-Path -Leaf) -Force | Out-Null
						} else {
							Write-Log -Message "The registry key HKU:\$sid\$($instance.Path) already exists. No need to create."
						}
						Write-Log -Message "Setting registry value $($instance.Name) at path HKU:\$sid\$($instance.Path) to $($instance.Value)"
						
						Set-ItemProperty -Path "HKU:\$sid\$($instance.Path)" -Name $instance.Name -Value $instance.Value -Type $instance.Type -Force
					}
				}
			}
			
			foreach ($instance in $RegistryInstance) {
				if ($Remove.IsPresent) {
					if ($instance.Path.Split('\')[0] -eq 'SOFTWARE' -and ((Get-Architecture) -eq 'x64')) {
						$Split = $instance.Path.Split('\')
						$x86Path = "HKCU\SOFTWARE\Wow6432Node\{0}" -f ($Split[1..($Split.Length)] -join '\')
						$CommandLine = "reg delete `"{0}`" /f && reg delete `"{1}`"" -f "HKCU\$($instance.Path)", $x86Path
					} else {
						$CommandLine = "reg delete `"{0}`" /f" -f "HKCU\$($instance.Path)"
					}
				} else {
					## Convert the registry value type to one that reg.exe can understand
					switch ($instance.Type) {
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
						default {
							throw "Registry type '$($instance.Type)' not recognized"
						}
					}
					$CommandLine = "reg add `"{0}`" /v {1} /t {2} /d {3} /f" -f "HKCU\$($instance.Path)", $instance.Name, $RegValueType, $instance.Value
				}
				Set-AllUserStartupAction -CommandLine $CommandLine
				
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Register-File {
	<#
	.SYNOPSIS
		A function that uses the utility regsvr32.exe utility to register a file
	.PARAMETER FilePath
		The file path
	#>
	[CmdletBinding()]
	param (
		[Parameter()]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[string]$FilePath
	)
	process {
		try {
			$Result = Start-Process -FilePath 'regsvr32.exe' -Args "/s `"$FilePath`"" -Wait -NoNewWindow -PassThru
			Wait-MyProcess -ProcessId $Result.Id
			Check-Error -SuccessString "Successfully registered file $FilePath"
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}
#endregion

#region SoftwareManagement
function Get-InstalledSoftware {
	<#
	.SYNOPSIS
		Retrieves a list of all software installed	
	.DESCRIPTION
		Retrieves a list of all software installed via the specified method
	.EXAMPLE
		Get-InstalledSoftware -Name adobe* -Publisher adobe -ComputerName COMPUTER
		This example retrieves all software installed on COMPUTER matching the string starting with 'adobe' and
		with a publisher equal to 'adobe'.
	.EXAMPLE
		Get-InstalledSoftware
		This example retrieves all software installed on the local computer
	.PARAMETER Name
		The software title you'd like to limit the query to.  Wildcards are permitted.
	.PARAMETER Guid
		The software GUID you'e like to limit the query to. No wildcards.
	.PARAMETER Publisher
		The software publisher you'd like to limit the query to. Wildcards are permitted.
	.PARAMETER Version
		The software version you'd like to limit the query to. Wildcards are permitted.
	.PARAMETER Computername
		The computer you'd like to query.  It defaults to the local machine if no computer specified. 
		Multiple computer names are allowed.
	#>
	[CmdletBinding()]
	param (
		[string]$Name,
		[string]$Publisher,
		[string]$Version,
		[ValidatePattern('\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b')]
		[string]$Guid,
		[Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[string[]]$Computername = 'localhost'
	)
	begin {
		$WhereQuery = "SELECT * FROM SMS_InstalledSoftware"
		
		if ($PSBoundParameters.Count -ne 0) {
			## Add any new parameters added here to match with the WMI property name
			$QueryBuild = @{
				'Name' = 'ProductName';
				'Publisher' = 'Publisher';
				'Version' = 'ProductVersion';
				'Guid' = 'SoftwareCode'
			}
			$QueryParams = $PSBoundParameters.GetEnumerator() | where { $QueryBuild.ContainsKey($_.Key) }
			if ($QueryParams) {
				$WhereQuery += ' WHERE'
				$BuiltQueryParams = { @() }.Invoke()
				foreach ($Param in $QueryParams) {
					## Allow asterisks in cmdlet but WQL requires percentage and double backslashes
					$ParamValue = $Param.Value | foreach { $_.Replace('*', '%').Replace('\', '\\') }
					$Operator = @{ $true = 'LIKE'; $false = '=' }[$ParamValue -match '\%']
					$BuiltQueryParams.Add("$($QueryBuild[$Param.Key]) $Operator '$($ParamValue)'")
				}
			}
		}
		$WhereQuery = "$WhereQuery $($BuiltQueryParams -join ' AND ')"
		Write-Log "Using WMI query $WhereQuery..."
		
		$Params = @{
			'Namespace' = 'root\cimv2\sms';
			'Query' = $WhereQuery;
			'ErrorAction' = 'SilentlyContinue';
			'ErrorVariable' = 'MyError'
		}
	}
	process {
		try {
			foreach ($Computer in $Computername) {
				try {
					$Params['ComputerName'] = $Computer
					$Software = Get-WmiObject @Params
					if (Check-Error $MyError "Successfully queried computer $Computer for installed software") {
						$Software | Sort-Object ARPDisplayname;
					}
				} catch {
					Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
					$false
				}
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}##endtry
	}
}

function Install-Software {
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
	.PARAMETER OtherInstallArgs
		This is a string of arguments that are passed to any other EXE installer.  There is no default.
	.PARAMETER KillProcess
		A list of process names that will be terminated prior to attempting the install.  This is useful
		in upgrade scenarios where you need to terminate the previous version's processes.
	.PARAMETER KillProcessDuringInstall
		A list of process names that will be terminated during the install routine.  While the parent process (either msiexec.exe, 
		setup.exe (or similar for InstallShield) or another EXE specified by OtherInstallerPath) is running, this will kill
		any child processes that are spawned during that time.
	.PARAMETER ProcessTimeout
		A value (in seconds) that the installer script will wait for the installation process to complete.  If the installation
		goes over this value, any processes (parent or child) will be terminated.
	.PARAMETER LogFilePath
		This is the path where the installer log file will be written.  If not passed, it will default
		to being named install.log in the system temp folder.
	.PARAMETER NoDefaultLogFilePath
		Use this switch parameter to prevent the default log folder path to be applied.  This is useful
		when you have an installer that uses a proprietary format for logging specified in the installer
		arguments such as 'msiexec.exe install.msi /log logfile.log'
	.PARAMETER RequiredFreeSpace
		This is the free space required on the C drive to check prior to installation.
	#>
	[CmdletBinding(DefaultParameterSetName = 'MSI')]
	param (
		[Parameter(ParameterSetName = 'InstallShield',
				   Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[ValidatePattern('\.exe$')]
		[string]$InstallShieldInstallerFilePath,
		[Parameter(ParameterSetName = 'Other',
				   Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[ValidatePattern('\.exe$')]
		[string]$OtherInstallerFilePath,
		[Parameter(ParameterSetName = 'InstallShield',
				   Mandatory = $true)]
		[ValidatePattern('\.iss$')]
		[string]$IssFilePath,
		[Parameter(ParameterSetName = 'MSI',
				   Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[string]$MsiInstallerFilePath,
		[string]$MsiExecSwitches,
		[Parameter(ParameterSetName = 'MSI')]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[ValidatePattern('\.msp$')]
		[string]$MspFilePath,
		[Parameter(ParameterSetName = 'MSI')]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[ValidatePattern('\.mst$')]
		[string]$MstFilePath,
		[Parameter(ParameterSetName = 'InstallShield')]
		[string]$InstallShieldInstallArgs,
		[Parameter(ParameterSetName = 'Other')]
		[string]$OtherInstallerArgs,
		[Alias('OtherInstallerArguments')]
		[Parameter()]
		[string[]]$KillProcess,
		[Alias('KillProcesPreInstall')]
		[string[]]$KillProcessDuringInstall,
		[int]$ProcessTimeout,
		[string]$LogFilePath,
		[switch]$NoDefaultLogFilePath,
		[string]$RequiredFreeSpace
	)
	
	begin {
		try {
			Write-Log -Message "Beginning software install..."
			
			$ProcessParams = @{
				'NoNewWindow' = $true;
				'Passthru' = $true
			}
						
			$SystemTempFolder = Get-SystemTempFilePath
			Write-Log -Message "Using temp folder $SystemTempFolder..."
			
		} catch {
			Write-Log -Message $_.Exception.Message -LogLevel '3'
		}
	}
	
	process {
		try {
			if ($InstallShieldInstallerFilePath) {
				$InstallerFilePath = $InstallShieldInstallerFilePath
			} elseif ($MsiInstallerFilePath) {
				$InstallerFilePath = $MsiInstallerFilePath
			} elseif ($OtherInstallerFilePath) {
				$InstallerFilePath = $OtherInstallerFilePath
			}
			if (!$LogFilePath -and !$NoDefaultLogFilePath.IsPresent) {
				$InstallerFileName = $InstallerFilePath | Split-Path -Leaf
				$LogFilePath = "$SystemTempFolder\$InstallerFileName.log"
			}
			Write-Log -Message "Using log file path '$LogFilePath'..."
			
			if ($MsiInstallerFilePath) {
				$InstallArgs = @()
				$InstallArgs += "/i `"$InstallerFilePath`" /qn"
				if ($MstFilePath) {
					$InstallArgs += "TRANSFORMS=`"$MstFilePath`""
				}
				if ($MspFilePath) {
					$InstallArgs += "PATCH=`"$MspFilePath`""
				}
				if ($MsiExecSwitches) {
					$InstallArgs += $MsiExecSwitches
				}
				
				$InstallArgs += "REBOOT=ReallySuppress ALLUSERS=1 /Lvx* `"$LogFilePath`""
				$InstallArgs = $InstallArgs -join ' '
				
				$ProcessParams['FilePath'] = 'msiexec.exe'
				$ProcessParams['ArgumentList'] = $InstallArgs
			} elseif ($InstallShieldInstallerFilePath) {
				if (!$InstallShieldInstallArgs) {
					$InstallArgs = "-s -f1`"$IssFilePath`" -f2`"$LogFilePath`" /SMS"
				} else {
					$InstallArgs = "-s -f1`"$IssFilePath`" $InstallShieldInstallArgs -f2`"$LogFilePath`" /SMS"
				}
				$ProcessParams['FilePath'] = $InstallerFilePath
				$ProcessParams['ArgumentList'] = $InstallArgs
			} elseif ($OtherInstallerFilePath) {
				if ($OtherInstallerArgs) {
					$ProcessParams['ArgumentList'] = $OtherInstallerArgs
				}
				$ProcessParams['FilePath'] = $OtherInstallerFilePath
				
			}
			if ($KillProcess) {
				Write-Log -Message 'Killing existing processes'
				$KillProcess | foreach { Stop-MyProcess -ProcessName $_ }
			}
			
			Write-Log -Message "Starting the command line process `"$($ProcessParams['FilePath'])`" $($ProcessParams['ArgumentList'])..."
			$Result = Start-Process @ProcessParams
			Write-Log "Waiting for process ID $($Result.Id)"
			
			$WaitParams = @{'ProcessId' = $Result.Id }
			if ($PSBoundParameters.ProcessTimeout) {
				$WaitParams.ProcessTimeout = $PSBoundParameters.ProcessTimeout
				$WaitParams.KillProcessDuringWait = $PSBoundParameters.KillProcessDuringInstall
			}
			Wait-MyProcess @WaitParams
			Check-Error -SuccessString "Process ID $($Result.Id) ran successfully"
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Remove-Software {
	<#
	.SYNOPSIS
		This function removes any software registered via Windows Installer from the local computer    
	.NOTES
		Created on:   	6/4/2014
		Created by:   	Adam Bertram
		Requirements:   Installed SCCM Client for the SMS_InstalledSoftware WMI class and the 
						Win32Reg_AddRemovePrograms WMI class.
						The msizap utility (if user would like to run)
		Todos:			Add ability to remove registry values/keys
						Read the cached MSI file to get installation directory to use to find shortcuts
						Funtionalize installed software query so user doesn't need SCCM client installed
						Add ability to remove folders in the start menu
	.DESCRIPTION
		This function searches a local computer for a specified application matching a name.  Based on the
		parameters given, it can either remove services, kill proceseses and if the software is
		installed, it uses the locally cached MSI to initiate an uninstall and has the option to 
		ensure the software is completely removed by running the msizap.exe utility.
	.EXAMPLE
		Remove-Software -ProductName 'Adobe Reader' -KillProcess 'proc1','proc2'
		This example would remove any software with 'Adobe Reader' in the name and look for and stop both the proc1 
		and proc2 processes
	.EXAMPLE
	    Remove-Software -ProductName 'Adobe Reader'
		This example would remove any software with 'Adobe Reader' in the name.
	.EXAMPLE
	    Remove-Software -ProductName 'Adobe Reader' -RemoveService 'servicename' -Verbose
		This example would remove any software with 'Adobe Reader' in the name, look for, stop and remove any service with a 
		name of servicename. It will output all verbose logging as well.
	.EXAMPLE
	    Remove-Software -ProductName 'Adobe Reader' -RemoveFolder 'C:\Program Files Files\Install Folder'
		This example would remove any software with 'Adobe Reader' in the name, look for and remove the 
		C:\Program Files\Install Folder, attempt to uninstall the software cleanly via msiexec using 
		the syntax msiexec.exe /x PRODUCTMSI /qn REBOOT=ReallySuppress which would attempt to not force a reboot if needed.
		If it doesn't uninstall cleanly, it would run copy the msizap utility from the default path to 
		the local computer, execute it with the syntax msizap.exe TW! PRODUCTGUID and remove itself when done.
	.PARAMETER ProductName
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
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true)]
		[string[]]$ProductName,
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
		[string]$MsizapFilePath = '\\configmanager\deploymentmodules\softwareinstallmanager\msizap.exe',
		[Parameter(ParameterSetName = 'ISS',
				   Mandatory = $true)]
		[ValidateScript({ Test-Path $_ -PathType 'Leaf' })]
		[ValidatePattern('\.iss$')]
		[string]$IssFilePath,
		[Parameter(ParameterSetName = 'ISS')]
		[ValidateScript({ Test-Path $_ -PathType 'Leaf' })]
		[string]$InstallShieldSetupFilePath
	)
	
	begin {
		try {
			$script:CmClientWmiNamespace = 'root\cimv2\sms'
			
		} catch {
			Write-Log -Message $_.Exception.Message -LogLevel '3'
			return
		}
	}
	
	process {
		try {
			if ($KillProcess) {
				Stop-MyProcess $KillProcess
			}
			
			if ($RemoveService) {
				Remove-MyService $RemoveService
			}
			
			foreach ($Product in $ProductName) {
				Write-Log -Message "Finding all software titles registered under the name '$Product'"
				$SoftwareInstances = Get-InstalledSoftware -Name $Product
				if (!$SoftwareInstances) {
					Write-Log -Message "No software installed that matches product '$Product'"
					break
				}
				foreach ($SoftwareInstance in $SoftwareInstances) {
					$Title = $SoftwareInstance.ARPDisplayname
					$Guid = $SoftwareInstance.SoftwareCode
					
					$InstallFolderPath = Get-InstallLocation -Guid $Guid
					if ($InstallFolderPath -and (@('C:', 'C:\Windows', 'C:\Windows\System32', 'C:\Windows\SysWOW64') -notcontains $InstallFolderPath.Trim())) {
						Write-Log -Message "Checking for processes in install folder '$InstallFolderPath'...."
						Write-Log -Message "Stopping all processes under the install folder $InstallFolderPath..."
						$Processes = (Get-Process | where { $_.Path -like "$InstallFolderPath*" } | select -ExpandProperty Name)
						if ($Processes) {
							Write-Log -Message "Sending processes: $Processes to Stop-MyProcess..."
							## Check to see if the process is still running.  It's possible the termination of other processes
							## already killed this one.
							$Processes = $Processes | where { Get-Process -Name $_ -ea 'SilentlyContinue' }
							Stop-MyProcess $Processes
						} else {
							Write-Log -Message 'No processes running under the install folder path'
						}
					} else {
						Write-Log -Message "Could not find the install folder path to stop open processes" -LogLevel '2'
					}
					
					if ($SoftwareInstance.UninstallString) {
						$InstallerType = Get-InstallerType $SoftwareInstance.UninstallString
					} else {
						Write-Log -Message "Uninstall string for $Title not found" -LogLevel '2'
					}
					if (!$PsBoundParameters['LogFilePath']) {
						$WmiParams = @{
							'Class' = 'Win32_Environment';
							'Filter' = "Name = 'TEMP' AND Username = '<SYSTEM>'"
						}
						$script:LogFilePath = "$((Get-WmiObject @WmiParams).VariableValue)\$Title.log"
						Write-Log -Message "No log file path specified.  Defaulting to $script:LogFilePath..."
					}
					if (!$InstallerType -or ($InstallerType -eq 'Windows Installer')) {
						Write-Log -Message "Installer type detected to be Windows Installer or unknown for $Title. Attempting Windows Installer removal" -LogLevel '2'
						Uninstall-WindowsInstallerPackage -ProductName $Title
					} elseif ($InstallerType -eq 'InstallShield') {
						Write-Log -Message "Installer type detected as Installshield."
						Write-Log -Message "ISS file at $IssFilePath is valid for the GUID $Guid"
						$Params = @{
							'IssFilePath' = $IssFilePath;
							'ProductName' = $Title;
							'SetupFilePath' = $InstallShieldSetupFilePath
						}
						if ($InstallshieldLogFilePath) {
							$Params.InstallshieldLogFilePath = $InstallshieldLogFilePath
						}
						Uninstall-InstallShieldPackage @Params
					}
					if (!(Validate-IsSoftwareInstalled -Name $Title)) {
						Write-Log -Message "Successfully removed $Title!"
					} else {
						Write-Log -Message "$Title was not uninstalled via traditional uninstall" -LogLevel '2'
						if ($RunMsizap.IsPresent) {
							Write-Log -Message "Attempting Msizap..."
							Uninstall-ViaMsizap -Guid $Guid -MsizapFilePath $MsizapFilePath -Params $MsiZapParams
						} else {
							Write-Log -Message "$Title failed to uninstall successfully" -LogLevel '3'
						}
					}
				}
			}
			
			if ($RemoveRegistryKey) {
				Write-Log -Message 'Beginning registry key removal...'
				foreach ($Key in $RemoveRegistryKey) {
					if (($Key | Split-Path -Qualifier) -eq 'HKLM:') {
						Write-Log -Message "Removing HKLM registry key '$Key' for system"
						Remove-Item -Path $Key -Recurse -Force -ea 'SilentlyContinue'
					} elseif (($Key | Split-Path -Qualifier) -eq 'HKCU:') {
						Write-Log -Message "Removing HKCU registry key '$Key' for all users"
						Set-RegistryValueForAllUsers -RegistryInstance @{ 'Path' = $Key.Replace('HKCU:\', '') } -Remove
					} else {
						Write-Log -Message "Registry key '$Key' not in recognized format" -LogLevel '2'
					}
				}
			}
			
			if ($InstallFolderPath) {
				Write-Log -Message "Removing any user profile shortcuts associated with the software if an install location was found"
				Get-Shortcut -MatchingTargetPath $InstallFolderPath | Remove-Item -Force
			}
			
			if ($Shortcut) {
				Write-Log -Message "Removing all shortcuts in all user profile folders"
				foreach ($key in $Shortcut.GetEnumerator()) {
					$Params = @{ $key.Name = $key.value }
					Get-Shortcut $Params | Remove-Item -Force -ea 'Continue'
				}
			}
			
			if ($RemoveFolder) {
				Write-Log -Message "Starting folder removal..."
				foreach ($Folder in $RemoveFolder) {
					try {
						Write-Log -Message "Checking for $Folder existence..."
						if (Test-Path $Folder -PathType 'Container') {
							Write-Log -Message "Found folder $Folder.  Attempting to remove..."
							Remove-Item $Folder -Force -Recurse -ea 'Continue'
							if (!(Test-Path $Folder -PathType 'Container')) {
								Write-Log -Message "Successfully removed $Folder"
							} else {
								Write-Log -Message "Failed to remove $Folder" -LogLevel '2'
							}
						} else {
							Write-Log -Message "$Folder was not found..."
						}
						Get-Shortcut -MatchingTargetPath $Folder -ErrorAction 'SilentlyContinue' | Remove-Item -ea 'Continue' -Force
					} catch {
						Write-Log -Message "Error occurred: '$($_.Exception.Message)' attempting to remove folder" -LogLevel '3'
					}
				}
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}
#endregion

#region UserProfiles
function Get-AllUsersDesktopFolderPath {
	<#
	.SYNOPSIS
		Because sometimes the all users desktop folder path can be different this function is a placeholder to find
		the all users desktop folder path. It uses a shell object to find this path.
	#>
	[CmdletBinding()]
	param ()
	process {
		try {
			$Shell = New-Object -ComObject "WScript.Shell"
			$Shell.SpecialFolders.Item('AllUsersDesktop')
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Get-AllUsersProfileFolderPath {
	<#
	.SYNOPSIS
		Because sometimes the all users profile folder path can be different this function is a placeholder to find
		the all users profile folder path ie. C:\ProgramData or C:\Users\All Users. It uses an environment variable
		to find this path.
	#>
	[CmdletBinding()]
	param ()
	process {
		try {
			$env:ALLUSERSPROFILE
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Get-AllUsersStartMenuFolderPath {
	<#
	.SYNOPSIS
		Because sometimes the all users profile folder path can be different this function is a placeholder to find
		the start menu in the all users profile folder path ie. C:\ProgramData or C:\Users\All Users.
	#>
	[CmdletBinding()]
	param ()
	process {
		try {
			if (((Get-OperatingSystem) -match 'XP') -or ((Get-OperatingSystem) -match '2003')) {
				"$(Get-AllUsersProfileFolderPath)\Start Menu"
			} else {
				"$(Get-AllUsersProfileFolderPath)\Microsoft\Windows\Start Menu"
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Get-ProfileSids {
	<#
	.SYNOPSIS
		This function queries the registry to find all of the SIDs of all the user profiles on the computer.
	#>
	[CmdletBinding()]
	param ()
	process {
		try {
			(Get-Childitem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList' | Where { ($_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$') }).PSChildName
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Get-RootUserProfileFolderPath {
	<#
	.SYNOPSIS
		Because sometimes the root user profile folder path can be different this function is a placeholder to find
		the root user profile folder path ie. C:\Users or C:\Documents and Settings for any OS.  It queries a registry value
		to find this path.
	#>
	[CmdletBinding()]
	param ()
	process {
		try {
			(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name ProfilesDirectory).ProfilesDirectory
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Get-UserProfilePath {
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
	[CmdletBinding(DefaultParameterSetName = 'None')]
	param (
		[Parameter(ParameterSetName = 'SID')]
		[string]$Sid,
		[Parameter(ParameterSetName = 'Username')]
		[string]$Username
	)
	
	process {
		try {
			if ($Sid) {
				$WhereBlock = { $_.PSChildName -eq $Sid }
			} elseif ($Username) {
				$WhereBlock = { $_.GetValue('ProfileImagePath').Split('\')[-1] -eq $Username }
			} else {
				$WhereBlock = { $_.PSChildName -ne $null }
			}
			Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList' | where $WhereBlock | % { $_.GetValue('ProfileImagePath') }
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Remove-ItemFromAllUserProfiles {
	<#
	.SYNOPSIS
		This function removes a file(s) or folder(s) with the same path in all user profiles including
		system profiles like SYSTEM, NetworkService and AllUsers.
	.EXAMPLE
		PS> .\Remove-ItemFromAllUserProfiles -Path 'AppData\Adobe'
	
		This example will remove the folder path 'AppData\Adobe' from all user profiles
	.PARAMETER Path
		The path(s) to the file or folder you'd like to remove.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string[]]$Path
	)
	
	process {
		try {
			$AllUserProfileFolderPath = Get-AllUsersProfileFolderPath
			$UserProfileFolderPaths = Get-UserProfilePath
			
			foreach ($p in $Path) {
				if (!(Test-Path "$AllUserProfileFolderPath\$p")) {
					Write-Log -Message "The folder '$AllUserProfileFolderPath\$p' does not exist"
				} else {
					Remove-Item -Path "$AllUserProfileFolderPath\$p" -Force -Recurse
				}
				
				
				foreach ($ProfilePath in $UserProfileFolderPaths) {
					if (!(Test-Path "$ProfilePath\$p")) {
						Write-Log -Message "The folder '$ProfilePath\$p' does not exist"
					} else {
						Remove-Item -Path "$ProfilePath\$p" -Force -Recurse
					}
				}
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Set-AllUserStartupAction {
	<#
	.SYNOPSIS
		A function that executes a command line for the any current logged on user and uses the Active Setup registry key to set a 
		registry value that contains a command line	EXE with arguments that will be executed once for every user that logs in.
	.PARAMETER CommandLine
		The command line string that will be executed once at every user logon
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]$CommandLine
	)
	process {
		try {
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
			Write-Log -Message 'Done'
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}
#endregion

#region WindowsInstaller
function Uninstall-ViaMsizap {
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
		[string]$MsizapFilePath = '\\configmanager\deploymentmodules\softwareinstallmanager\msizap.exe',
		[Parameter()]
		[string]$LogFilePath = "$(Get-SystemTempFilePath)\msizap.log"
	)
	process {
		try {
			Write-Log -Message "-Starting the process `"$MsiZapFilePath $Params $Guid`"..."
			$NewProcess = Start-Process $MsiZapFilePath -ArgumentList "$Params $Guid" -Wait -NoNewWindow -PassThru -RedirectStandardOutput $LogFilePath
			Wait-MyProcess -ProcessId $NewProcess.Id
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Uninstall-WindowsInstallerPackage {
	<#
	.SYNOPSIS
		This function runs an uninstall for a Windows Installer package
	.PARAMETER ProductName
		The software title of the Windows installer package you'd like to uninstall.  Use either the ProductName
		param or the Guid param to find the Windows installer package.
	.PARAMETER Guid
		The GUID of the Windows Installer package
	#>
	[CmdletBinding(DefaultParameterSetName = 'Guid')]
	param (
		[Parameter(ParameterSetName = 'Name')]
		[Alias('Name')]
		[string]$ProductName,
		[Parameter(ParameterSetName = 'Guid')]
		[ValidatePattern('\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b')]
		[string]$Guid
	)
	process {
		try {
			if ($ProductName) {
				Write-Log -Message "Attempting to uninstall Windows Installer using name '$ProductName'..."
				$Params = @{ 'ProductName' = $ProductName }
			} elseif ($Guid) {
				Write-Log -Message "Attempting to uninstall Windows Installer using GUID '$Guid'..."
				$Params = @{ 'Guid' = $Guid }
			}
			
			## The MSI module does not work with PSv2
			if ($psversiontable.psversion.major -eq 2) {
				Uninstall-WindowsInstallerPackageWithMsiexec @Params
			} else {
				$Result = Uninstall-WindowsInstallerPackageWithMsiModule @Params
				## I've seen instances where using the MSI module does not work but using the traditional msiexec.exe does
				if (!$Result) {
					Uninstall-WindowsInstallerPackageWithMsiexec @Params
				} else {
					$Result
				}
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Uninstall-WindowsInstallerPackageWithMsiexec {
	<#
	.SYNOPSIS
		This function runs an uninstall for a Windows Installer package using msiexec.exe /x
	.PARAMETER ProductName
		The software title of the Windows installer package you'd like to uninstall.  Use either the ProductName
		param or the Guid param to find the Windows installer package.
	.PARAMETER Guid
		The GUID of the Windows Installer package
	#>
	[CmdletBinding(DefaultParameterSetName = 'Guid')]
	param (
		[Parameter(ParameterSetName = 'Name')]
		[Alias('Name')]
		[string]$ProductName,
		[Parameter(ParameterSetName = 'Guid')]
		[ValidatePattern('\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b')]
		[string]$Guid
	)
	process {
		try {
			if ($ProductName) {
				Write-Log -Message "Attempting to uninstall Windows Installer with msiexec.exe using name '$ProductName'..."
				$Params = @{ 'Name' = $ProductName }
			} elseif ($Guid) {
				Write-Log -Message "Attempting to uninstall Windows Installer with msiexec.exe using GUID '$Guid'..."
				$Params = @{ 'Guid' = $Guid }
			}
			$Product = Get-InstalledSoftware @Params
			Write-Log -Message "Initiating msiexec.exe with arguments '/x $($Product.SoftwareCode) /qn REBOOT=ReallySuppress'"
			$Process = Start-Process 'msiexec.exe' -ArgumentList "/x $($Product.SoftwareCode) /qn REBOOT=ReallySuppress" -PassThru -Wait -NoNewWindow
			Wait-WindowsInstaller
			Check-Process $Process
			if (!(Validate-IsSoftwareInstalled @Params)) {
				Write-Log -Message "Successfully uninstalled MSI package with msiexec.exe"
				$true
			} else {
				Write-Log -Message "Failed to uninstall MSI package with msiexec.exe" -LogLevel '3'
				$false
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Uninstall-WindowsInstallerPackageWithMsiModule {
	<#
	.SYNOPSIS
		This function runs an uninstall for a Windows Installer package using the Windows Installer Powershell module
		https://psmsi.codeplex.com
	.PARAMETER ProductName
		The software title of the Windows installer package you'd like to uninstall.  Use either the ProductName
		param or the Guid param to find the Windows installer package.
	.PARAMETER Guid
		The GUID of the Windows Installer package
	#>
	[CmdletBinding(DefaultParameterSetName = 'Guid')]
	param (
		[Parameter(ParameterSetName = 'Name')]
		[Alias('Name')]
		[string]$ProductName,
		[Parameter(ParameterSetName = 'Guid')]
		[ValidatePattern('\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b')]
		[string]$Guid
	)
	process {
		try {
			$ChildModulesPath = '\\configmanager\deploymentmodules'
			if (!(Test-Path "$ChildModulesPath\MSI")) {
				Write-Log -Message "Required MSI module is not available. Moving to msiexec.exe uninstall method" -LogLevel '2'
				$false
			} elseif ((Get-OperatingSystem) -notmatch 'XP') {
				Write-Log -Message "Importing MSI module..."
				Import-Module "$ChildModulesPath\MSI"
			}
			
			$UninstallParams = @{
				'Log' = $script:LogFilePath
				'Chain' = $true
				'Force' = $true
				'ErrorAction' = 'SilentlyContinue'
				'Properties' = 'REBOOT=ReallySuppress'
			}
			
			if ($ProductName) {
				$MsiProductParams = @{ 'Name' = $ProductName }
			} elseif ($Guid) {
				$MsiProductParams = @{ 'ProductCode' = $Guid }
			}
			
			Get-MSIProductInfo @MsiProductParams | Uninstall-MsiProduct @UninstallParams
			Wait-WindowsInstaller
			if (!(Validate-IsSoftwareInstalled @MsiProductParams)) {
				Write-Log -Message "Successfully uninstalled MSI package '$ProductName' with MSI module"
				$true
			} else {
				Write-Log -Message "Failed to uninstall MSI package '$ProductName' with MSI module" -LogLevel '2'
				$false
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Wait-WindowsInstaller {
	<#
	.SYNOPSIS
		This function should be called immediately after the Uninstall-WindowsInstallerPackage function.  This is a specific
		process waiting function especially for msiexec.exe.  It was built because the Wait-MyProcess function will sometimes
		not work with msiexec installs/uninstalls.  This is because msiexec.exe creates a process tree which doesn't necessarily
		mean child processes.  Using this function will ensure your script always wait for the msiexec.exe process you
		kicked off to complete before continuing.
	#>
	[CmdletBinding()]
	param ()
	process {
		try {
			$MsiexecProcesses = Get-WmiObject -Class Win32_Process -Filter "Name = 'msiexec.exe'" | where { $_.CommandLine -ne 'C:\Windows\system32\msiexec.exe /V' }
			if ($MsiExecProcesses) {
				Write-Log -Message "Found '$($MsiexecProcesses.Count)' Windows installer processes.  Waiting..."
				foreach ($Process in $MsiexecProcesses) {
					Wait-MyProcess -ProcessId $Process.ProcessId
				}
				Wait-WindowsInstaller
			} else {
				Write-Log -Message "No Windows installer processes found"
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}
#endregion

#region InstallShield
function Uninstall-InstallShieldPackage {
	<#
	.SYNOPSIS
		This function runs an uninstall for any InstallShield packaged software.  This function utilitizes an
		InstallShield ISS file to silently uninstall the application.
	.PARAMETER ProductName
		One or more software titles of the InstallShield package you'd like to uninstall.
	.PARAMETER IssFilePath
		The file path where the pre-built silent answer file (ISS) is located.
	.PARAMETER SetupFilePath
		The file path where the EXE InstallShield installer is located.
	.PARAMETER LogFilePath
		The log file path where the InstallShield installer will log results.  If not log file path
		is specified it will be created in the system temp folder.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[Alias('Name')]
		[string[]]$ProductName,
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[string]$IssFilePath,
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
		[string]$SetupFilePath,
		[ValidateScript({ Test-Path -Path ($_ | Split-Path -Parent) -PathType 'Container' })]
		[string]$LogFilePath = "(Get-SystemTempFilePath)\IssSetupLog.log"
	)
	process {
		try {
			foreach ($Product in $ProductName) {
				Write-Log -Message "Beginning uninstall for Installshield product '$ProductName'"
				## Find the uninstall string to find the cached setup.exe
				$Products = Get-InstalledSoftware $Product
				## If multiple products are found, remove them all
				foreach ($p in $Products) {
					$Title = $p.ARPDisplayName
					$UninstallString = $p.UninstallString
					## Check to ensure anything is in the UninstallString property
					if (!$p.UninstallString) {
						Write-Log -Message "No uninstall string found for product $Title" -LogLevel '2'
					} elseif ($p.UninstallString -match '(\w:\\[a-zA-Z0-9 _.() { }-]+\\.*.exe)+') {
						## Test to ensure the cached setup.exe exists
						if (!(Test-Path $Matches[0])) {
							Write-Log -Message "Installer file path not found in $($p.UninstallString) or cannot be found on the file system" -LogLevel '2'
						} else {
							$InstallerFilePath = $Matches[0]
							Write-Log -Message "Valid installer file path is $InstallerFilePath"
						}
					}
					if (!$InstallerFilePath) {
						if (!$SetupFilePath) {
							Write-Log -Message "No setup folder path specified. This software cannot be removed" -LogLevel '2'
							continue
						} else {
							$InstallerFilePath = $SetupFilePath
						}
					}
					## Run the setup.exe passing the ISS file to uninstall
					if ($InstallshieldLogFilePath) {
						$MyLogFilePath = $InstallshieldLogFilePath
					} else {
						$MyLogFilePath = $script:LogFilePath
					}
					$InstallArgs = "/s /f1`"$IssFilePath`" /f2`"$MyLogFilePath`" /SMS"
					Write-Log -Message "Running the install syntax `"$InstallerFilePath`" $InstallArgs"
					$Process = Start-Process "`"$InstallerFilePath`"" -ArgumentList $InstallArgs -Wait -NoNewWindow -PassThru
					if (!(Validate-IsSoftwareInstalled $Title)) {
						Write-Log -Message "The product $Title was successfully removed!"
						$true
					} else {
						Write-Log -Message "The product $Title was not removed.  Attempting secondary uninstall method" -LogLevel '2'
						## Parse out the EXE file path and arguments.  This regex could be improved on big time.
						$FilePathRegex = '(([a-zA-Z]\:|\\)\\([^\\]+\\)*[^\/:*?"<>|]+\.[a-zA-Z]{3})" (.+)'
						if ($UninstallString -match $FilePathRegex) {
							$InstallerFilePath = $matches[1]
							$InstallArgs = $matches[4]
							$InstallArgs = "$InstallArgs /s /f1`"$IssFilePath`" /f2`"$MyLogFilePath`" /SMS"
							Write-Log -Message "Running the install syntax `"$InstallerFilePath`" $InstallArgs"
							$Process = Start-Process "`"$InstallerFilePath`"" -ArgumentList $InstallArgs -Wait -NoNewWindow -PassThru
							if (!(Validate-IsSoftwareInstalled $Title)) {
								Write-Log -Message "The product '$Title' was not removed!"
								$false
							}
						} else {
							Write-Log -Message "Could not parse out the setup installer and arguments from uninstall string. The product '$Title' was not removed!"
							$false
						}
						
					}
				}
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}
#endregion

#region Logging
function Start-Log {
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
	[CmdletBinding()]
	param (
		[ValidateScript({ Split-Path $_ -Parent | Test-Path })]
		[string]$FilePath = "$(Get-SystemTempFilePath)\$((Get-Date -f 'MM-dd-yyyy (hhmm tt)') + 'Software.log')"
	)
	
	try {
		if (!(Test-Path $FilePath)) {
			## Create the log file
			New-Item $FilePath -Type File | Out-Null
		}
		
		## Set the global variable to be used as the FilePath for all subsequent Write-Log
		## calls in this session
		$global:ScriptLogFilePath = $FilePath
	} catch {
		Write-Error $_.Exception.Message
	}
}

function Write-Log {
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
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $true)]
		[string]$Message,
		[Parameter()]
		[ValidateSet(1, 2, 3)]
		[int]$LogLevel = 1
	)
	
	try {
		$TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
		## Build the line which will be recorded to the log file
		$Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
		$LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel
		$Line = $Line -f $LineFormat
		
		## Record the line to the log file if it's declared.  If not, just write to Verbose stream
		## This is helpful when using these functions interactively when you don't preface a function
		## with a Write-Log entry with Start-Log to create the $ScriptLogFilePath variable
		if (Test-Path variable:\ScriptLogFilePath) {
			Add-Content -Value $Line -Path $ScriptLogFilePath
		} else {
			Write-Verbose $Line
		}
	} catch {
		Write-Error $_.Exception.Message
	}
}
#endregion

#region Processes
function Check-Process {
	<#
	.SYNOPSIS
		This function is called after the execution of an external CMD process to log the status of how the process was exited.
	.PARAMETER Process
		A System.Diagnostics.Process object type that is output by using the -Passthru parameter on the Start-Process cmdlet
	#>
	[CmdletBinding()]
	param (
		[Parameter()]
		[System.Diagnostics.Process]$Process
	)
	process {
		try {
			if (@(0, 3010) -notcontains $Process.ExitCode) {
				Write-Log -Message "Process ID $($Process.Id) failed. Return value was $($Process.ExitCode)" -LogLevel '2'
				$false
			} else {
				Write-Log -Message "Process ID $($Process.Id) exited with successfull exit code '$($Process.ExitCode)'."
				$true
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Get-ChildProcess {
	<#
	.SYNOPSIS
		This function childs all child processes a parent process has spawned
	.PARAMETER ProcessId
		The potential parent process ID
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]$ProcessId
	)
	process {
		try {
			Get-WmiObject -Class Win32_Process -Filter "ParentProcessId = '$ProcessId'"
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Stop-MyProcess {
	<#
	.SYNOPSIS
		This function stops a process while provided robust logging of the activity
	.PARAMETER ProcessName
		One more process names
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string[]]$ProcessName
	)
	process {
		try {
			$ProcessesToStop = Get-Process -Name $ProcessName -ErrorAction 'SilentlyContinue'
			if (!$ProcessesToStop) {
				Write-Log -Message "-No processes to be killed found..."
			} else {
				foreach ($process in $ProcessesToStop) {
					Write-Log -Message "-Process $($process.Name) is running. Attempting to stop..."
					$WmiProcess = Get-WmiObject -Class Win32_Process -Filter "name='$($process.Name).exe'" -ea 'SilentlyContinue' -ev WMIError
					if ($WmiError) {
						Write-Log -Message "Unable to stop process $($process.Name). WMI query errored with `"$($WmiError.Exception.Message)`"" -LogLevel '2'
					} elseif ($WmiProcess) {
						$WmiResult = $WmiProcess.Terminate()
						if ($WmiResult.ReturnValue -ne 0) {
							Write-Log -Message "-Unable to stop process $($process.name). Return value was $($WmiResult.ReturnValue)" -LogLevel '2'
						} else {
							Write-Log -Message "-Successfully stopped process $($process.Name)..."
						}
					}
				}
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Wait-MyProcess {
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
	.PARAMETER SleepInterval
		The number of seconds the process should be checked to ensure it's still running
	.PARAMETER KillProcessDuringWait
		One or more chid process names that will be killed if found during the running of the parent process.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]$ProcessId,
		[int]$ProcessTimeout = 600,
		[int]$ReportInterval = 15,
		[int]$SleepInterval = 1,
		[string[]]$KillProcessDuringWait
	)
	process {
		try {
			$Process = Get-Process -Id $ProcessId -ea 'SilentlyContinue'
			if ($Process) {
				Write-Log -Message "Process '$($Process.Name)' ($($Process.Id)) found. Waiting to finish and capturing all child processes."
				$ChildProcessIds = @()
				## While waiting for the initial process to stop, collect all child IDs it spawns
				$ChildProcessesToLive = @()
				$Timer = [Diagnostics.Stopwatch]::StartNew()
				$i = 0
				while (!$Process.HasExited) {
					$ChildProcesses = Get-ChildProcess -ProcessId $ProcessId
					if ($ChildProcesses) {
						if ($KillProcessDuringWait) {
							$ToKill = $ChildProcesses | where { $KillProcessDuringWait -contains $_.Name }
							Write-Log -Message "Found $($ToKill | Get-Count) child processes spawned that should be killed. Stopping processes now."
							$ChildProcessesToLive += $ChildProcesses | where { $KillProcessDuringWait -contains $_.Name }
							Stop-MyProcess -ProcessName $ToKill
						} else {
							$ChildProcessesToLive += $ChildProcesses
						}
					}
					if ($Timer.Elapsed.TotalSeconds -ge $ProcessTimeout) {
						Write-Log -Message "The process '$($Process.Name)' ($($Process.Id)) has exceeded the timeout of $ProcessTimeout seconds.  Killing process."
						$Timer.Stop()
						Stop-MyProcess -ProcessName $Process.Name
					} elseif (($i % $ReportInterval) -eq 0) {
						Write-Log "Still waiting for process '$($Process.Name)' ($($Process.Id)) after $([Math]::Round($Timer.Elapsed.TotalSeconds,0)) seconds"
					}
					Start-Sleep -Seconds $SleepInterval
					$i++
				}
				Write-Log "Process '$($Process.Name)' ($($Process.Id)) has finished after $([Math]::Round($Timer.Elapsed.TotalSeconds,0)) seconds"
				if ($ChildProcessesToLive) {
					$ChildProcessesToLive = $ChildProcessesToLive | Select-Object -Unique
					Write-Log -Message "Parent process '$($Process.Name)' ($($Process.Id)) has finished but still has $($ChildProcessesToLive | Get-Count) child processes ($($ChildProcessesToLive.Name -join ',')) left.  Waiting on these to finish."
					foreach ($Process in $ChildProcessesToLive) {
						Wait-MyProcess -ProcessId $Process.ProcessId
					}
				} else {
					Write-Log -Message 'No child processes found spawned'	
				}
				Write-Log -Message "Finished waiting for process '$($Process.Name)' ($($Process.Id)) and all child processes"
				return $true
			} else {
				Write-Log -Message "Process ID '$ProcessId' not found.  No need to wait on it."
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}
#endregion

#region Shortcuts
function Get-Shortcut {
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
	[CmdletBinding()]
	param (
		[string]$MatchingTargetPath,
		[string]$MatchingName,
		[string]$MatchingFilePath,
		[string[]]$FolderPath,
		[switch]$NoRecurse
	)
	process {
		try {
			if (!$FolderPath) {
				$FolderPath = (Get-RootUserProfileFolderPath), (Get-AllUsersProfileFolderPath)
			}
			
			$Params = @{
				'Include' = @('*.url', '*.lnk');
				'ErrorAction' = 'SilentlyContinue';
				'ErrorVariable' = 'MyError';
				'Force' = $true
			}
			
			if (!$NoRecurse) {
				$Params['Recurse'] = $true
			}
			
			$ShellObject = New-Object -ComObject Wscript.Shell
			[System.Collections.ArrayList]$Shortcuts = @()
			
			foreach ($Path in $FolderPath) {
				try {
					Write-Log -Message "Searching for shortcuts in $Path..."
					[System.Collections.ArrayList]$WhereConditions = @()
					$Params['Path'] = $Path
					if ($MatchingTargetPath) {
						$WhereConditions.Add('(($ShellObject.CreateShortcut($_.FullName)).TargetPath -like "*$MatchingTargetPath*")') | Out-Null
					}
					if ($MatchingName) {
						$WhereConditions.Add('($_.Name -like "*$MatchingName*")') | Out-Null
					}
					if ($MatchingFilePath) {
						$WhereConditions.Add('($_.FullName -like "*$MatchingFilePath*")') | Out-Null
					}
					if ($WhereConditions.Count -gt 0) {
						$WhereBlock = [scriptblock]::Create($WhereConditions -join ' -and ')
						## TODO: Figure out a way to make this cleanly log access denied errors and continue
						Get-ChildItem @Params | where $WhereBlock
					} else {
						Get-ChildItem @Params
					}
					if ($NewShortcuts) {
						$Shortcuts.Add($NewShortcuts) | Out-Null
					}
				} catch {
					Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
					$false
				}
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function New-Shortcut {
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
	.PARAMETER TargetFilePath
		The file path of the application you'd like the shortcut to point to
	.PARAMETER Arguments
		File arguments you'd like to append to the target file path
	#>
	[CmdletBinding(DefaultParameterSetName = 'CommonLocation')]
	param (
		[Parameter(ParameterSetName = 'CustomLocation',
				   Mandatory = $true)]
		[ValidateScript({ Test-Path $_ -PathType 'Container' })]
		[string]$FolderPath,
		[Parameter(ParameterSetName = 'CommonLocation',
				   Mandatory = $true)]
		[ValidateSet('AllUsersDesktop')]
		[string]$CommonLocation,
		[Parameter(Mandatory = $true)]
		[string]$Name,
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path $_ -PathType 'Leaf' })]
		[string]$TargetFilePath,
		[Parameter()]
		[string]$Arguments
	)
	begin {
		try {
			$ShellObject = New-Object -ComObject Wscript.Shell
		} catch {
			Write-Log -Message $_.Exception.Message -LogLevel '3'
		}
	}
	process {
		try {
			if ($CommonLocation -eq 'AllUsersDesktop') {
				$FilePath = "$(Get-AllUsersDesktopFolderPath)\$Name.lnk"
			} elseif ($FolderPath) {
				$FilePath = "$FolderPath\$Name.lnk"
			}
			if (Test-Path $FilePath) {
				throw "$FilePath already exists. New shortcut cannot be made here."
			}
			$Object = $ShellObject.CreateShortcut($FilePath)
			$Object.TargetPath = $TargetFilePath
			$Object.Arguments = $Arguments
			$Object.WorkingDirectory = ($TargetFilePath | Split-Path -Parent)
			Write-Log -Message "Creating shortcut at $FilePath using targetpath $TargetFilePath"
			$Object.Save()
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}
#endregion

#region Services
function Remove-MyService {
	<#
	.SYNOPSIS
		This function stops and removes a Windows service
	.EXAMPLE
		Remove-MyService -Name bnpagent
	.PARAMETER ServiceName
	 	The service name you'd like to stop and remove
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Get-Service -Name $_ -ea 'SilentlyContinue' })]
		[string]$Name
	)
	process {
		try {
			$ServicesToRemove = Get-Service $Name -ea 'SilentlyContinue' -ev MyError
			if (!(Check-Error $MyError "Found $($ServicesToRemove.Count) services to remove")) {
				throw $MyError
			} elseif (!$ServicesToRemove) {
				Write-Log -Message "-No services to be removed found..."
			} else {
				foreach ($Service in $ServicesToRemove) {
					try {
						Write-Log -Message "-Found service $($Service.DisplayName)."
						if ($Service.Status -ne 'Stopped') {
							Write-Log -Message "-Service $($Service.Displayname) is not stopped."
							Stop-Service $Service -ErrorAction 'SilentlyContinue' -Force -ev ServiceError
							if (!(Check-Error $ServiceError "-Successfully stopped $($Service.Displayname)")) {
								throw $MyError	
							}
						} else {
							Write-Log -Message "-Service $($Service.Displayname) is already stopped."
						}
						Write-Log -Message "-Attempting to remove service $($Service.DisplayName)..."
						$WmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$($Service.ServiceName)'" -ea 'SilentlyContinue' -ev WMIError
						if ($WmiError) {
							Write-Log -Message "-Unable to remove service $($Service.DisplayName). WMI query errored with `"$($WmiError.Exception.Message)`"" -LogLevel '2'
						} else {
							$DeleteService = $WmiService.Delete()
							if ($DeleteService.ReturnValue -ne 0) {
								## Delete method error codes http://msdn.microsoft.com/en-us/library/aa389960(v=vs.85).aspx
								Write-Log -Message "-Service $($Service.DisplayName) failed to remove. Delete error code was $($DeleteService.ReturnValue).." -LogLevel '2'
							} else {
								Write-Log -Message "-Service $($Service.DisplayName) successfully removed..."
							}
						}
					} catch {
						Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
						$false
					}
				}
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}
#endregion

#region HelperFunctions
function Check-Error {
	<#
	.SYNOPSIS
		This function is used after the execution of any script snippet.  It is used as a standardized output
		method to log either an error or a success.
	.PARAMETER MyError
		The System.Exception object type error typically thrown in a try/catch block
	.PARAMETER SuccessString
		If no error is found, this will be logged.
	#>
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]$MyError,
		[Parameter()]
		[string]$SuccessString
	)
	process {
		try {
			if ($MyError) {
				Write-Log -Message $MyError.Exception.Message -LogLevel '2'
				$false
			} else {
				Write-Log -Message $SuccessString
				$true
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Convert-CompressedGuidToGuid {
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
	[OutputType([System.String])]
	param (
		[Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
		[ValidatePattern('^[0-9a-fA-F]{32}$')]
		[string]$CompressedGuid
	)
	process {
		try {
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
			foreach ($index in $Indexes.GetEnumerator()) {
				$part = $CompressedGuid.Substring($index.Key, $index.Value).ToCharArray()
				[array]::Reverse($part)
				$Guid += $part -join ''
			}
			$Guid = $Guid.Insert(9, '-').Insert(14, '-').Insert(19, '-').Insert(24, '-')
			$Guid + '}'
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Convert-GuidToCompressedGuid {
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
	[CmdletBinding()]
	[OutputType()]
	param (
		[Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
		[string]$Guid
	)
	begin {
		$Guid = $Guid.Replace('-', '').Replace('{', '').Replace('}', '')
	}
	process {
		try {
			$Groups = @(
			$Guid.Substring(0, 8).ToCharArray(),
			$Guid.Substring(8, 4).ToCharArray(),
			$Guid.Substring(12, 4).ToCharArray(),
			$Guid.Substring(16, 16).ToCharArray()
			)
			$Groups[0..2] | foreach {
				[array]::Reverse($_)
			}
			$CompressedGuid = ($Groups[0..2] | foreach { $_ -join '' }) -join ''
			
			$chararr = $Groups[3]
			for ($i = 0; $i -lt $chararr.count; $i++) {
				if (($i % 2) -eq 0) {
					$CompressedGuid += ($chararr[$i + 1] + $chararr[$i]) -join ''
				}
			}
			$CompressedGuid
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Convert-ToUncPath {
	<#
	.SYNOPSIS
		A simple function to convert a local file path and a computer name to a network UNC path.
	.PARAMETER LocalFilePath
		A file path ie. C:\Windows\somefile.txt
	.PARAMETER Computername
		The computer in which the file path exists on
	#>
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]$LocalFilePath,
		[Parameter()]
		[string]$Computername
	)
	process {
		try {
			$RemoteFilePathDrive = ($LocalFilePath | Split-Path -Qualifier).TrimEnd(':')
			"\\$Computername\$RemoteFilePathDrive`$$($LocalFilePath | Split-Path -NoQualifier)"
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Get-32BitProgramFilesPath {
	<#
	.SYNOPSIS
		On x64 machines the x86 program files path is Program Files (x86) while on x86 machines it's just Program Files.  This function
		does that decision for you and just outputs the x86 program files path regardless of OS architecture.
	#>
	[CmdletBinding()]
	param ()
	process {
		try {
			if ((Get-Architecture) -eq 'x64') {
				${ env:ProgramFiles(x86) }
			} else {
				$env:ProgramFiles
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Get-32BitRegistrySoftwarePath {
	<#
	.SYNOPSIS
		On x64 machines the x86 Software registry key path is HKLM:\SOFTWARE\Wow6432Node while on x86 machines it's just 
		HKLM:\Software. This function does that decision for you and just outputs the x86 path regardless of OS architecture.
	.PARAMETER Scope
		Specify either HKLM or HKCU.  Defaults to HKLM.
	#>
	[CmdletBinding()]
	param (
		[ValidateSet('HKLM', 'HKCU')]
		[string]$Scope = 'HKLM'
	)
	process {
		try {
			if ((Get-Architecture) -eq 'x64') {
				"$Scope`:\SOFTWARE\Wow6432Node"
			} else {
				"$Scope`:\SOFTWARE"
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Get-Architecture {
	<#
	.SYNOPSIS
		This simple function tells you whether the machine you're running on is either x64 or x86
	#>
	[CmdletBinding()]
	param ()
	process {
		try {
			if ([System.Environment]::Is64BitOperatingSystem -or ((Get-WmiObject -Class Win32_ComputerSystem | select -ExpandProperty SystemType) -eq 'x64-based PC')) {
				'x64'
			} else {
				'x86'
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Get-Count {
	<#
	.SYNOPSIS
		This function was created to account for collections where the output from a command
		is 1 and simply using .Count doesn't work well.
	#>
	param (
		[Parameter(ValueFromPipeline=$true)]
		$Value
	)
	if (!$Input) {
		0
	} else {
		$count = $Input.Count
		$count
	}
}

function Get-DriveFreeSpace {
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
	
	Begin {
		try {
			$WhereQuery = "SELECT FreeSpace,DeviceID FROM Win32_Logicaldisk"
			
			if ($PsBoundParameters.DriveLetter) {
				$WhereQuery += ' WHERE'
				$BuiltQueryParams = { @() }.Invoke()
				foreach ($Letter in $DriveLetter) {
					$BuiltQueryParams.Add("DeviceId = '$DriveLetter`:'")
				}
				$WhereQuery = "$WhereQuery $($BuiltQueryParams -join ' OR ')"
			}
			Write-Debug "Using WQL query $WhereQuery"
			$WmiParams = @{
				'Query' = $WhereQuery
				'ErrorVariable' = 'MyError';
				'ErrorAction' = 'SilentlyContinue'
			}
		} catch {
			Write-Log -Message $_.Exception.Message -LogLevel '3'
		}
	}
	Process {
		try {
			foreach ($Computer in $Computername) {
				try {
					$WmiParams.Computername = $Computer
					$WmiResult = Get-WmiObject @WmiParams
					if (!(Check-Error $MyError "Sucessfull WMI query")) {
						throw $MyError
					} elseif (!$WmiResult) {
						throw "Drive letter does not exist on target system"
					}
					foreach ($Result in $WmiResult) {
						if ($Result.Freespace) {
							[pscustomobject]@{
								'Computername' = $Computer;
								'DriveLetter' = $Result.DeviceID;
								'Freespace' = [int]($Result.FreeSpace / "1$SizeOutputLabel")
							}
						}
					}
				} catch {
					Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
					$false
				}
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Get-InstallerType {
	<#
	.SYNOPSIS
		Based on the uninstall string retrieved from the registry this function will tell you what kind of installer was
		used to install the product.  This information is helpful when figuring out the best way to remove software.
	
	.PARAMETER UninstallString
		The uninstall string that's stored in the HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\%GUID% UninstallString
		registry value.
	#>
	[CmdletBinding()]
	param (
		[string]$UninstallString
	)
	
	process {
		try {
			if ($UninstallString -imatch 'msiexec.exe') {
				'Windows Installer'
			} elseif ($UninstallString -imatch 'InstallShield Installation') {
				'InstallShield'
			} else {
				$false
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Get-InstallLocation {
	<#
	.SYNOPSIS
		This function finds the main install location for a piece of software
	.EXAMPLE
		PS> Get-InstalledSoftware -Name 'MySoftware' | Get-InstallLocation

		This example will find the install folder for the 'MySoftware' software installed on the local computer
	.PARAMETER ProductName
	 	The name of the software you'd like to query
	.PARAMETER Guid
		Optionally choose to search by GUID
	#>
	[CmdletBinding(DefaultParameterSetName = 'Guid')]
	param (
		[Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Name')]
		[string]$ProductName,
		[Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Guid')]
		[string]$Guid
	)
	process {
		try {
			if ($PSBoundParameters.ProductName) {
				Write-Log -Message "Checking WMI for install location for name '$ProductName'..."
				## Prefer to use the GUID to find the software rather than the name.  It won't happen very often but there's been
				## times when duplicate titles show up while the GUIDs are different
				$Params = @{ 'Name' = $ProductName }
			} elseif ($PSBoundParameters.Guid) {
				Write-Log -Message "Checking WMI for install location for GUID '$Guid'..."
				$Params = @{ 'Guid' = $Guid }
			}
			
			$SoftwareInstance = Get-InstalledSoftware @Params
			if ($SoftwareInstance.InstalledLocation) {
				$SoftwareInstance.InstalledLocation.TrimEnd('\')
			} else {
				Write-Log -Message 'Install location not found in WMI.  Checking registry...'
				Write-Log -Message "Checking for installer reg keys for '$ProductName'..."
				$UninstallRegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
				$InstallerRegKeys = Get-ChildItem $UninstallRegKey | where { $_.GetValue('DisplayName') -eq $ProductName }
				if (!$InstallerRegKeys) {
					Write-Log -Message "No matches for '$ProductName' in registry"
				} else {
					Write-Log -Message "Found '$($InstallerRegKeys.Count)' installer registry keys..."
					$Processes = @()
					Write-Log -Message "Checking for matches in uninstall strings.."
					foreach ($Key in $InstallerRegKeys) {
						$InstallFolderPath = $Key.GetValue('InstallLocation')
						if ($InstallFolderPath) {
							$InstallFolderPath.TrimEnd('\')
						} elseif (!$InstallFolderPath -and (($Key.GetValue('UninstallString') -match '\w:\\([a-zA-Z0-9 _.(){}-]+\\)+')) -and (($Key.GetValue('UninstallString') -notmatch 'Installshield Installation Information'))) {
							Write-Log -Message 'No install location found but did find a file path in the uninstall string...'
							$Matches.Values | select -Unique | where { Test-Path $_ } | foreach  { $_.TrimEnd('\') }
						} else {
							Write-Log -Message "Could not find the install folder path" -LogLevel '2'
						}
					}
				}
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Get-LoggedOnUserSID {
	<#
	.SYNOPSIS
		This function queries the registry to find the SID of the user that's currently logged onto the computer interactively.
	#>
	[CmdletBinding()]
	param ()
	process {
		try {
			New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
			(Get-ChildItem HKU: | where { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' }).PSChildName
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Get-OperatingSystem {
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
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]$Computername = 'localhost'
	)
	process {
		try {
			(Get-WmiObject -ComputerName $Computername -Query "SELECT Caption FROM Win32_OperatingSystem").Caption
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Get-SystemTempFilePath {
	<#
	.SYNOPSIS
		This function uses the TEMP system environment variable to easily discover the folder path
		to the system's temp folder
	#>
	[CmdletBinding()]
	param ()
	process {
		try {
			[environment]::GetEnvironmentVariable('TEMP', 'Machine')
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}
#endregion

#region Certificates
function Import-Certificate {
	<#
	.SYNOPSIS
		This function imports a certificate into any certificate store on a local computer
	.EXAMPLE
		PS> Import-Certificate -Location LocalMachine -StoreName My -FilePath C:\certificate.cer

		This example will import the certificate.cert certificate into the Personal store for the 
		local computer
	.EXAMPLE
		PS> Import-Certificate -Location CurrentUser -StoreName TrustedPublisher -FilePath C:\certificate.cer

		This example will import the certificate.cer certificate into the Trusted Publishers store for the 
		currently logged on user
	.PARAMETER Location
	 	This is the location (either CurrentUser or LocalMachine) where the store is located which the certificate
		will go into
	.PARAMETER StoreName
		This is the certificate store that the certificate will be placed into
	.PARAMETER FilePath
		This is the path to the certificate file that you'd like to import
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateSet('CurrentUser', 'LocalMachine')]
		[string]$Location,
		[Parameter(Mandatory = $true)]
		[ValidateScript({
			if ($Location -eq 'CurrentUser') {
				(Get-ChildItem Cert:\CurrentUser | select -ExpandProperty name) -contains $_
			} else {
				(Get-ChildItem Cert:\LocalMachine | select -ExpandProperty name) -contains $_
			}
		})]
		[string]$StoreName,
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path $_ -PathType Leaf })]
		[string]$FilePath
	)
	
	begin {
		$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
		Set-StrictMode -Version Latest
		try {
			[void][System.Reflection.Assembly]::LoadWithPartialName("System.Security")
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
			exit
		}
	}
	
	process {
		try {
			$Cert = Get-Item $FilePath
			$Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $Cert
			foreach ($Store in $StoreName) {
				$X509Store = New-Object System.Security.Cryptography.X509Certificates.X509Store $Store, $Location
				$X509Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
				$X509Store.Add($Cert)
				$X509Store.Close()
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}
#endregion

#region FileSystem
function Copy-FileWithHashCheck {
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
	process {
		try {
			$CopyParams = @{ 'Path' = $SourceFilePath; 'Destination' = $DestinationFolderPath }
			
			$DestinationFilePath = "$DestinationFolderPath\$($SourceFilePath | Split-Path -Leaf)"
			if (!$Force.IsPresent -and (Test-Path $DestinationFilePath)) {
				throw "The proposed destination file path '$DestinationFilePath' already exists."
			} else {
				$CopyParams.Force = $true
			}
			
			Copy-Item @CopyParams
			$SourceHash = Get-MyFileHash -Path $SourceFilePath
			$DestHash = Get-MyFileHash -Path "$DestinationFolderPath\$($SourceFilePath | Split-Path -Leaf)"
			if ($SourceHash.SHA256 -ne $DestHash.SHA256) {
				$false
			} else {
				$true
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Find-InTextFile {
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
	begin {
		$SystemTempFolderPath = Get-SystemTempFilePath
		if (!$UseRegex.IsPresent) {
			$Find = [regex]::Escape($Find)
		}
	}
	process {
		try {
			foreach ($File in $FilePath) {
				if ($Replace) {
					if ($NewFilePath) {
						if ((Test-Path -Path $NewFilePath -PathType 'Leaf') -and $Force.IsPresent) {
							Remove-Item -Path $NewFilePath -Force
							(Get-Content $File) -replace $Find, $Replace | Add-Content -Path $NewFilePath -Force
						} elseif ((Test-Path -Path $NewFilePath -PathType 'Leaf') -and !$Force.IsPresent) {
							Write-Warning "The file at '$NewFilePath' already exists and the -Force param was not used"
						} else {
							(Get-Content $File) -replace $Find, $Replace | Add-Content -Path $NewFilePath -Force
						}
					} else {
						(Get-Content $File) -replace $Find, $Replace | Add-Content -Path "$File.tmp" -Force
						Remove-Item -Path $File
						Rename-Item -Path "$File.tmp" -NewName $File
					}
				} else {
					Select-String -Path $File -Pattern $Find
				}
			}
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}

function Set-MyFileSystemAcl {
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
	[CmdletBinding()]
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
	
	process {
		try {
			$Acl = (Get-Item $Path).GetAccessControl('Access')
			$Ar = New-Object System.Security.AccessControl.FileSystemAccessRule($Identity, $Right, $InheritanceFlags, $PropagationFlags, $Type)
			$Acl.SetAccessRule($Ar)
			Set-Acl $Path $Acl
		} catch {
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			$false
		}
	}
}
#endregion