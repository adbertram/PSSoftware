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
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Get-Service -Name $_ -ea 'SilentlyContinue' })]
		[string]$Name
	)
	process
	{
		try
		{
			Write-Log -Message "$($MyInvocation.MyCommand) - BEGIN"
			$ServicesToRemove = Get-Service $Name -ea 'SilentlyContinue' -ev MyError
			if (!(Test-Error $MyError "Found $($ServicesToRemove.Count) services to remove"))
			{
				throw $MyError
			}
			elseif (!$ServicesToRemove)
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
							Stop-Service $Service -ErrorAction 'SilentlyContinue' -Force -ev ServiceError
							if (!(Test-Error $ServiceError "-Successfully stopped $($Service.Displayname)"))
							{
								throw $MyError
							}
						}
						else
						{
							Write-Log -Message "-Service $($Service.Displayname) is already stopped."
						}
						Write-Log -Message "-Attempting to remove service $($Service.DisplayName)..."
						$WmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$($Service.ServiceName)'" -ea 'SilentlyContinue' -ev WMIError
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
			Write-Log -Message "$($MyInvocation.MyCommand) - END"
		}
		catch
		{
			Write-Log -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -LogLevel '3'
			Write-Log -Message "$($MyInvocation.MyCommand) - END"
			$false
		}
	}
}