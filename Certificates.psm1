Set-StrictMode -Version Latest

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
	[OutputType()]
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
		$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
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