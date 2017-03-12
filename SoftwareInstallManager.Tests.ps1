#region import modules
$ThisModule = "$($MyInvocation.MyCommand -replace '\.Tests\.ps1$')"
$RequiredModules = $ThisModule
Import-Module -Name $RequiredModules -Force -ErrorAction Stop
#endregion

InModuleScope SoftwareInstallManager {
	describe 'Get-InstalledSoftware' {
		
		mock 'Write-Log' {
			return [pscustomobject]@{  }
		} -ModuleName 'SoftwareInstallManager'
		
		it 'outputs the right type of object' {
			Get-InstalledSoftware | should beofType 'System.Management.Automation.PSCustomObject'
		}
		
		it 'outputs the right number of objects' {
				
		}
	}
}