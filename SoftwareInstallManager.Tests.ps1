#region import modules
$ThisModule = "$($MyInvocation.MyCommand -replace '\.Tests\.ps1$')"
Import-Module -Name "$ThisModule.psd1" -Force -ErrorAction Stop
#endregion

InModuleScope SoftwareInstallManager {
	describe 'Get-InstalledSoftware' {
		
		mock 'Write-Log' {
			return [pscustomobject]@{  }
		}
		
		it 'outputs the right type of object' {
			Get-InstalledSoftware | should beofType 'System.Management.Automation.PSCustomObject'
		}
		
		it 'outputs the right number of objects' {
				
		}
	}
}