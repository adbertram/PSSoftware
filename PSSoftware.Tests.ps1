#region import modules
$ThisModule = "$($MyInvocation.MyCommand.Path -replace '\.Tests\.ps1$', '').psd1"
$ThisModuleName = (($ThisModule | Split-Path -Leaf) -replace '\.psd1')
Get-Module -Name $ThisModuleName -All | Remove-Module -Force

Import-Module -Name $ThisModule -Force -ErrorAction Stop
#endregion

describe 'Module-level tests' {
	
	it 'should validate the module manifest' {
	
		{ Test-ModuleManifest -Path $ThisModule -ErrorAction Stop } | should not throw
	}

	it 'should pass all error-level script analyzer rules' {
		Invoke-ScriptAnalyzer -Path $PSScriptRoot -Severity Error | should benullorempty
	}

}

InModuleScope PSSoftware {
	
}

describe 'New-TempFile' {
	$file = New-TempFile
	it 'should return FileInfo type' {
		$file | should beoftype [System.IO.FileInfo]
	}
	it 'file should exist' {
		Test-Path $file | should betrue
	}
	Remove-Item $file
}