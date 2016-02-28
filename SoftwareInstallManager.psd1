<#	
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2014 v4.1.60
	 Created on:   	6/23/2014 4:18 PM
	 Created by:   	Adam Bertram
	 Organization: 	Adam the Automator, LLC
	 Filename:     	SoftwareInstallManager.psd1
	 -------------------------------------------------------------------------
	 Module Manifest
	-------------------------------------------------------------------------
	 Module Name: SoftwareInstallManager
	===========================================================================
#>

@{	
ModuleToProcess = 'SoftwareInstallManager.psm1'	

# Version number of this module.
ModuleVersion = '1.0.0.0'

# ID used to uniquely identify this module
GUID = 'b7b17534-a60e-424a-8d13-949988b977bd'

# Author of this module
Author = 'Adam Bertram'

# Company or vendor of this module
CompanyName = 'Adam the Automator, LLC'

# Copyright statement for this module
Copyright = '(c) 2015. All rights reserved.'

# Description of the functionality provided by this module
	Description = 'This module assists software deployment administrators in deploying disparate software. It is designed to
provide a standard interface to treat software installers of all types exactly the same.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Name of the Windows PowerShell host required by this module
PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
PowerShellHostVersion = ''

# Minimum version of the .NET Framework required by this module
DotNetFrameworkVersion = '2.0'

# Minimum version of the common language runtime (CLR) required by this module
CLRVersion = '2.0.50727'

# Processor architecture (None, X86, Amd64, IA64) required by this module
ProcessorArchitecture = 'None'

# Modules that must be imported into the global environment prior to importing
# this module
RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to
# importing this module
ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
FormatsToProcess = @()

# Modules to import as nested modules of the module specified in
# ModuleToProcess
	NestedModules = @(
	'Certificates.psm1',
	'FileSystem.psm1',
	'Helpers.psm1',
	'InstallShield.psm1',
	'Processes.psm1',
	'Registry.psm1',
	'Services.psm1',
	'Shortcuts.psm1',
	'UserProfiles.psm1',
	'WindowsInstaller.psm1',
	'WindowsServices.psm1'
	)

# Functions to export from this module
FunctionsToExport = '*'

# Cmdlets to export from this module
CmdletsToExport = '*'

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module
AliasesToExport = '*'

# List of all modules packaged with this module
ModuleList = @()

# List of all files packaged with this module
FileList = @()

# Private data to pass to the module specified in ModuleToProcess
PrivateData = ''

}







