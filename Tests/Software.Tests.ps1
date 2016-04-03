#region import modules
$ThisModule = "$($MyInvocation.MyCommand -replace '\.Tests\.ps1$')"
$RequiredModules = $ThisModule
Import-Module -Name $RequiredModules -Force
#endregion

