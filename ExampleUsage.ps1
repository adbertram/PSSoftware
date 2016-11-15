param (
    [Parameter(Mandatory)]
    [string[]]$Client,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$InstallerFilePath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ModuleFolderPath = 'C:\Program Files\WindowsPowerShell\Modules\SoftwareInstallManager'
)

foreach ($c in $Client) {
    try {
        ## Perform numerous connection checks before copying everything over
        $failReason = "The client [$($c)] "
        if (-not (Test-Connection -ComputerName $c -Quiet -Count 1)) {
            throw "$failReason cannot be pinged"
        } elseif (-not (Test-Path "\\$c\c$")) {
            throw "$failReason 's admin share is unavailable"
        }

        ## Copy the installer to the client
        Copy-Item -Path $InstallerFilePath -Destination "\\$c\c$"

        ## Copy the SoftwareInstallManager module to the client
        Copy-Item -Path $ModuleFolderPath -Destination "\\$c\c$" -Recurse

        ## Execute the software installer
        Invoke-Command -ComputerName $c -ScriptBlock { 
            Import-Module C:\SoftwareInstallManager\SoftwareInstallManager.psm1
            $installerFileName = $using:InstallerFilePath | Split-Path -Leaf
            Install-Software -OtherInstallerFilePath "C:\$installerFileName" -OtherInstallerArgs '/silent /norestart'
         }
    } catch {
        Write-Error -Message $_.Exception.Message
    }
}