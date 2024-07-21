<#
.SYNOPSIS
The Zeroed.Tech IIS Machine Key Auditer

.DESCRIPTION
Identifies all generated IIS machine keys and logs their generation dates and paths.
By running this script, you are acknowledging that you've taken a backup of this host.
Zeroed.Tech takes no responsibility if things go wrong.

.EXAMPLE
.\IIS-Machine-Key-Audit.ps1
.\IIS-Machine-Key-Audit.ps1 | Format-Table
.\IIS-Machine-Key-Audit.ps1 | Select ApplicationPool, UserName, MachineKeyFound,Created,Path | Format-Table
#>

$ErrorActionPreference = 'Continue'
Import-Module IISAdministration

<#
    Improved error logging from https://stackoverflow.com/questions/38064704/how-can-i-display-a-naked-error-message-in-powershell-without-an-accompanying
#>
function Write-Error($message) {
    [Console]::ForegroundColor = 'red'
    [Console]::Error.WriteLine($message)
    [Console]::ResetColor()
}

function ResolveSidFromUsername($username) {
    return (New-Object System.Security.Principal.NTAccount($username)).Translate([System.Security.Principal.SecurityIdentifier]).Value
}

function GetUsernameForApplicationPool($applicationPool) {
    switch ($applicationPool.ProcessModel.IdentityType) {
        "ApplicationPoolIdentity" {
            return $applicationPool.Name
        }
        "SpecificUser" {
            return $applicationPool.ProcessModel.UserName
        }
        "LocalSystem" {
            return "system"
        }
        Default {
            return $applicationPool.ProcessModel.IdentityType
        }
    }
}

function GetSidForApplicationPool($applicationPool) {
    switch ($applicationPool.ProcessModel.IdentityType) {
        "ApplicationPoolIdentity" {
            return $applicationPool.Attributes["applicationPoolSid"].Value
        }
        Default {
            return ResolveSidFromUsername(GetUsernameForApplicationPool($applicationPool))
        }
    }
}

function GetIISMachineKeyLocationForApplicationPool($applicationPool) {
    switch ($applicationPool.ProcessModel.IdentityType) {
        "LocalSystem" {
            try {
                $keyLocation = "HKLM:\SECURITY\Policy\Secrets\L`$ASP.NETAutoGenKeysV44.0.30319.0"
                # Confirm key is present, Throws an exception if not/we can't access it
                Get-ChildItem -Path $keyLocation -ErrorAction Stop | Out-Null

                $keyTime = [datetime]::FromFileTimeUtc([System.BitConverter]::ToInt64([byte[]](Get-ItemPropertyValue -Path "$keyLocation\CupdTime" -Name "(Default)"), 0))
                    
                return [pscustomobject]@{
                    Path = $keyLocation
                    Date = $keyTime
                }
            }
            catch [System.Security.SecurityException] {
                Write-Error "Permission denied whilst accessing $keyLocation. Please rerun as an SYSTEM"
            }
            catch [System.Management.Automation.ItemNotFoundException] {
                # Not found
                return $null;
            }
        }
        Default {
            New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
            # Check for the presence of a key under the application pools user profile
            # Check if the user profile is mounted and if not, mount it
            $profileMounted = $false;
            $sid = GetSidForApplicationPool($applicationPool)
            $keyLocation = "HKU:\$sid\Software\Microsoft\ASP.NET\4.0.30319.0"
            $keyTime = $null
            
            if (!(Test-Path -Path "HKU:\$sid")) {
                # Registry is not mounted, check if it exists
                if (MountRegistryForSid($sid)) {
                    $profileMounted = $true
                }
            }
            # The profile should now be mounted
            # Check for the presence of a machine key under this profile
            $keyTime = GetMachineKeyTimeFromKey($keyLocation)
            
            Remove-PSDrive -Name HKU -PSProvider Registry
            if ($profileMounted) {
                # We mounted a users profile so lets unmount it
                UnmountRegistryForSid($sid);
            }

            # If we found a key, return it
            if ($null -ne $keyTime) {
                return [pscustomobject]@{
                    Path = $keyLocation
                    Date = $keyTime
                }
            }
            
            # A user profile could not be found or a machine key could not be found within it, check under the local machine key
            $keyLocation = "HKLM:\SOFTWARE\Microsoft\ASP.NET\4.0.30319.0\AutoGenKeys\$sid"
            $keyTime = GetMachineKeyTimeFromKey($keyLocation)
            if ($null -ne $keyTime) {
                return [pscustomobject]@{
                    Path = $keyLocation
                    Date = $keyTime
                }
            }

            return $null
        }
    }
}

function GetMachineKeyTimeFromKey($key) {
    if (Test-Path -Path $key) {
        try {
            # Test for the presence of a machine key, we don't need the actual value
            Get-ItemProperty -Path $keyLocation | Select-Object -ExpandProperty "AutoGenKeyV4" -ErrorAction Stop | Out-Null
            # Now that we know theres a machine key present, pull out its timestamp
            $keyTime = Get-ItemPropertyValue -Path $keyLocation -Name "AutoGenKeyCreationTime"
            return [datetime]::FromFileTimeUtc($keyTime)
            
        }
        catch {
        }
    }
    return $null
}

function MountRegistryForSid($sid) {
    try {
        # Locate the path to the users profile
        $profilePath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -Name ProfileImagePath -ErrorAction Stop
        $profileRegPath = "$profilePath\NTUSER.dat"

        # Mount the users profile
        reg load HKU\$sid $profileRegPath | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Error "A user profile for $sid was found at $profilRegPath but an error was encountered whilst mounting it. Error $LASTEXITCODE"
            return $false
        }
        # The registry hive should be mounted now, verify we can access it
        if (Test-Path -Path "HKU:\$sid") {
            return $true
        }
        Write-Error "A user profile for $sid was successfully mounted but could not be accessed. Please reboot your host to ensure it's in a clean state"
        return $false
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        # A user profile was not found for this sid
        return $false
    }
}

function UnmountRegistryForSid($sid) {
    # Ensure nothing is holding a reference to the hive we're unloading
    [gc]::collect()
    # Mount the users profile
    reg unload HKU\$sid $profileRegPath | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to unmount user profile for $sid. Please reboot your host to ensure it's in a clean state. Error $LASTEXITCODE"
    }
}

Get-IISAppPool | ForEach-Object {
    $appPool = $_
    $iisMachineKey = GetIISMachineKeyLocationForApplicationPool($appPool)

    [pscustomobject]@{
        ApplicationPool = $appPool.Name
        UserName        = GetUsernameForApplicationPool($appPool)
        SID             = GetSidForApplicationPool($appPool)
        MachineKeyFound = $($iisMachineKey -ne $null)
        Created         = $iisMachineKey.Date
        Path            = $iisMachineKey.Path
    }
}