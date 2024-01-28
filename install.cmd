@echo off
cls
color 07
title Installation Script
mode 76, 30
set "nul1=1>nul"
set "nul2=2>nul"

::  Elevate script as admin

%nul1% fltmc || (
	powershell.exe "Start-Process cmd.exe -ArgumentList '/c \"%~f0\"' -Verb RunAs" && exit /b
	echo: &echo ==== ERROR ==== &echo:
	echo This script requires admin privileges.
	echo Press any key to exit...
	pause >nul
	exit
)

::  Disable QuickEdit for this cmd.exe session only

reg query HKCU\Console /v QuickEdit %nul2% | find /i "0x0" %nul1% || if not defined quedit (
	reg add HKCU\Console /v QuickEdit /t REG_DWORD /d "0" /f %nul1%
	start cmd.exe /c "%~f0"
	exit /b
)

powershell.exe "cd %~dp0; $f=[io.file]::ReadAllText('%~f0') -Split ':Install\:.*'; Invoke-Expression ($f[1]);" & goto End

:Install:
function Return-Error {
	Write-Host "Requirements are not met."
	exit 1
}

if (Test-Path "requirements.txt") {
	$requirements = Get-Content -Path "requirements.txt" -Raw
	Invoke-Expression $requirements
	$variables = @($program, $programShort, $url, $zip, $disk1, $setupFile, $ui,
		$certUtil, $certUtilUrl, $certUtilZip, $certUtilFolder, $certUtilFile, $psp, $pspROOT,
		$folder, $info, $serverConfig, $serverService, $key,
		$user, $dirs, $pattern, $file, $website, $clientConfig, $clientService, $dualFiles, $logFolder, $laneConfig,
		$workstationId, $laneWorkstationId, $lane1, $lane2, $palUrl, $palFolder, $palZip,
		$frontDevices, $backDevices, $frontDevice, $backDevice, $frontDeviceRegEx, $backDeviceRegEx)
	foreach ($variable in $variables) {
		if (!$variable) {
			Return-Error
		}
	}
} else {
	Return-Error
}

# Handle user interaction

$parentProcessID = (Get-WmiObject Win32_Process -Filter "ProcessId=$PID").ParentProcessId

function Handle-UserInput {
	while (([int]$choice - 48) -notin 0..$options.Length) {
		$choice = [Console]::ReadKey($true).KeyChar
	}
	if ($choice -eq "0") {
		Stop-Process -Id $parentProcessID
		Stop-Process -Id $PID
	}

	Clear-Host

	return $selection
}

function Show-Options {
	Clear-Host

	Write-Host
	Write-Host
	Write-Host
	Write-Host
	Write-Host
	Write-Host
	Write-Host
	Write-Host "       =============================================================="
	Write-Host
	Write-Host "               $message"
	Write-Host

	for ($i = 0; $i -lt $options.Length; $i++) {
		Write-Host "               [$($i + 1)] $($options[$i])"
	}

	for ($i = 0; $i -lt (7 - $options.Length); $i++) {
		Write-Host
	}

	Write-Host "               [0] Exit"
	Write-Host
	Write-Host "       =============================================================="
	Write-Host
	for ($i = 1; $i -le $options.Length; $i++) {
		$optionsCount += "$i,"
	}
	Write-Host -ForegroundColor Green "             Enter a menu option in the Keyboard [${optionsCount}0] :"
	Write-Host

	return Handle-UserInput
}

$message = "Installation Script"
$options = @("Server", "Dual lane", $frontDevice, $backDevice)
$setup = Show-Options

# Check if the program is already installed
if (Get-Package | Where-Object {$_.Name -eq $program}) {
	$message = "$programShort is already installed."
	$options = @("Continue")
	$choice = Show-Options
}

Write-Host -ForegroundColor Green "Installing..."

$ip = (Test-Connection -ComputerName (hostname) -Count 1).IPv4Address.IPAddressToString

# Get registered terminal
$dirs | ForEach-Object {
	if (Test-Path "$_\$file") {
		$regTerm = Get-Content "$_\$file" | Select-String -Pattern $pattern
		if ($regTerm) {
			$regTerm = $regTerm.Matches.Groups[1].Value
			$strip = ($regTerm | Select-String -Pattern "\|.*").Matches.Value
			$regTerm = $regTerm.Trim($strip).Trim("=").Trim()
			Write-Host "RegTerm: $regTerm"
			return
		}
	}
}
if (!($regTerm)) {
	if ((hostname).StartsWith("HN") -and ((hostname).Length -eq 15)) {
		$innCode = (hostname).Substring(2,5)
	} else {
		while ($true) {
			$innCode = (Read-Host -Prompt "INN code").Trim().ToUpper()
			if ($innCode -match "^[A-Z]{5}$") {
				break
			}
			Write-Host "Invalid code. Example: ABCDE"
		}
	}
	Start-Process msedge -ArgumentList $website
	$regTerm = (Read-Host -Prompt "RegTerm").Trim()
}
if ($setup -ne "1" -and ($regTerm.Length -gt 16)) {
	$last16 = $regTerm.Substring($regTerm.Length - 16)
} else {
	$last16 = $regTerm
}

switch ($setup) {
{$_ -in "2", "3", "4"} {
	control printers
	$ws = (Read-Host -Prompt "Workstation name").Trim()

	function Find-FrontDevice {
		while ($true) {
			foreach ($device in $frontDevices) {
				if (Get-PnpDevice -PresentOnly | Where-Object {$_.FriendlyName -match $device}) {
					return $true
				}
			}
			return $false
		}
	}

	function Find-BackDevice {
		while ($true) {
			foreach ($device in $backDevices) {
				if (!(Get-PnpDevice -PresentOnly | Where-Object {$_.FriendlyName -match $device})) {
					return $false
				}
			}
			return $true
		}
	}

	function Find-Again([string]$device) {
		$message = "$device was not found."
		$options = @("Try again", "Skip $device", "Assume $device is connected")
		$choice = Show-Options 

		if ($choice -eq "1") {
			continue deviceLookup
		} elseif ($choice -eq "2") {
			Write-Host "Skipping $device."
			Start-Sleep -Seconds 1
		} elseif ($choice -eq "3") {
			Write-Host "Assuming $device is connected."
			if ($device -eq $frontDevice) {
				$global:foundFrontDevice = $true
			} elseif ($device -eq $backDevice) {
				$global:foundBackDevice = $true
			}
			Start-Sleep -Seconds 1
		}
	}

	function Set-Device([string]$device) {
		if ($device -eq $frontDevice) {
			$global:foundFrontDevice = Find-FrontDevice
			if (!$foundFrontDevice) {
				Find-Again $device
			}
		} elseif ($device -eq $backDevice) {
			$global:foundBackDevice = Find-BackDevice
			if (!$foundBackDevice) {
				Find-Again $device
			}
		}
	}

	:devicelookup while ($true) {
		if ($setup -eq "2") {
			Set-Device $frontDevice
			Set-Device $backDevice
			break
		} elseif ($setup -eq "3") {
			Set-Device $frontDevice
			break
		} elseif ($setup -eq "4") {
			Set-Device $backDevice
			break
		}
	}

	if ($foundFrontDevice) {
		Write-Host "Found $frontDevice."
	}
	if ($foundBackDevice) {
		Write-Host "Found $backDevice."
	}
}
1 {
	Write-Host "Server."
	$ws = "Server"

	# Store ID
	while ($true) {
		$storeID = (Read-Host -Prompt "Store ID").Trim()
		if ($storeID.ToString().Length -eq 11) {
			break
		}
	}

	# DMP
	$secureDmp = Read-Host -AsSecureString -Prompt "DMP key"
	$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureDmp)
	$dmp = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
	[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

	# Password
	$securePassword = Read-Host -AsSecureString -Prompt "Password"
	$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
	$pw = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
	[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

	# Cert Utility
	Write-Host "Downloading $certUtil..."
	try {
		Start-BitsTransfer -Source $certUtilUrl -Destination $certUtilZip
	} catch {
		$ProgressPreference = "SilentlyContinue"
		Invoke-WebRequest -Uri $certUtilUrl -Outfile $certUtilZip
		$ProgressPreference = "Continue"
	}
	Expand-Archive -Force $certUtilZip "C:\"
	Remove-Item $certUtilZip

	$pspROOT | clip
	Write-Host "Get thumbprint and close $certUtil to continue..."
	Start-Process $certUtilFile -Wait
	Write-Host "$certUtil closed."

	# Thumbprint
	while ($true) {
		$thumbprint = (Read-Host -Prompt "Thumbprint").Trim()
		if ($thumbprint.Length -eq 40) {
			break
		} else {
			Write-Host "Invalid thumbprint. Try again."
		}
	}

	$pfxThumbprint = ((Get-ChildItem -Path "Cert:\LocalMachine\My\*") | Where-Object {$_.Thumbprint -eq $thumbprint}).Thumbprint
	$cerThumbprint = ((Get-ChildItem -Path "Cert:\LocalMachine\Root\*") | Where-Object {$_.Thumbprint -eq $thumbprint}).Thumbprint

	# Folder
	New-Item -Force -ItemType Directory -Path $folder

	# Information
	Out-File -Force -FilePath $info
	$lines = @("Thumbprint: $thumbprint", "Store ID: $storeID", "DMP key: $dmp", "Password: $pw", "Port: 8991")
	foreach ($line in $lines) {
		Add-Content -Path $info -Value $line
	}

	# Export certificates
	Export-PfxCertificate -Cert "Cert:\LocalMachine\My\$pfxThumbprint" -FilePath "$folder\$psp.pfx" -Password $SecurePassword -ChainOption EndEntityCertOnly -NoProperties
	Export-Certificate -Type CERT -Cert "Cert:\LocalMachine\Root\$cerThumbprint" -FilePath "$folder\$pspROOT.cer"
	Write-Host "Exported certificates."
	Write-Host "Saved information text file."
	explorer $folder
	notepad $info
}
{$_ -in "1", "2", "3", "4"} {
	# Download and extract setup
	if (Test-Path $zip) {
		$message = "$zip already exists."
		$options = @("Use existing zip file", "Replace zip file")
		$choice = Show-Options
		if ($choice -eq "2") {
			Remove-Item -Recurse -Force $zip
		}
	}

	if (Test-Path $disk1) {
		$message = "$disk1 already exists."
		$options = @("Use existing folder", "Replace folder")
		$choice = Show-Options
		if ($choice -eq "2") {
			Remove-Item -Recurse -Force $disk1
		}
	}

	if (!(Test-Path $zip) -and !(Test-Path $disk1)) {
		Write-Host "Downloading setup..."
		try {
			Start-BitsTransfer -Source $url -Destination $zip
		} catch {
			$ProgressPreference = "SilentlyContinue"
			Invoke-WebRequest -Uri $url -Outfile $zip
			$ProgressPreference = "Continue"
		}
	}

	if (!(Test-Path $disk1)) {
		Expand-Archive -Force $zip -DestinationPath "C:\"
		Remove-Item -Force $zip
	}
}
# Set lane configuration
2 {
	# Replace current files with dual lane config
	if (Test-Path "$dualFiles\*") {
		Move-Item -Force "$dualFiles\*" $disk1
		Remove-Item -Recurse -Force $dualFiles
	}
	Write-Host "Dual lane."
}
3 {
	Write-Host "$frontDevice."
}
4 {
	Write-Host "$backDevice."
}
{$_ -in "2", "3"} {
	# PAL packages
	if (!(Test-Path $palFolder)) {
		New-Item -ItemType Directory $palFolder
	}
	Write-Host "Downloading PAL packages..."
	try {
		Start-BitsTransfer -Source $palUrl -Destination $palZip
	} catch {
		$ProgressPreference = "SilentlyContinue"
		Invoke-WebRequest -Uri $palUrl -Outfile $palZip
		$ProgressPreference = "Continue"
	}
	Expand-Archive -Force $palZip -DestinationPath $palFolder
	Remove-Item -Force $palZip
	Write-Host "PAL packages deployed."
	break
}
{$_ -in "2", "3", "4"} {
	Write-Host "Import certificates and press any key to continue..."
	:certsLookup while ($true) {
		$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
		if ((Test-Path "$disk1\*.cer") -and (Test-Path "$disk1\*.out")) {
			Write-Host "Certificates found."
			break
		} else {
			$message = "The $programShort certificates were not found in $disk1"
			$options = @("Try again", "Skip certificates")
			$choice = Show-Options 
			if ($choice -eq "1") {
				continue certsLookup
			}
			elseif ($choice -eq "2") {
				Write-Output "Skipping certificates."
				break certsLookup
			}
		}
	}
}
1 {
	$dmp | clip
}
}

# Run setup
Write-Host "Running setup..."
Start-Process -Verb RunAs $setupFile -Wait

# Check if the program is installed
if (Get-Package | Where-Object {$_.Name -eq $program}) {
	Write-Host "Setup completed."
} else {
	Write-Host "$program was not installed."
	exit 1
}

# Get log path
$log = Get-ChildItem -Path $logFolder | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1 | Select-Object -ExpandProperty FullName

switch ($setup) {
1 {
	# Set thumbprint
	$text = Get-Content -Path $serverConfig
	foreach ($line in $text) {
		if ($line -match $key) {
			$currentValue = $matches[1]
		}
	}
	$modifiedKey = $matches[0] -Replace "value=`"$currentValue`"", "value=`"$thumbprint`""
	$text = $text -Replace $matches[0], $modifiedKey
	Set-Content -Path $serverConfig -Value $text
	Restart-Service $serverService
	Write-Host "Thumbprint successfully applied to the server configuration file."
	Get-Content $serverConfig | Select-String -Pattern $thumbprint
}
{$_ -in "2", "3", "4"} {
	# Apply regTerm
	$text = Get-Content -Path $clientConfig
	foreach ($line in $text) {
		if ($line -match $workstationId) {
			$currentValue = $matches[1]
		}
	}
	$modifiedWorkstationId = $matches[0] -Replace "value=`"$currentValue`"", "value=`"$last16`""
	$text = $text -Replace $matches[0], $modifiedWorkstationId
	Set-Content -Path $clientConfig -Value $text
	Restart-Service $clientService
	Get-Content $clientConfig | Select-String -Pattern $last16 | ForEach-Object { $_.Line.Trim() }

	Start-Process $ui

	# Get serial numbers
	if ($foundFrontDevice) {
		:serialLookup while ($true) {
			try {
				$frontDeviceSerialNumber = (Select-String -Path $log -Pattern $frontDeviceRegEx).Matches.Groups[1].Value
				break
			} catch {
				while ($true) {
					$message = "$frontDevice serial number was not found."
					$options = @("Restart $program Service", "Continue")
					$choice = Show-Options 
					if ($choice -eq "1") {
						Restart-Service $clientService
						continue serialLookup
					} elseif ($choice -eq "2") {
						break serialLookup
					}	
				}
			}
		}
	}
	if ($foundBackDevice) {
		:serialLookup while ($true) {
			try {
				$backDeviceSerialNumber = (Select-String -Path $log -Pattern $backDeviceRegEx).Matches.Groups[0].Value
				break
			} catch {
				while ($true) {
					$message = "$backDevice serial number was not found."
					$options = @("Restart $program Service", "Continue")
					$choice = Show-Options
					if ($choice -eq "1") {
						Restart-Service $clientService
						continue serialLookup
					} elseif ($choice -eq "2") {
						break serialLookup
					}	
				}
			}
		}
	}

	# Lane config
	if ($frontDeviceSerialNumber -and $backDeviceSerialNumber) {
		$text = Get-Content -Path $laneConfig

		# workstationId
		foreach ($line in $text) {
			if ($line -match $laneWorkstationId) {
				$currentValue = $matches[1]
			}
		}
		$modifiedLaneWorkstationId = $matches[0] -Replace "value=`"$currentValue`"", "value=`"$last16`""
		$text = $text -Replace $matches[0], $modifiedLaneWorkstationId

		# Lane 1
		foreach ($line in $text) {
			if ($line -match $lane1) {
				$currentValue = $matches[1]
			}
		}
		$modifiedLane1 = $matches[0] -Replace "value=`"$currentValue`"", "value=`"$frontDeviceSerialNumber`""
		$text = $text -Replace $matches[0], $modifiedLane1

		# Lane 2
		foreach ($line in $text) {
			if ($line -match $lane2) {
				$currentValue = $matches[1]
			}
		}
		$modifiedLane2 = $matches[0] -Replace "value=`"$currentValue`"", "value=`"$backDeviceSerialNumber`""
		$text = $text -Replace $matches[0], $modifiedLane2

		Set-Content -Path $laneConfig -Value $text
		Get-Content $laneConfig | Select-String -Pattern $frontDeviceSerialNumber, $backDeviceSerialNumber
		Restart-Service $clientService
	} else {
		Write-Host "LaneConfig does not have the devices' serial numbers."
		Start-Sleep -Seconds 2
	}
}
4 {
	try {
		$backDeviceSerialNumber = (Select-String -Path $log -Pattern $backDeviceRegEx).Matches.Groups[0].Value
	} catch {
		Write-Output "$backDevice serial number was not found."
		Start-Sleep -Seconds 1
	}
}
}

notepad $log
$message = "Installation completed."
$options = @("Restart $program Service", "Finish")
$count = 0
while ($true) {
	$choice = Show-Options
	if ($choice -eq "1") {
		switch ($setup) {
		1 {
			Restart-Service $serverService
		}
		{$_ -in "2", "3", "4"} {
			Restart-Service $clientService
		}
		}
		$count++
	} elseif ($choice -eq "2") {
		# Print system properties
		$properties = "$ws completed.`nIP: $ip`nHostname: $(hostname)`nRegTerm: $regTerm"
		if ($frontDeviceSerialNumber) {
			$properties += "`n{$frontDevice}: $frontDeviceSerialNumber"
		}
		if ($backDeviceSerialNumber) {
			$properties += "`n${backDevice}: $backDeviceSerialNumber"
		}
		if ($frontDeviceSerialNumber) {
			$properties += "`nPAL packages deployed."
		}
		Write-Host $properties
		$properties | clip

		Write-Host
		Write-Host "Installation details are copied to the clipboard."
		Write-Host "Check the $programShort log."
		Start-Sleep -Seconds 1
		if ($count -gt 0) {
			notepad $log
		}
		break
	}
}
:Install:

:End
echo:
echo Press any key to exit...
pause >nul
del "%~dp0\requirements.txt"
del "%~f0"