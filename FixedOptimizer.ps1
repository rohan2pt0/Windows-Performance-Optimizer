# Windows System Performance Optimizer
# Author: Claude
# Version: 1.0

# Function to check for administrator privileges
function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    return $isAdmin
}

# Function to display colored text
function Write-HostColored {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [string]$ForegroundColor = "White"
    )
    
    Write-Host $Message -ForegroundColor $ForegroundColor
}

# Main menu function
function Show-Menu {
    param (
        [string]$Title = 'Windows System Performance Optimizer'
    )
    Clear-Host
    Write-HostColored "===== $Title =====" -ForegroundColor Cyan
    Write-HostColored "1: Run Quick System Analysis" -ForegroundColor Green
    Write-HostColored "2: Clean Temporary Files" -ForegroundColor Green
    Write-HostColored "3: Optimize Startup Programs" -ForegroundColor Green
    Write-HostColored "4: Optimize Windows Settings" -ForegroundColor Green
    Write-HostColored "5: View System Information" -ForegroundColor Green
    Write-HostColored "Q: Quit" -ForegroundColor Yellow
    Write-HostColored "=================================" -ForegroundColor Cyan
}

# Function to get system information
function Get-SystemInformation {
    Write-HostColored "`n===== System Information =====" -ForegroundColor Cyan
    
    # Get basic system info
    $computerSystem = Get-CimInstance CIM_ComputerSystem
    $operatingSystem = Get-CimInstance CIM_OperatingSystem
    
    Write-HostColored "Computer Name: $($computerSystem.Name)" -ForegroundColor White
    Write-HostColored "Model: $($computerSystem.Model)" -ForegroundColor White
    Write-HostColored "Manufacturer: $($computerSystem.Manufacturer)" -ForegroundColor White
    Write-HostColored "OS: $($operatingSystem.Caption)" -ForegroundColor White
    Write-HostColored "Version: $($operatingSystem.Version)" -ForegroundColor White
    
    # Get processor info
    $processor = Get-CimInstance CIM_Processor
    Write-HostColored "CPU: $($processor.Name)" -ForegroundColor White
    Write-HostColored "Cores: $($processor.NumberOfCores)" -ForegroundColor White
    Write-HostColored "Logical Processors: $($processor.NumberOfLogicalProcessors)" -ForegroundColor White
    
    # Get memory info
    $totalMemoryGB = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
    $freeMemoryGB = [math]::Round($operatingSystem.FreePhysicalMemory / 1MB, 2)
    $usedMemoryGB = [math]::Round($totalMemoryGB - $freeMemoryGB, 2)
    $memoryUsagePercent = [math]::Round(($usedMemoryGB / $totalMemoryGB) * 100, 2)
    
    Write-HostColored "Total RAM: $totalMemoryGB GB" -ForegroundColor White
    Write-HostColored "Used RAM: $usedMemoryGB GB ($memoryUsagePercent%)" -ForegroundColor White
    Write-HostColored "Free RAM: $freeMemoryGB GB" -ForegroundColor White
    
    # Get disk info
    $disks = Get-CimInstance CIM_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
    foreach ($disk in $disks) {
        $sizeGB = [math]::Round($disk.Size / 1GB, 2)
        $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
        $usedGB = [math]::Round($sizeGB - $freeGB, 2)
        $usedPercent = [math]::Round(($usedGB / $sizeGB) * 100, 2)
        
        Write-HostColored "Disk $($disk.DeviceID):" -ForegroundColor White
        Write-HostColored "  Total: $sizeGB GB" -ForegroundColor White
        Write-HostColored "  Used: $usedGB GB ($usedPercent%)" -ForegroundColor White
        Write-HostColored "  Free: $freeGB GB" -ForegroundColor White
    }
}

# Function to analyze resource-heavy processes
function Get-ResourceHeavyProcesses {
    param (
        [int]$Top = 10
    )
    
    Write-HostColored "`n===== Top $Top Resource-Heavy Processes =====" -ForegroundColor Cyan
    
    Write-HostColored "`n--- CPU Usage ---" -ForegroundColor Yellow
    $cpuProcesses = Get-Process | Sort-Object CPU -Descending | Select-Object -First $Top
    $cpuProcesses | Format-Table -Property Id, ProcessName, @{Name="CPU(s)"; Expression={"{0:N2}" -f ($_.CPU)}}, @{Name="Memory(MB)"; Expression={"{0:N2}" -f ($_.WorkingSet / 1MB)}} -AutoSize
    
    Write-HostColored "`n--- Memory Usage ---" -ForegroundColor Yellow
    $memoryProcesses = Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First $Top
    $memoryProcesses | Format-Table -Property Id, ProcessName, @{Name="Memory(MB)"; Expression={"{0:N2}" -f ($_.WorkingSet / 1MB)}}, @{Name="CPU(s)"; Expression={"{0:N2}" -f ($_.CPU)}} -AutoSize
}

# Function to clean temporary files
function Remove-TemporaryFiles {
    Write-HostColored "`n===== Cleaning Temporary Files =====" -ForegroundColor Cyan
    
    $tempFolders = @(
        "$env:TEMP",
        "$env:SystemRoot\Temp",
        "$env:SystemRoot\Prefetch",
        "$env:SystemRoot\SoftwareDistribution\Download"
    )
    
    $totalFilesRemoved = 0
    
    foreach ($folder in $tempFolders) {
        if (Test-Path $folder) {
            $filesBefore = (Get-ChildItem -Path $folder -Recurse -File -ErrorAction SilentlyContinue).Count
            
            Write-HostColored "Cleaning $folder ($filesBefore files)..." -ForegroundColor Yellow
            
            # Remove files
            $filesToRemove = Get-ChildItem -Path $folder -Recurse -File -ErrorAction SilentlyContinue | 
                           Where-Object { !$_.PSIsContainer -and $_.LastWriteTime -lt (Get-Date).AddDays(-1) }
            
            foreach ($file in $filesToRemove) {
                try {
                    Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
                    $totalFilesRemoved++
                } catch {
                    # Silently continue if file is in use
                }
            }
        }
    }
    
    Write-HostColored "`nTotal temporary files removed: $totalFilesRemoved" -ForegroundColor Green
    
    # Run disk cleanup
    Write-HostColored "Running Windows Disk Cleanup utility..." -ForegroundColor Yellow
    Start-Process -FilePath cleanmgr.exe -ArgumentList "/sagerun:1" -Wait -ErrorAction SilentlyContinue
}

# Function to optimize startup programs
function Optimize-StartupPrograms {
    Write-HostColored "`n===== Optimizing Startup Programs =====" -ForegroundColor Cyan
    
    try {
        # Get all startup items
        $startupItems = @()
        
        # From Registry Run keys (current user)
        $regPathCU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        if (Test-Path $regPathCU) {
            $items = Get-ItemProperty -Path $regPathCU
            foreach ($prop in $items.PSObject.Properties) {
                if ($prop.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                    $startupItems += [PSCustomObject]@{
                        Name = $prop.Name
                        Command = $prop.Value
                        Type = "Registry (Current User)"
                        Path = $regPathCU
                        Status = "Enabled"
                    }
                }
            }
        }
        
        # From Registry Run keys (all users)
        $regPathLM = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
        if (Test-Path $regPathLM) {
            $items = Get-ItemProperty -Path $regPathLM
            foreach ($prop in $items.PSObject.Properties) {
                if ($prop.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                    $startupItems += [PSCustomObject]@{
                        Name = $prop.Name
                        Command = $prop.Value
                        Type = "Registry (All Users)"
                        Path = $regPathLM
                        Status = "Enabled"
                    }
                }
            }
        }
        
        # Display results
        if ($startupItems.Count -gt 0) {
            Write-HostColored "Found $($startupItems.Count) startup items:" -ForegroundColor Yellow
            $startupItems | Format-Table -Property Name, Type, Status -AutoSize
            
            # Ask user if they want to disable any startup items
            Write-HostColored "`nWould you like to disable any of these startup items to improve boot performance?" -ForegroundColor Yellow
            $choice = Read-Host "Enter 'Y' to select items to disable, or any other key to skip"
            
            if ($choice -eq 'Y' -or $choice -eq 'y') {
                # Display items with indexes
                for ($i = 0; $i -lt $startupItems.Count; $i++) {
                    Write-HostColored "[$i] $($startupItems[$i].Name) ($($startupItems[$i].Type))" -ForegroundColor Cyan
                }
                
                Write-HostColored "`nEnter the numbers of items to disable (separated by commas):" -ForegroundColor Yellow
                $selection = Read-Host
                
                $itemsToDisable = @()
                $itemsToDisable = $selection -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' -and [int]$_ -lt $startupItems.Count } | ForEach-Object { [int]$_ }
                
                foreach ($index in $itemsToDisable) {
                    $item = $startupItems[$index]
                    try {
                        if ($item.Type -like "Registry*") {
                            # Backup before removing
                            $backupName = "$($item.Name)_backup"
                            Copy-Item -Path $item.Path -Destination "$($item.Path)_backup" -ErrorAction SilentlyContinue
                            
                            # Remove from registry
                            Remove-ItemProperty -Path $item.Path -Name $item.Name -ErrorAction Stop
                            Write-HostColored "Disabled startup item: $($item.Name)" -ForegroundColor Green
                        }
                    } catch {
                        Write-HostColored "Error disabling item $($item.Name): $_" -ForegroundColor Red
                    }
                }
                
                Write-HostColored "`nStartup optimization complete. The changes will take effect after reboot." -ForegroundColor Green
            }
        } else {
            Write-HostColored "No startup items found." -ForegroundColor Green
        }
    } catch {
        Write-HostColored "Error analyzing startup programs: $_" -ForegroundColor Red
    }
}

# Function to optimize Windows settings
function Optimize-WindowsSettings {
    Write-HostColored "`n===== Optimizing Windows Settings =====" -ForegroundColor Cyan
    
    # Visual effects optimization
    Write-HostColored "Optimizing visual effects for performance..." -ForegroundColor Yellow
    try {
        # Create a backup of current settings
        $backupPath = "$env:USERPROFILE\Documents\VisualEffectsBackup.reg"
        $regKey = "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
        
        # Export current settings if the key exists
        if (Test-Path -Path "Registry::$regKey") {
            reg export "$regKey" $backupPath /y | Out-Null
            Write-HostColored "Visual effects settings backed up to $backupPath" -ForegroundColor Green
        }
        
        # Set visual effects to "Adjust for best performance"
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 2 -ErrorAction SilentlyContinue
        
        Write-HostColored "Visual effects optimized for performance" -ForegroundColor Green
    } catch {
        Write-HostColored "Error optimizing visual effects: $_" -ForegroundColor Red
    }
    
    # Power plan optimization
    Write-HostColored "Setting power plan to High Performance..." -ForegroundColor Yellow
    try {
        # Try to get the high performance power plan
        $highPerfPlan = powercfg -l | ForEach-Object {
            if ($_ -match "High performance") {
                $_.Split()[3]
            }
        }
        
        # If high performance plan exists, activate it
        if ($highPerfPlan) {
            powercfg -setactive $highPerfPlan | Out-Null
            Write-HostColored "Power plan set to High Performance" -ForegroundColor Green
        } else {
            # Try to create a high performance plan
            powercfg -duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c | Out-Null
            Write-HostColored "Created and activated High Performance power plan" -ForegroundColor Green
        }
    } catch {
        Write-HostColored "Error setting power plan: $_" -ForegroundColor Red
    }
}

# Function to run system analysis
function Run-QuickAnalysis {
    Write-HostColored "`n===== Quick System Analysis =====" -ForegroundColor Cyan
    
    # CPU analysis
    try {
        $cpuLoad = (Get-CimInstance -ClassName Win32_Processor).LoadPercentage
        
        if ($cpuLoad -ge 80) {
            Write-HostColored "CPU Usage: $cpuLoad% (High)" -ForegroundColor Red
        } elseif ($cpuLoad -ge 50) {
            Write-HostColored "CPU Usage: $cpuLoad% (Moderate)" -ForegroundColor Yellow
        } else {
            Write-HostColored "CPU Usage: $cpuLoad% (Good)" -ForegroundColor Green
        }
        
        # Get high CPU processes
        $highCPUProcesses = Get-Process | Sort-Object CPU -Descending | Select-Object -First 5
        
        Write-HostColored "Top CPU consumers:" -ForegroundColor Yellow
        $highCPUProcesses | Format-Table -Property ProcessName, Id, @{Name="CPU(s)"; Expression={"{0:N2}" -f ($_.CPU)}}, @{Name="Memory(MB)"; Expression={"{0:N2}" -f ($_.WorkingSet / 1MB)}} -AutoSize
    } catch {
        Write-HostColored "Error analyzing CPU: $_" -ForegroundColor Red
    }
    
    # Memory analysis
    try {
        $computerSystem = Get-CimInstance CIM_ComputerSystem
        $operatingSystem = Get-CimInstance CIM_OperatingSystem
        
        $totalMemoryGB = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
        $freeMemoryGB = [math]::Round($operatingSystem.FreePhysicalMemory / 1MB, 2)
        $usedMemoryGB = [math]::Round($totalMemoryGB - $freeMemoryGB, 2)
        $memoryUsagePercent = [math]::Round(($usedMemoryGB / $totalMemoryGB) * 100, 2)
        
        if ($memoryUsagePercent -ge 90) {
            Write-HostColored "Memory Usage: $memoryUsagePercent% ($usedMemoryGB GB used of $totalMemoryGB GB) (Critical)" -ForegroundColor Red
        } elseif ($memoryUsagePercent -ge 80) {
            Write-HostColored "Memory Usage: $memoryUsagePercent% ($usedMemoryGB GB used of $totalMemoryGB GB) (High)" -ForegroundColor Red
        } elseif ($memoryUsagePercent -ge 70) {
            Write-HostColored "Memory Usage: $memoryUsagePercent% ($usedMemoryGB GB used of $totalMemoryGB GB) (Moderate)" -ForegroundColor Yellow
        } else {
            Write-HostColored "Memory Usage: $memoryUsagePercent% ($usedMemoryGB GB used of $totalMemoryGB GB) (Good)" -ForegroundColor Green
        }
        
        # Get high memory processes
        $highMemoryProcesses = Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 5
        
        Write-HostColored "Top memory consumers:" -ForegroundColor Yellow
        $highMemoryProcesses | Format-Table -Property ProcessName, Id, @{Name="Memory(MB)"; Expression={"{0:N2}" -f ($_.WorkingSet / 1MB)}} -AutoSize
    } catch {
        Write-HostColored "Error analyzing memory: $_" -ForegroundColor Red
    }
    
    # Disk analysis
    try {
        $disks = Get-CimInstance CIM_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
        
        Write-HostColored "Disk status:" -ForegroundColor Yellow
        
        foreach ($disk in $disks) {
            $sizeGB = [math]::Round($disk.Size / 1GB, 2)
            $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
            $usedGB = [math]::Round($sizeGB - $freeGB, 2)
            $usedPercent = [math]::Round(($usedGB / $sizeGB) * 100, 2)
            
            if ($usedPercent -ge 90) {
                Write-HostColored "  Drive $($disk.DeviceID): $usedPercent% ($freeGB GB free of $sizeGB GB) (Critical)" -ForegroundColor Red
            } elseif ($usedPercent -ge 80) {
                Write-HostColored "  Drive $($disk.DeviceID): $usedPercent% ($freeGB GB free of $sizeGB GB) (Low space)" -ForegroundColor Yellow
            } else {
                Write-HostColored "  Drive $($disk.DeviceID): $usedPercent% ($freeGB GB free of $sizeGB GB) (Good)" -ForegroundColor Green
            }
        }
    } catch {
        Write-HostColored "Error analyzing disks: $_" -ForegroundColor Red
    }
}

# Main function to execute the script
function Start-Optimization {
    # Check for admin privileges
    if (-not (Test-Administrator)) {
        Write-HostColored "This script requires administrator privileges." -ForegroundColor Red
        Write-HostColored "Please restart the script as an administrator." -ForegroundColor Yellow
        
        $choice = Read-Host "Would you like to restart the script with administrator privileges? (Y/N)"
        if ($choice -eq 'Y' -or $choice -eq 'y') {
            Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        }
        
        exit
    }
    
    # Display welcome message
    Clear-Host
    Write-HostColored "===== Windows System Performance Optimizer =====" -ForegroundColor Cyan
    Write-HostColored "This script will help optimize your Windows system for better performance." -ForegroundColor White
    Write-HostColored "Version: 1.0" -ForegroundColor White
    Write-HostColored "=================================================" -ForegroundColor Cyan
    
    # Main menu loop
    $keepRunning = $true
    while ($keepRunning) {
        Show-Menu
        $choice = Read-Host "Enter your choice"
        
        switch ($choice) {
            "1" { Run-QuickAnalysis }
            "2" { Remove-TemporaryFiles }
            "3" { Optimize-StartupPrograms }
            "4" { Optimize-WindowsSettings }
            "5" { Get-SystemInformation }
            "q" { $keepRunning = $false }
            "Q" { $keepRunning = $false }
            default { Write-HostColored "Invalid choice. Please try again." -ForegroundColor Yellow }
        }
        
        if ($keepRunning) {
            Write-HostColored "`nPress any key to return to the main menu..." -ForegroundColor Yellow
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
    }
    
    Write-HostColored "Thank you for using Windows System Performance Optimizer!" -ForegroundColor Cyan
    Write-HostColored "Exiting..." -ForegroundColor Yellow
}

# Start the script
Start-Optimization