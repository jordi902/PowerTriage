<#
.DESCRIPTION
    PowerTriage is a script to perform incident response via PowerShell on compromised devices with an Windows Operating System (Workstation & Server).  
	
	It's recommended to run this script with administrative privileges to get more Artifacts. Nevertheless, if not possible, some artificats will be collected.

    The collected information is saved in an output directory in the current folder, this is by creating a folder named 'DFIR-_hostname_-_year_-_month_-_date_'. This folder is zipped at the end to enable easy Collecting.
    
#>
clear

#Variable to hide error messages when Recent Items Function is executed
$ErrorActionPreference = "SilentlyContinue"

$Version = '1.0'
$ASCIIBanner = @"
 ____                       _____     _                  
|  _ \ _____      _____ _ _|_   _| __(_) __ _  __ _  ___ 
| |_) / _ \ \ /\ / / _ \ '__|| || '__| |/ _` |/ _` |/ _ \
|  __/ (_) \ V  V /  __/ |   | || |  | | (_| | (_| |  __/
|_|   \___/ \_/\_/ \___|_|   |_||_|  |_|\__,_|\__, |\___|
                                              |___/      `n
"@
Write-Host $ASCIIBanner
Write-Host "PowerTriage is a script to perform incident response via PowerShell on compromised devices with an Windows Operating System (Workstation & Server)." 
Write-Host "Version: $Version"
Write-Host "By twitter: @jdangosto, Github: https://github.com/jdangosto - Jesus Angosto (jdangosto)"

Write-Host "=================================================================================================================================================`n"

#Check Admin Privileges

$IsAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent() `
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Self-elevate the script if required
#if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
# if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
#  $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
#  Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
#  Exit
# }
#}

if ($IsAdmin) {
    Write-Host "DFIR Session starting as Administrator...`n"
}
else {
    Write-Host "No Administrator session detected. For the best performance run as Administrator. Not all items can be collected...`n" -ForegroundColor Red
    Start-Sleep -Seconds 3
    Write-Host "DFIR Session starting...`n`n"
}

#Seleccionar directorio de salida 

Write-Host "README: " -ForegroundColor Yellow
Write-Host "==========================================================================================================================================`n" -ForegroundColor Yellow
Write-Host "You can specify the output directory if you want, OTHERWISE a directory will be created in the SAME LOCATION where this script is running.`n" -ForegroundColor Yellow
Write-Host "==========================================================================================================================================`n" -ForegroundColor Yellow
#Write-Host "Example: C:\PowerTriage`n"


$folder = Read-Host "Folder to save the artifacts (You can leave it empty)"

If ($folder){
    $path = "C:\"
    $ExecutionTime = $(get-date -f yyyyMMdd_HHmmsstt)
    Write-Host "Running task 1 of 20" -ForegroundColor Yellow
    Write-Host "Creating output directory...`n"
    $FolderCreation = "$path\PowerTriage-$env:computername-$ExecutionTime" 
    Write-Host $FolderCreation
    mkdir -Force $FolderCreation | Out-Null
    Write-Host "==========================================================================================================================================`n" -ForegroundColor Green
    Write-Host "                               Output directory created: $FolderCreation...`n" -ForegroundColor Green
    Write-Host "==========================================================================================================================================`n" -ForegroundColor Green
    Start-Sleep -Seconds 3
   
}else{
   # $path = "C:\"
    $path = $pwd
    $ExecutionTime = $(get-date -f yyyyMMdd_HHmmsstt)
    Write-Host "Running task 1 of 20" -ForegroundColor Yellow
    Write-Host "Creating output directory...`n"
    $FolderCreation = "$path\PowerTriage-$env:computername-$ExecutionTime"
    Write-Host $FolderCreation
    mkdir -Force $FolderCreation | Out-Null
     Write-Host "==========================================================================================================================================`n" -ForegroundColor Green
    Write-Host "                               Output directory created: $FolderCreation...`n" -ForegroundColor Green
    Write-Host "==========================================================================================================================================`n" -ForegroundColor Green
    Start-Sleep -Seconds 3
   
}

#Ip del sistema
Write-Host "Running task 2 of 20" -ForegroundColor Yellow
Write-Host "Collecting IP Address...`n"
Get-NetIPAddress | Out-File -FilePath $FolderCreation\ip_info.txt

#Conexiones abiertas y establecidas
Write-Host "Running task 3 of 20" -ForegroundColor Yellow
Write-Host "Collecting open and stablished TCP conecctions...`n"
Get-NetTCPConnection -state Established | Out-File -FilePath $FolderCreation\TCP_Stablished_Connections.txt

#Listado de Shadow Copies
Write-Host "Running task 4 of 20" -ForegroundColor Yellow
write-host "Collecting List of existing shadow copies...`n"
Get-CimInstance Win32_ShadowCopy | Out-File -FilePath $FolderCreation\Shadow_Copies_list.txt

#persistencia en Autorun
Write-Host "Running task 4 of 20" -ForegroundColor Yellow
write-host "Collecting Autorun info...`n"
Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List | Out-File -Force $FolderCreation\Autoruns.txt

#Usuarios activos
Write-Host "Running task 5 of 20" -ForegroundColor Yellow
write-host "Collecting Active user/s on system...`n"
query user | Out-File -FilePath $FolderCreation\Active_users.txt

#Usuarios locales
Write-Host "Running task 6 of 20" -ForegroundColor Yellow
write-host "Collecting local users...`n"
Get-LocalUser | format-table | Out-File -FilePath $FolderCreation\Local_Users.txt


function Get-ProcessAndHashes {
    Write-Host "Running task 7 of 20" -ForegroundColor Yellow
    Write-Host "Collecting Active Processes...`n"
    $ProcessFolder = "$FolderCreation\ProcessInformation"
    New-Item -Path $ProcessFolder -ItemType Directory -Force | Out-Null
    $UniqueProcessHashOutput = "$ProcessFolder\UniqueProcessHash.csv"
    $ProcessListOutput = "$ProcessFolder\ProcessList.csv"
	$CSVExportLocation = "$CSVOutputFolder\Processes.csv"

    $processes_list = @()
    foreach ($process in (Get-WmiObject Win32_Process | Select-Object Name, ExecutablePath, CommandLine, ParentProcessId, ProcessId))
    {
        $process_obj = New-Object PSCustomObject
        if ($null -ne $process.ExecutablePath)
        {
            $hash = (Get-FileHash -Algorithm SHA256 -Path $process.ExecutablePath).Hash 
            $process_obj | Add-Member -NotePropertyName Proc_Hash -NotePropertyValue $hash
            $process_obj | Add-Member -NotePropertyName Proc_Name -NotePropertyValue $process.Name
            $process_obj | Add-Member -NotePropertyName Proc_Path -NotePropertyValue $process.ExecutablePath
            $process_obj | Add-Member -NotePropertyName Proc_CommandLine -NotePropertyValue $process.CommandLine
            $process_obj | Add-Member -NotePropertyName Proc_ParentProcessId -NotePropertyValue $process.ParentProcessId
            $process_obj | Add-Member -NotePropertyName Proc_ProcessId -NotePropertyValue $process.ProcessId
            $processes_list += $process_obj
        }   
    }

    ($processes_list | Select-Object Proc_Path, Proc_Hash -Unique).GetEnumerator() | Export-Csv -NoTypeInformation -Path $UniqueProcessHashOutput
	($processes_list | Select-Object Proc_Path, Proc_Hash -Unique).GetEnumerator() | Export-Csv -NoTypeInformation -Path $CSVExportLocation
    ($processes_list | Select-Object Proc_Name, Proc_Path, Proc_CommandLine, Proc_ParentProcessId, Proc_ProcessId, Proc_Hash).GetEnumerator() | Export-Csv -NoTypeInformation -Path $ProcessListOutput
	
}


function Print-ProcessTree() { 

  Write-Host "Running task 8 of 20" -ForegroundColor Yellow
  Write-Host "Collecting Process Tree (Parent & Child)...`n"

    function Get-ProcessAndChildProcesses($Level, $Process) { 

        "{0}[{1,-5}] [{2}]" -f ("  " * $Level), $Process.ProcessId, $Process.Name 

        $Children = $AllProcesses | where-object {$_.ParentProcessId -eq $Process.ProcessId -and $_.CreationDate -ge $Process.CreationDate} 

        if ($null -ne $Children) { 

            foreach ($Child in $Children) { 

                Get-ProcessAndChildProcesses ($Level + 1) $Child 

            } 

        } 

    } 

  

    $AllProcesses = Get-CimInstance -ClassName "win32_process" 

    $RootProcesses = @() 

    # Process "System Idle Process" is processed differently, as ProcessId and ParentProcessId are 0 

    # $AllProcesses is sliced from index 1 to the end of the array 

    foreach ($Process in $AllProcesses[1..($AllProcesses.length-1)]) { 

        $Parent = $AllProcesses | where-object {$_.ProcessId -eq $Process.ParentProcessId -and $_.CreationDate -lt $Process.CreationDate} 

        if ($null -eq $Parent) { 

            $RootProcesses += $Process 

        } 

    } 

    # Process the "System Idle process" separately 

    "[{0,-5}] [{1}]" -f $AllProcesses[0].ProcessId, $AllProcesses[0].Name 

    foreach ($Process in $RootProcesses) { 

        Get-ProcessAndChildProcesses 0 $Process 

    } 

} 

function Get-Evtx {
    Write-Host "Running task 9 of 20" -ForegroundColor Yellow
    Write-Host "Collecting System Events(evtx) Files...`n"
    $EventViewer = "$FolderCreation\EventsLogs"
    mkdir -Force $EventViewer | Out-Null
    $evtxPath = "C:\Windows\System32\winevt\Logs"
    $channels = @(
        "Application",
        "Security",
        "System",
        "Microsoft-Windows-Sysmon%4Operational",
        "Microsoft-Windows-TaskScheduler%4Operational",
        "Microsoft-Windows-PowerShell%4Operational",
        "Microsoft-Windows-WMI-Activity/Operational",
        "Microsoft-Windows-NTLM/Operational"
    )

    Get-ChildItem "$evtxPath\*.evtx" | Where-Object{$_.BaseName -in $channels} | ForEach-Object{
        Copy-Item  -Path $_.FullName -Destination "$($EventViewer)\$($_.Name)"
    }
}

#Obtención de procesos
Get-ProcessAndHashes
Print-ProcessTree | Out-File -Force $FolderCreation\ProcessInformation\ProcessTree.txt

#Obtencion de Eventos de sistema: Aplicación, Sistema, Seguridad, Sysmon, Tareas Programadas, Powershell Operational
Get-Evtx

#comandos powershell de todos los usuarios
function PowerShell_Commands{
 Write-Host "Running task 10 of 20" -ForegroundColor Yellow
 Write-Host "Collecting Console Powershell History (all users)...`n"
    $PowershellConsoleHistory = "$FolderCreation\PowerShellHistory"
    #Write-Host "Directorio: " $PowershellConsoleHistory
    # Directorio de los usuarios
    
    $usersDirectory = "C:\Users"
    # Listado de directorio de usuarios en C:\Users
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory
    foreach ($userDir in $userDirectories) {
        $userName = $userDir.Name
        $historyFilePath = Join-Path -Path $userDir.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path -Path $historyFilePath -PathType Leaf) {
            $outputDirectory = "$PowershellConsoleHistory\$userDir"
            mkdir -Force $outputDirectory | Out-Null
            Copy-Item -Path $historyFilePath -Destination $outputDirectory -Force
            }
        }
    

}

PowerShell_Commands

#Tareas Programadas
Write-Host "Running task 11 of 20" -ForegroundColor Yellow
Write-Host "Collecting Schedule Tasks and Tasks run info...`n"
$ScheduleFolder = "$FolderCreation\ScheduleTask"
mkdir -Force $ScheduleFolder | Out-Null
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Format-List | Out-File -Force -FilePath $ScheduleFolder\ScheduleTask_list.txt
Write-Host "Running task 12 of 20" -ForegroundColor Yellow
Write-Host "Collecting Schedule Tasks Run Info...`n"
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Get-ScheduledTaskInfo | Out-File -Force -FilePath $ScheduleFolder\ScheduleTask_RunInfo.txt

#Servicios
Write-Host "Running task 13 of 20" -ForegroundColor Yellow
Write-Host "Collecting running services...`n"
Get-Service | Where-Object {$_.Status -eq "Running"} | format-list | Out-file -Force -FilePath $FolderCreation\Services_Running.txt


#PowerShell Console History todos los usuarios

function Get-PowershellHistory {
    Write-Host "Running task 14 of 20" -ForegroundColor Yellow
    Write-Host "Collecting Console Powershell History All Users...`n"
    $PowershellConsoleHistory = "$FolderCreation\PowerShellHistory"
    # Specify the directory where user profiles are stored
    $usersDirectory = "C:\Users"
    # Get a list of all user directories in C:\Users
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory
    foreach ($userDir in $userDirectories) {
        $userName = $userDir
        $historyFilePath = Join-Path -Path $userDir.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path -Path $historyFilePath -PathType Leaf) {
            $outputDirectory = "$PowershellConsoleHistory\$userDir"
            mkdir -Force $outputDirectory | Out-Null
            Copy-Item -Path $historyFilePath -Destination $outputDirectory -Force
            }
        }
}    

Get-PowershellHistory

#Elementos Recientes
function RecentFiles{
 Write-Host "Running task 15 of 20" -ForegroundColor Yellow
 Write-Host "Collecting Recent Items (all users)...`n"
    $Recent = "$FolderCreation\Recent_Items"
    #Write-Host "Directorio: " $Recent
    # Directorio de los usuarios
    #mkdir -Force $Recent | Out-Null
    $usersDirectory = "C:\Users"
    # Listado de directorio de usuarios en C:\Users
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory
    foreach ($userDir in $userDirectories) {
        $userName = $userDir.Name
        $RecentFilePath = Join-Path -Path $userDir.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\Recent\*"
        #Write-Host $RecentFilePath
        #Write-Host $userName
        $origen = $RecentFilePath
        $destino = "$Recent\$userName"
        #Write-Host $origen "--" $destino
        
            Copy-Item "$origen" -Destination "$destino"
        }
}
RecentFiles


#ActivitiesCache all Users
function ActivitiesCache{
 Write-Host "Running task 16 of 20" -ForegroundColor Yellow
 Write-Host "Collecting Recent Items (all users)...`n"
    $Recent = "$FolderCreation\Activities_Cache"
    $usersDirectory = "C:\Users"
    # Listado de directorio de usuarios en C:\Users
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory
    foreach ($userDir in $userDirectories) {
   
        $userName = $userDir.Name
        $RecentFilePath = Join-Path -Path $userDir.FullName -ChildPath "AppData\Local\ConnectedDevicesPlatform\*"
        #Write-Host $RecentFilePath
        #Write-Host $userName
        $origen = $RecentFilePath
        $destino = "$Recent\$userName"
        #Write-Host $origen "--" $destino
      try{
            Copy-Item "$origen" -Destination "$destino" -Force -Recurse
       }
       catch{ Write-Host "User $userName hasn't ActivitiesCache file"}

        }
}
ActivitiesCache

#Copia de Prefecth
function CopyPrefetch{
  Write-Host "Running task 17 of 20" -ForegroundColor Yellow
  Write-Host "Collecting Prefetch...`n"
  $origen = "C:\Windows\Prefetch"
  $destino = "$FolderCreation\Prefetch"
  Copy-Item -Path "$origen" -Destination "$destino" -Force -Recurse
}
CopyPrefetch

#RecycleBin All Users
function RecycleBin{

    Write-Host "Running task 18 of 20" -ForegroundColor Yellow
    Write-Host "Collecting Recycle.Bin (all users)...`n"
    $origen = "C:\`$Recycle.Bin"
    $destino = "$FolderCreation\RecycleBin"
    Copy-Item -Path "$origen" -Destination "$destino" -Force -Recurse
   
}
RecycleBin

function Get-DNS {
    Write-Host "Running task 19 of 20" -ForegroundColor Yellow
    Write-Host "Collecting DNS Cache..."
    $destino = "$FolderCreation\DNSCache.txt"
    Get-DnsClientCache | Format-List | Out-File -Force -FilePath $destino
	
}
Get-DNS

function Zip-Results {
    Write-Host "Running task 20 of 20" -ForegroundColor Yellow
    Write-Host "Write results to $FolderCreation.zip...`n"
    Compress-Archive -Force -LiteralPath $FolderCreation -DestinationPath "$FolderCreation.zip"
    delete colleted folder
    Remove-Item -Path $FolderCreation -Recurse
}

Zip-Results
