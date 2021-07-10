

param (
    [Parameter(Mandatory)][String] $Action, 
    [Parameter(Mandatory)][String] $Path, 
    [String] $RecipientKeyName, 
    [String] $TransferFileName, 
    [String] $ReconcileFileName = "##protect_transfer_reconcile##.csv", 
    [String] $SecretFileName = ".\transfer.key", 
    [switch] $ExcludeHash,
    [switch] $Install7zip
)

$default_dateLocal = Get-Date -Format "yyyyMMdd_HHmm"
$default_reconcileFile = "##protect_transfer_reconcile##.csv"
$default_secretEncrypted = ".\transfer.key"


function Write-Log {
    param(
        [String] $LogEntry
    )

    $date = Get-Date -f "yyyy-MM-dd"

    $logPath = Join-Path -Path ".\" -ChildPath "Logs"
    $logName = "protect_transfer_reconcile_$date.log"
    $sFullPath = Join-Path -Path $logPath -ChildPath $logName 

    if (!(Test-Path -Path $logPath)) {
        $null = New-Item -Path $logPath -ItemType Directory
    }

    if (!(Test-Path -Path $sFullPath)) {
        Write-Host "Log path: $sFullPath"
        $null = New-Item -Path $sFullPath -ItemType File
    }
    $dateTime = Get-Date -f "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $sFullPath -Value "[$dateTime]. $LogEntry"

}

function Close-Log {
    $dateTime = Get-Date -f "yyyy-MM-dd HH:mm:ss"
    Write-Log "***********************************************************************************"
    Write-Log "*   End of processing: [$dateTime]"
    Write-Log "***********************************************************************************"
}

function New-RandomPassword {
param(
    [int]$length = 20,
    [String]$characters = "abcdefghiklmnoprstuvwxyzABCDEFGHKLMNOPRSTUVWXYZ1234567890!()?}][{@#*+-",
    [switch]$ConvertToSecureString
)
    $password = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
    $private:ofs=""
    
    if ($ConvertToSecureString.IsPresent) {
        return ConvertTo-SecureString -String [String]$characters[$password] -AsPlainText -Force
    } else {
        return [String]$characters[$password]
    }
}


# Reconcile
function Set-Reconcile
{
Param( 
    [Parameter(Mandatory)][String] $ReconcileFile,
    [Parameter(Mandatory)][String] $FolderName,
    [switch]$Feedback = $false
) 

    if ($reconcileFile -eq "")
    {
        $reconcileFile = $default_reconcileFile
    }

    If (!(Test-Path -Path $folderName )) {    
        Write-Log "Folder '$folderName' does not exist"
        Write-Host "Folder '$folderName' does not exist" -ForegroundColor Red
        Close-Log
        return
    }

    Write-Log "Generating reconciliation file '$reconcileFile'"
    Write-Host "Generating reconciliation file '$reconcileFile'"
    
    $totalFileCount = 0
    $totalFileSize = 0

    Set-Content -Path $reconcileFile  -Value '"FullName","LastWriteTime","Length","Hash","ParentFolder","Object"'
    Get-Childitem $folderName -Recurse | Where-Object {!$_.PSIsContainer} | ForEach-Object {
        $totalFilecount = $totalFileCount + 1
        $totalFileSize = $totalFileSize + $_.Length 
        if ($ExcludeHash) {
            $sourceHash = ""
        } else {
            $sourceHash = (Get-FileHash -Path $_.FullName).Hash
        }
        $record = '"'+$_.FullName.Replace($folderName, "")+'","'+$_.LastWriteTime.ToString("yyyy-MM-ddTHH:mm:ss")+'",'+$_.Length+',"'+$sourceHash+'","'+ $_.Directory + '","' + $_.Name + '"'
        Add-Content -Path  $reconcileFile  -Value $record
    }

    if ($totalFileSize -ge 1000000000000) {
        $totalRightLabel = "TB"
        $totalFileXbytes = [math]::Round(($totalFileSize / 1000000000000), 2)        
    } else {
        if ($totalFileSize -ge 1000000000) {
            $totalRightLabel = "GB"
            $totalFileXbytes = [math]::Round(($totalFileSize / 1000000000), 2)        
        } else { 
            if ($totalFileSize -ge 1000000) {
                $totalRightLabel = "MB"
                $totalFileXbytes = [math]::Round(($totalFileSize / 1000000), 2)        
            } else {
                $totalRightLabel = "KB"
                $totalFileXbytes = [math]::Round(($totalFileSize / 1000), 2)
            }
        }
    }

    Write-Log "Total reconcile file count is $totalFileCount and size $totalFileXbytes $totalRightLabel"
    if ($feedback) {
        Write-Host "Total reconcile file count is $totalFileCount and size $totalFileXbytes $totalRightLabel" -ForegroundColor Green
    }
}


function Invoke-Pack
{
Param( 
    [String] $TransferFolder,
    [String] $ToName,
    [String] $CompressFile,
    [String] $ReconcileFile,
    [String] $SecretEncrypted
) 
    # Send
    If (!(Test-Path -Path $transferFolder )) {    
        Write-Log "Folder '$transferFolder' does not exist"
        Write-Host "Folder '$transferFolder' does not exist" -ForegroundColor Red
        Close-Log
        return
    }


    Write-Log "Packing files to compress file '$compressFile'"
    Write-Log "Source folder is '$transferFolder'"
    Write-Host "Packing files to compress file '$compressFile'"

    if ($reconcileFile -eq "")
    {
        $reconcileFile = $default_reconcileFile
    }

    if ($secretEncrypted -eq "")
    {
        $secretEncrypted = $default_secretEncrypted
    }

    # First step - create protected secret
    $secret = New-RandomPassword -Length 80
    Protect-CmsMessage -To $toName -OutFile $secretEncrypted -Content $secret

    # Second step - compress the data files
    Compress-7Zip -Path $transferFolder -ArchiveFileName $compressFile -Format SevenZip 

    # Third step - create the reconcile file
    Set-Reconcile -ReconcileFile $reconcileFile -FolderName $transferFolder

    # Fourth step - add reconcile file to ZIP and encrypt
    Write-Log "Add reconcile file '$reconcileFile' to file '$compressFile'"
    $fullReconcileName = (Get-Item $reconcileFile).FullName
    $fullZipName = (Get-Item $compressFile).FullName
    Compress-7Zip -Path $fullReconcileName -ArchiveFileName $fullZipName -Format SevenZip -Append -Password $secret -EncryptFilenames
    Remove-Item $fullReconcileName
    Write-Log "Package ready in file '$compressFile' from folder '$transferFolder'"
    Write-Host "Package ready in file '$compressFile' from folder '$transferFolder'"  -ForegroundColor Green
}


function Invoke-Unpack
{
Param( 
    [String] $RestoreFolder,
    [String] $ToName,
    [String] $CompressFile,
    [String] $SecretEncrypted
) 
    # Receive
    If (!(Test-Path -Path $CompressFile )) {    
        Write-Log "Transfer/compress file '$CompressFile' does not exist"
        Write-Host "Transfer/compress file '$CompressFile' does not exist" -ForegroundColor Red
        Close-Log
        return
    }

    if ($secretEncrypted -eq "")
    {
        $secretEncrypted = $default_secretEncrypted
    }

    # First step - decrypt password for uncompressing
    Write-Log "Restoring files transferred to '$restoreFolder'"
    Write-Log "Package/Compress file is '$compressFile'"
    $secret = Unprotect-CmsMessage -To $toName -Path $secretEncrypted

    # Second step - uncompress the data files
    Expand-7Zip -ArchiveFileName $compressFile -TargetPath $restoreFolder -Password $secret
    Write-Log "Package unpacked from file '$compressFile' to folder '$restoreFolder'"
    Write-Host "Package unpacked from file '$compressFile' to folder '$restoreFolder'" -ForegroundColor Green
}


# Reconcile
function Invoke-Reconcile
{
Param( 
    [Parameter(Mandatory)][String] $reconcileFileName,
    [Parameter(Mandatory)][String] $folderName
) 

    Write-Log "Reconciling documents transferred"
    Write-Host "Reconciling documents transferred"
    If (!(Test-Path -Path $reconcileFileName )) {    
        Write-Log "Reconciliation file '$reconcileFileName' does not exist"
        Write-Host "Reconciliation file '$reconcileFileName' does not exist" -ForegroundColor Red
        Close-Log
        return
    }
    If (!(Test-Path -Path $folderName )) {    
        Write-Log "Folder '$folderName' does not exist"
        Write-Host "Folder '$folderName' does not exist" -ForegroundColor Red
        Close-Log
        return
    }
    Write-Log "Using reconciliation file '$reconcileFileName'"
    
    $totalFilecount = 0
    $errorCount = 0

    # For each entry in the reconcile file
    #     find the file and compare hash
    Import-Csv $reconcileFileName | ForEach-Object {
        $totalFileCount = $totalFileCount +1 
        $restoreFileName = $(Join-Path -Path $folderName -ChildPath $_.FullName)    
        If (Test-Path -Path $restoreFileName ) {    
            $targetHash= (Get-FileHash -Path $restoreFileName).Hash
            if ($_.Hash -ne $targetHash) {
                $errorCount = $errorCount + 1
                Write-Log "Hash mismatch for file '$restoreFileName'"
            }
            if ((Get-Item -Path $restoreFileName).LastWriteTime.ToString("yyyy-MM-ddTHH:mm:ss") -ne $_.LastWriteTime) {
                $errorCount = $errorCount + 1
                Write-Log "Last write mismatch for file '$restoreFileName'"
            }
            
        } else {
            $errorCount = $errorCount + 1
            Write-Log "Non existant target file '$restoreFileName'"
        }
    }

    Write-Log "Total file count is $totalFileCount with $errorCount errors"
    if ($errorCount -gt 0) {
        Write-Host "Total file count is $totalFileCount with $errorCount errors" -ForegroundColor Red
    } else {
        Write-Host "Total file count is $totalFileCount with $errorCount errors"  -ForegroundColor Green
    }
}

$dateTimeStart = Get-Date -f "yyyy-MM-dd HH:mm:ss"
Write-Log "***********************************************************************************"
Write-Log "*   Start of processing: [$dateTimeStart]"
Write-Log "***********************************************************************************"

if ($install7zip) {
    Install-Module -Name 7Zip4Powershell -Scope CurrentUser
}

$actioned = $false

if ($action -eq "Pack") {
    $actioned = $true
    if ($RecipientKeyName -eq "") {
        Write-Log "Recipient Key Name required for packing" 
        Write-Host "Recipient Key Name required for packing"  -ForegroundColor Red
        Close-Log
        return
    } 
    
    if ($TransferFileName -eq "") {
        $TransferFileName = ".\transfer_protect_$default_dateLocal.7z"
    }
    
    Invoke-Pack -TransferFolder $path -ToName $recipientKeyName -CompressFile $transferFileName -ReconcileFile $reconcileFileName -SecretEncrypted $secretFileName
    
}


if ($action -eq "Unpack") {
    $actioned = $true
    if ($RecipientKeyName -eq "") {
        Write-Log "Recipient Key Name required for unpacking" 
        Write-Host "Recipient Key Name required for unpacking" -ForegroundColor Red
        Close-Log
        return
    } 
    if ($TransferFileName -eq "") {
            Write-Log "Transfer/Compress File Name required for unpacking" 
            Write-Host "Transfer/Compress File Name required for unpacking" -ForegroundColor Red
            Close-Log
            return
    } 
    
    Invoke-Unpack -RestoreFolder $path -ToName $recipientKeyName -CompressFile $transferFileName
    
}


if ($action -eq "ReconcileFile") {
    $actioned = $true
    Set-Reconcile -ReconcileFile $reconcileFileName -FolderName $path -Feedback 
}


if ($action -eq "Reconcile") {
    $actioned = $true
    $localReconcileFile = Join-Path -Path $path -ChildPath $reconcileFileName
    Invoke-Reconcile -ReconcileFile $localReconcileFile -FolderName $path
}


if (!($actioned))
{
    Write-Log "Unknown action '$action'.  No processing performed" 
    Write-Host "Unknown action '$action'.  No processing performed"  -ForegroundColor Red
    Write-Host "Recognised actions: "
    Write-Host "    Pack          : Pack folder contents into secure 7Zip file"
    Write-Host "    Unpack        : Unpack folder contents from secure 7Zip file"
    Write-Host "    Reconcile     : Reconcile files in unpack folder with list of packed files"
    Write-Host "    ReconcileFile : Generate a reconcile file without packing"
}

Close-Log
