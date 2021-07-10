<#
 .Synopsis
   Allows the secure transfer and reconciliation of a large number of files

 .Description
   Packages source folder contents into a 7ZIP file, adding a reconciliation 
   file to the 7ZIP file and then encrypting the contents.  Send 
   * this script
   * the 7ZIP package file 
   * plus optional SecretFilename ( if using RecipientKeyName )
   to the target or recipient.
   
   The source folder is not altered and only read rights are required. A log
   file is written at exceution to record activity.

   The SecretFileName can be sent via email, while the 7ZIP can go different routes 
   such as:
   * HTTPS web file upload
   * SFTP transfer
   * USB stick

   At the target, unpack the contents to a folder and reconcile the results.  You
   will need write access on the target storage. A log file is written at exceution
   to record activity.

   Your bulk file transfer is encrypted in transit.  Note that if you use the
   SecretKey method the ecnrypted contents will only be as secure as the strength
   of your secret.

   A log file is produced on execution.  Repeated executions on the same day
   will add text content to the same log file.  The default log name takes the form:
   "protect_transfer_reconcile_yyyy-MM-dd.log"

   You will need to have installed the 7Zip4Powershell PowerShell cmdlet 
   before using the pack or unpack actions.  You can install the cmdlet
   by executing 
   .\protect_transfer_reconcile.ps1 -Action install -Path ".\" 

   Author:  Tom Peltonen

 .Parameter Action
  Action to perform, which can be:
  - Install
  - Pack
  - Unpack
  - Reconcile
  - ReconcileFile

 .Parameter Path
  The path to the files and folders to pack or the path to the unpack location. 
  The path can include a trailing * as a wildcard to only include a subset of 
  directories.

  When using the trailing * for names, the filtering is only applied to immediate
  folder names under the parent folder.  The filter does not cascade to lower folders.
  

 .Parameter RecipientKeyName
  The recipient of the package which is used to find the appropriate
  certificate for encrypting with the public key.  Either the RecipientKeyName 
  or the SecretKey is required for packing or unpacking the 7ZIP file.
  Using the RecipientKeyName is the most secure transfer option as a
  asymmetric cryptographic key is used that can only be decrypted by the 
  holder of the private key.

  If you are using the RecipientKeyName, then the 7ZIP file contents can only
  be unzipped by the holder of the private key and the SecretFileName file.
  If you don't have the private, which you should not unless you are sending
  to yourself, then you cannot unpack the 7ZIP file.

 .Parameter SecretKey
  A tradiitional secret to encrypt or decrypt the 7ZIP package. Either the RecipientKeyName 
  or the SecretKey is required for packing or unpacking the 7ZIP file.  This method
  uses a symmetric cryptographic key exchange which is less secure then the 
  RecipientKeyName approach.

 .Parameter TransferFileName
  The location and name of the 7ZIP file.  If not supplied a default 7ZIP file name
  will be generated in the current directory.

  The default name will take the form ".\transfer_protect_yyyyMMdd_hhmm.7z"

 .Parameter RootFolderName
  The root folder, which should be used if using wildcard (*) for the
  path.  A guess will be made as to value if not supplied, which will
  work in  many circumstances.

 .Parameter ReconcileFileName
  The name of the reconfile file name to generate during pack or use 
  during unpack.  This is a file name without path.  If no value is 
  supplied, then a default name is generated.
  The reconcile file is included into the root of the 7ZIP file.
  Once a reconcile is executed, you can delete this file from the 
  restored location.

  The default name is "##protect_transfer_reconcile##.csv"

 .Parameter SecretFileName
  The secret file name is used with RecipientKeyName to secure the
  internally generated password for the 7ZIP file.  When unpacking the
  7ZIP file you will need access to this file if RecipientKeyName
  was used. If not supplied a default name is used.  This file is 
  encrypted with RecipientKeyName.

  The default name is ".\transfer.key"

 .Parameter ExcludeHash
  Exclude the file hash from the reconcile file.  As producing a file
  hash takes compute cycles during pack, you can select to bypass this 
  generation to speed up the packaging.  Excluding the hash does reduce 
  the functionality of the reconciliation at unpack.

 .Parameter LogPath
  The log folder where log files are written.  If the folder does not
  exist then it is created.  You need write access rights to this location.

 .Notes
  This script has been written to use the 7ZIP function as it is open source
  and provides a secure encryption mechanism, plus portability on Windows,
  Linux and MacOS.

  It is also beneficial that 7ZIP has efficient compression algorithms.

  Compressing and packing a large data set can take significant time and also
  require storage space.  The script does not check if you have sufficient
  free storage to package the source contents into a single 7ZIP file.  It is your
  responsibility to ensure sufficient storage space exists.

 
 .Example
   # Pack and encrypt all files in folder ".\transferpack\" using a private-public key
   # A file named ".\transfer.key" is also generated alongside the 7ZIP file
   protect_transfer_reconcile.ps1 -Action pack -Path ".\transferpack\" -RecipientKeyName data@mycompany
 
 .Example
   # Unpack all files in 7ZIP file "transfer_protect_yyyMMdd_hhmm.7z" to folder ".\targetdir" using a private-public key
   # You will need the file named ".\transfer.key" to unpack the encrypted 7ZIP file
   .\protect_transfer_reconcile.ps1 -Action unpack -TransferFileName "transfer_protect_yyyMMdd_hhmm.7z" -Path ".\targetdir" -RecipientKeyName data@mycompany
 
 .Example
   # Reconcile files in folder ".\targetdir"
   .\protect_transfer_reconcile.ps1 -Action reconcile -Path ".\targetdir" 

 .Example
   # Pack and encrypt all files in folder ".\transferpack\" using a password
   .\protect_transfer_reconcile.ps1 -Action pack -Path ".\transferpack\" -SecretKey "fjks932c-x=23ds"
 
 .Example
   # Unpack all files in 7ZIP file "transfer_protect_yyyMMdd_hhmm.7z" to folder ".\targetdir" using a password
   .\protect_transfer_reconcile.ps1 -Action unpack -TransferFileName "transfer_protect_yyyMMdd_hhmm.7z" -Path ".\targetdir" -SecretKey "fjks932c-x=23ds"

 .Example
   # Pack and encrypt all files in folder ".\transferpack\02*" where the folder name starts with "02" using a password
   .\protect_transfer_reconcile.ps1 -Action pack -Path ".\transferpack\02*" -SecretKey "fjks932c-x=23ds"

#>

param (
    [Parameter(Mandatory)][String] $Action, 
    [Parameter(Mandatory)][String] $Path, 
    [String] $RecipientKeyName,
    [String] $SecretKey, 
    [String] $TransferFileName, 
    [String] $RootFolderName,
    [String] $ReconcileFileName, 
    [String] $SecretFileName, 
    [switch] $ExcludeHash,
    [String] $LogPath

)

$default_dateLocal = Get-Date -Format "yyyyMMdd_HHmm"
$default_reconcileFile = "##protect_transfer_reconcile##.csv"
$default_secretEncrypted = ".\transfer.key"


function Write-Log {
    param(
        [String] $LogEntry
    )

    $date = Get-Date -f "yyyy-MM-dd"

    if ($LogPath -eq "")
    {
        $logPath = Join-Path -Path ".\" -ChildPath "Logs"
    }
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
    [int] $length = 20,
    [String] $characters = "abcdefghiklmnoprstuvwxyzABCDEFGHKLMNOPRSTUVWXYZ1234567890!()?}][{@#*+-",
    [switch] $ConvertToSecureString
)
    $password = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
    $private:ofs=""
    
    if ($ConvertToSecureString.IsPresent) {
        return ConvertTo-SecureString -String [String]$characters[$password] -AsPlainText -Force
    } else {
        return [String]$characters[$password]
    }
}

function Test-Files
{
    Param( 
        [Parameter(Mandatory)][String] $FolderName,
        [String] $Filter
    ) 

    Get-ChildItem $folderName -Recurse | Where-Object {!$_.PSIsContainer} | ForEach-Object {
        return $true
    }
    
    return $false
}

# Reconcile
function Set-Reconcile
{
Param( 
    [Parameter(Mandatory)][String] $ReconcileFile,
    [Parameter(Mandatory)][String] $FolderName,
    [String] $RootFolderName,
    [String] $Filter,
    [switch] $Feedback = $false
) 

    if ($reconcileFile -eq "")
    {
        $reconcileFile = $default_reconcileFile
    }

    If (!(Test-Path -Path $folderName )) {    
        Write-Log "Folder '$folderName' does not exist"
        Write-Host "Folder '$folderName' does not exist" -ForegroundColor Red
        Close-Log
        Exit
    }

    Write-Log "Generating reconciliation file '$reconcileFile'"
    Write-Host "Generating reconciliation file '$reconcileFile'"
    
    $totalFileCount = 0
    $totalFileSize = 0

    if ($rootFolderName -eq "") {
        $rootFolderName = $folderName
    }

    Set-Content -Path $reconcileFile  -Value '"FullName","LastWriteTime","Length","Hash","ParentFolder","Object"'
    Get-ChildItem $folderName -Recurse | Where-Object {!$_.PSIsContainer} | ForEach-Object {
        $totalFilecount = $totalFileCount + 1
        $totalFileSize = $totalFileSize + $_.Length 
        if ($ExcludeHash) {
            $sourceHash = ""
        } else {
            $sourceHash = (Get-FileHash -Path $_.FullName).Hash
        }
        $record = '"'+$_.FullName.Replace($rootFolderName, "")+'","'+$_.LastWriteTime.ToString("yyyy-MM-ddTHH:mm:ss")+'",'+$_.Length+',"'+$sourceHash+'","'+ $_.Directory + '","' + $_.Name + '"'
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

    Write-Log "Total reconcile file count is $totalFileCount and size $totalFileXbytes $totalRightLabel ($totalFileSize)"
    if ($feedback) {
        Write-Host "Total reconcile file count is $totalFileCount and size $totalFileXbytes $totalRightLabel" -ForegroundColor Green
    }
}

# Compress / Package
function Invoke-Pack
{
Param( 
    [String] $TransferFolder,
    [String] $RootFolder,
    [String] $Filter,
    [String] $Secret,
    [String] $CompressFile,
    [String] $ReconcileFile
) 

    If (!(Test-Path -Path $transferFolder )) {    
        Write-Log "Folder '$transferFolder' does not exist"
        Write-Host "Folder '$transferFolder' does not exist" -ForegroundColor Red
        Close-Log
        Exit
    }

    Write-Log "Packing files to compress file '$compressFile'"
    Write-Log "Source folder is '$transferFolder'"
    Write-Host "Packing files to compress file '$compressFile'"

    if ($reconcileFile -eq "")
    {
        $reconcileFile = $default_reconcileFile
    }

    if ($transferFolder.EndsWith("*"))
    {
        $firstCompress = $true

        Get-ChildItem $transferFolder| ForEach-Object {
            Write-Log "Transfer folder '$($_.FullName)'"
            Write-Host "Transfer folder '$($_.FullName)'"
            if (Test-Files -FolderName $_.FullName -Filter $filter) {
                try {
                    if ($firstCompress) {
                        Compress-7Zip -Path $_.FullName -ArchiveFileName $compressFile -Format SevenZip -PreserveDirectoryRoot    
                    } else {
                        Compress-7Zip -Path $_.FullName -ArchiveFileName $compressFile -Format SevenZip -PreserveDirectoryRoot -Append    
                    }
                    $firstCompress = $false
                } catch {
                    Write-Log "Compress error with file '$($_.FullName)'.  See any previous errors.  $Error"
                    Write-Host "Compress error with file '$($_.FullName)'.  See any previous errors.  $Error" -ForegroundColor Red
                }
            } else {
                Write-Log "Empty folder '$($_.FullName)'"
                Write-Host "Empty folder '$($_.FullName)'"
            }
        }
    } else {
        Write-Log "Transfer folder '$transferFolder'"
        Write-Host "Transfer folder '$transferFolder'"
        Compress-7Zip -Path $transferFolder -ArchiveFileName $compressFile -Format SevenZip     
    }

    If (!(Test-Path -Path $compressFile )) {    
        Write-Log "Compress file '$compressFile' was not created.  See any previous errors"
        Write-Host "Compress file '$compressFile' was not created.  See any previous errors" -ForegroundColor Red
        Close-Log
        Exit
    }

    Set-Reconcile -ReconcileFile $reconcileFile -FolderName $transferFolder -Filter $filter -RootFolderName $rootFolder
    If (!(Test-Path -Path $compressFile )) {    
        Write-Log "Reconcile file '$reconcileFile' was not created.  See any previous errors"
        Write-Host "Reconcile file '$reconcileFile' was not created.  See any previous errors" -ForegroundColor Red
        Close-Log
        return
    }

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
    [String] $Secret,
    [String] $CompressFile
) 

    If (!(Test-Path -Path $CompressFile )) {    
        Write-Log "Transfer/compress file '$CompressFile' does not exist"
        Write-Host "Transfer/compress file '$CompressFile' does not exist" -ForegroundColor Red
        Close-Log
        Exit
    }

    Write-Log "Restoring files transferred to '$restoreFolder'"
    Write-Log "Package/Compress file is '$compressFile'"

    # Uncompress the data files
    Expand-7Zip -ArchiveFileName $compressFile -TargetPath $restoreFolder -Password $secret
    Write-Log "Package unpacked from file '$compressFile' to folder '$restoreFolder'"
    Write-Host "Package unpacked from file '$compressFile' to folder '$restoreFolder'" -ForegroundColor Green
}


# Reconcile
function Invoke-Reconcile
{
Param( 
    [Parameter(Mandatory)][String] $ReconcileFile,
    [Parameter(Mandatory)][String] $Folder,
    [String] $TargetReconcileFile,
    [String] $Filter
) 

    if ($reconcileFile -eq "")
    {
        $reconcileFile = $default_reconcileFile
    }

    Write-Log "Reconciling documents transferred"
    Write-Host "Reconciling documents transferred"
    If (!(Test-Path -Path $reconcileFile )) {    
        Write-Log "Reconciliation file '$reconcileFile' does not exist"
        Write-Host "Reconciliation file '$reconcileFile' does not exist" -ForegroundColor Red
        Close-Log
        Exit
    }
    If (!(Test-Path -Path $folder )) {    
        Write-Log "Folder '$folder' does not exist"
        Write-Host "Folder '$folder' does not exist" -ForegroundColor Red
        Close-Log
        Exit
    }
    Write-Log "Using reconciliation file '$reconcileFile'"
    
    $totalFileCount = 0
    $totalFileSize = 0
    $errorCount = 0
    $missingHash = $false

    # For each entry in the reconcile file
    #     find the file and compare hash
    Import-Csv $reconcileFile | ForEach-Object {
        $totalFileCount = $totalFileCount +1 
        $restoreFileName = $(Join-Path -Path $folder -ChildPath $_.FullName)    
        If (Test-Path -Path $restoreFileName ) {    
            if ($_.Hash -ne "") {
                $targetHash= (Get-FileHash -Path $restoreFileName).Hash
                if ($_.Hash -ne $targetHash) {
                    $errorCount = $errorCount + 1
                    Write-Log "Hash mismatch for file '$restoreFileName'"
                }
            } else {
                $missingHash = $true
            }
            if ((Get-Item -Path $restoreFileName).LastWriteTime.ToString("yyyy-MM-ddTHH:mm:ss") -ne $_.LastWriteTime) {
                $errorCount = $errorCount + 1
                Write-Log "Last write mismatch for file '$restoreFileName'"
            }
            $totalFileSize = $totalFileSize + (Get-Item -Path $restoreFileName).Length             
        } else {
            $errorCount = $errorCount + 1
            Write-Log "Non existant target file '$restoreFileName'"
        }
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
    Write-Log "Total file storage size is $totalFileXbytes $totalRightLabel ($totalFileSize)"
    Write-Host "Total file storage size is $totalFileXbytes $totalRightLabel"

    Write-Log "Total file count is $totalFileCount with $errorCount errors"
    if ($missingHash)
    {
        Write-Log "Reconcile file had one or many or all blank hash entries"
        Write-Host "Reconcile file had one or many or all blank hash entries"  -ForegroundColor Yellow
    }
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


$actioned = $false

if ($action -eq "Install") {
    $actioned = $true
    Install-Module -Name 7Zip4Powershell -Scope CurrentUser
}

if ($action -eq "Pack") {
    $actioned = $true
    if (($RecipientKeyName -eq "") -and ($SecretKey -eq "")) {
        Write-Log "Recipient Key Name or Secret Key required for packing" 
        Write-Host "Recipient Key Name or Secret Key required for packing"  -ForegroundColor Red
        Close-Log
        return
    } 
      
    if ($rootFolderName -eq "") {
        if ($path.EndsWith("*")) {
            Write-Log "Root folder required for packing when using wild card for Path" 
            Write-Host "Root folder required for packing when using wild card for Path"  -ForegroundColor Red
            Close-Log
            return
        } else {
            $rootFolderName = $path
        }
    }

    if ($TransferFileName -eq "") {
        $TransferFileName = ".\transfer_protect_$default_dateLocal.7z"
    }

    if ($SecretKey -eq "") {
        if ($secretFileName -eq "")
        {
            $secretFileName = $default_secretEncrypted
        }
        $secret = New-RandomPassword -Length 80
        Protect-CmsMessage -To $recipientKeyName -OutFile $secretFileName -Content $secret
    } else {
        $secret = $SecretKey
    }

    Invoke-Pack -TransferFolder $path -Secret $secret -CompressFile $transferFileName -ReconcileFile $reconcileFileName -RootFolder $rootFolderName
}


if ($action -eq "Unpack") {
    $actioned = $true
    if (($RecipientKeyName -eq "") -and ($SecretKey -eq "")) {
        Write-Log "Recipient Key Name or Secret Key required for unpacking" 
        Write-Host "Recipient Key Name or Secret Key required for unpacking" -ForegroundColor Red
        Close-Log
        return
    } 
    if ($TransferFileName -eq "") {
            Write-Log "Transfer/Compress File Name required for unpacking" 
            Write-Host "Transfer/Compress File Name required for unpacking" -ForegroundColor Red
            Close-Log
            return
    } 
    
    if ($SecretKey -eq "") {
        if ($secretFileName -eq "")
        {
            $secretFileName = $default_secretEncrypted
        }
        $secret = Unprotect-CmsMessage -To $recipientKeyName -Path $secretFileName
    } else {
        $secret = $SecretKey
    }
    Invoke-Unpack -RestoreFolder $path -Secret $secret -CompressFile $transferFileName
    
}


if ($action -eq "ReconcileFile") {
    $actioned = $true
    if ($reconcileFileName -eq "")
    {
        $reconcileFileName = $default_reconcileFile
    }
    Set-Reconcile -ReconcileFile $reconcileFileName -FolderName $path -Feedback -RootFolderName $rootFolderName
}


if ($action -eq "Reconcile") {
    $actioned = $true
    if ($reconcileFileName -eq "")
    {
        $reconcileFileName = $default_reconcileFile
    }
    $localReconcileFile = Join-Path -Path $path -ChildPath $reconcileFileName
    Invoke-Reconcile -ReconcileFile $localReconcileFile -Folder $path
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
    Write-Host "    Install       : Install required packages"
}

Close-Log
