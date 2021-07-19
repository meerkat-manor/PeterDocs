<#
 .Synopsis
   Allows the secure transfer and reconciliation of a large number of files

   PTRfile: Protect, Transfer, Reconcile files

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
   due to possible size such as:
   * Cloud storage provider
   * HTTPS web file upload
   * SFTP transfer
   * USB stick

   At the target, unpack the contents to a folder and reconcile the results.  You
   will need write access on the target storage. A log file is written at exceution
   to record activity.

   Your bulk file transfer is encrypted in transit.  Note that if you use the
   SecretKey method the ecnrypted contents will only be as secure as the strength
   of your secret.

   You can use storage providers such as Dropbox, AWS S3, Google Drive, OneDrive or BackBlaze
   and your documents have additonal protection.

   A log file is produced on execution.  Repeated executions on the same day
   will add text content to the same log file.  The default log name takes the form:
   "ptr_files_yyyy-MM-dd.log"

   You will need to have installed the 7Zip4Powershell PowerShell cmdlet 
   before using the pack or unpack actions.  You can install the cmdlet
   by executing 
   .\ptrFiles.ps1 -Action install -Path ".\" 

   Author:  Tom Peltonen

 .Parameter Action
  Action to perform, which can be:
  - Install             : Install 7Zip4PowerShell
  - Pack                : Archive the contents of a folder(s)
  - Unpack              : Unpack the archive, but no reconfile is performed
  - Reconcile           : Reconcile the contents in the restored folder
  - ReconcileFile       : Generate reconfile file.  The pack process does this.
  - ArchiveInformation  : Fetch archive information

 .Parameter Path
  The path to the files and folders to pack or the path to the unpack location. 
  The path can include a trailing * as a wildcard to only include a subset of 
  directories.

  When using the trailing * for names, the filtering is only applied to immediate
  folder names under the parent folder.  The filter does not cascade to lower folders.

  The path can be a local drive, mapped network drive or a network shared folder
  location such as \\stora\MyLibrary.

  The Path can also be a file containing a list of paths, one per line.  To use a
  list file, prefix the Path value with a "@" and name the file. Do not use a folder
  for @ defined path.

  A file (@ prefix) containing a list of paths cannot contain generic path names, that 
  is paths with trailing wildcard of "*"

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

  Note: Currently the script doe snot user Secure Strings

 .Parameter ArchiveFileName
  The location and name of the 7ZIP file.  If not supplied a default 7ZIP file name
  will be generated in the current directory for the pack action.

  The default name will take the form ".\transfer_protect_yyyyMMdd_hhmm.7z"

  For unpack actions, the archive file name parameter is mandatory.

 .Parameter RootFolderName
  The root folder, which should be used if using wildcard (*) for the
  path.  A guess will be made as to value if not supplied, which will
  work in many circumstances.

 .Parameter FileFilter
  A filter on file names.  This does not filter directories.
  An example to only include JPEG file is "*.jpg".  You can also
  filter on picture file names starting with "IMG*.jpg"

 .Parameter ReconcileFileName
  The name of the reconfile file name to generate during pack or use 
  during unpack.  This is a file name without path.  If no value is 
  supplied, then a default name is generated.
  The reconcile file is included into the root of the 7ZIP file.
  Once a reconcile is executed, you can delete this file from the 
  restored location.

  The default name is "##protect_transfer_reconcile_files##.csv"

 .Parameter SecretFileName
  The secret file name is used with RecipientKeyName to secure the
  internally generated password for the 7ZIP file.  When unpacking the
  7ZIP file you will need access to this file if RecipientKeyName
  was used. If not supplied a default name is used.  This file is 
  encrypted with RecipientKeyName.

  The default name is the archive file name with postfix  ".key"

 .Parameter Profile
  The profile name to use for Install and Transfer actions.  The
  default for Install is "UserScope".  The default for "Transfer"
  is "default"
  Profile name can also be specifed with Environment variable 
  "PTRFILES_PROFILE"

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

  If you need to copy files from one directory to another accessible directory from
  your Windows desktop, you might consider using ROBOCOPY.  If the target directory
  is not accessible and you want to reconcile, then this tool is appropriate. 

  The following environment variables are supported:
  - PTRFILES_RECIPIENTKEYNAME
  - PTRFILES_PROFILE

 
 .Example
   # Pack and encrypt all files in folder ".\transferpack\" using a private-public key
   # A file with the postifx ".key" is also generated alongside the 7ZIP file
   .\ptrFiles.ps1 -Action pack -Path ".\transferpack\" -RecipientKeyName data@mycompany
 
 .Example
   # Unpack all files in 7ZIP file "transfer_protect_yyyMMdd_hhmm.7z" to folder ".\targetdir" using a private-public key
   # You will need the file "transfer_protect_yyyMMdd_hhmm.7z.key" to unpack the encrypted 7ZIP file
   .\ptrFiles.ps1 -Action unpack -ArchiveFileName "transfer_protect_yyyMMdd_hhmm.7z" -Path ".\targetdir" -RecipientKeyName data@mycompany
 
 .Example
   # Reconcile files in folder ".\targetdir"
   .\ptrFiles.ps1 -Action reconcile -Path ".\targetdir" 

 .Example
   # Pack and encrypt all files in folder ".\transferpack\" using a password
   .\ptrFiles.ps1 -Action pack -Path ".\transferpack\" -SecretKey "fjks932c-x=23ds"
 
 .Example
   # Unpack all files in 7ZIP file "transfer_protect_yyyMMdd_hhmm.7z" to folder ".\targetdir" using a password
   .\ptrFiles.ps1 -Action unpack -ArchiveFileName "transfer_protect_yyyMMdd_hhmm.7z" -Path ".\targetdir" -SecretKey "fjks932c-x=23ds"

 .Example
   # Pack and encrypt all files in folder ".\transferpack\02*" where the folder name starts with "02" using a password
   .\ptrFiles.ps1 -Action pack -Path ".\transferpack\02*" -SecretKey "fjks932c-x=23ds"

#>

param (
    [Parameter(Mandatory)][String] $Action, 
    [Parameter(Mandatory)][String] $Path, 
    [String] $RecipientKeyName,
    [String] $SecretKey, 
    [String] $ArchiveFileName, 
    [String] $RootFolderName,
    [String] $FileFilter,
    [String] $ReconcileFileName, 
    [String] $SecretFileName, 
    [String] $CloudProfile,
    [switch] $ExcludeHash,
    [String] $LogPath

)

$default_dateLocal = Get-Date -Format "yyyyMMdd_HHmm"
$default_archiveFile = ".\ptr_file_##date##.7z"
$default_reconcileFile = "##protect_transfer_reconcile_files##.csv"
$default_profile = "default"

function Write-Log {
    param(
        [String] $LogEntry
    )

    $date = Get-Date -f "yyyy-MM-dd"

    if ($LogPath -eq "")
    {
        $logPath = Join-Path -Path ".\" -ChildPath "Logs"
    }
    $logName = "ptr_files_$date.log"
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

function Get-SoftwareName {
    return [String] "PTRFILES"
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

function Test-FilesExist
{
    Param( 
        [Parameter(Mandatory)][String] $FolderName,
        [String] $FileFilter
    ) 

    Get-ChildItem $folderName -Recurse | Where-Object {!$_.PSIsContainer} | ForEach-Object {
        return $true
    }
    
    return $false
}

function Get-ConvenientFileSize
{
    Param( 
        [Parameter(Mandatory)][long] $Size
    ) 
 
    
    if ($totalFileSize -ge 1000000000000) {
        $totalRightLabel = "TB"
        $totalFileXbytes = [math]::Round(($size / 1000000000000), 2)        
    } else {
        if ($totalFileSize -ge 1000000000) {
            $totalRightLabel = "GB"
            $totalFileXbytes = [math]::Round(($size / 1000000000), 2)        
        } else { 
            if ($totalFileSize -ge 1000000) {
                $totalRightLabel = "MB"
                $totalFileXbytes = [math]::Round(($size / 1000000), 2)        
            } else {
                $totalRightLabel = "KB"
                $totalFileXbytes = [math]::Round(($size / 1000), 2)
            }
        }
    }

    return $totalFileXbytes.ToString() + " " + $totalRightLabel
}



function Get-B2ApiToken {
    Param
    (
        [Parameter(Mandatory)] [ValidateNotNull()] [ValidateNotNullOrEmpty()] [String] $AccountId,
        [Parameter(Mandatory)] [ValidateNotNull()] [ValidateNotNullOrEmpty()] [String] $AccountKey
    )


    Begin
    {
        if(-not $AccountID -or -not $AccountKey)
        {
            [PSCredential]$b2Creds = Get-Credential -Message 'Enter your B2 account ID and application key below.'
            try
            {
                [String]$AccountId = $b2Creds.GetNetworkCredential().UserName
                [String]$AccountKey = $b2Creds.GetNetworkCredential().Password
            }
            catch
            {
                throw 'You must specify the account ID and application key.'
            }
        }
        
        [String]$plainCreds = "${AccountId}:${AccountKey}"
        [String]$encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($plainCreds))
        [Hashtable]$sessionHeaders = @{'Authorization'="Basic $encodedCreds"}
        [Uri]$b2ApiUri = 'https://api.backblaze.com/b2api/v1/b2_authorize_account'
    }
    Process
    {
        try
        {
            $b2Info = Invoke-RestMethod -Method Get -Uri $b2ApiUri -Headers $sessionHeaders
            [String]$script:SavedB2AccountID = $b2Info.accountId
            [Uri]$script:SavedB2ApiUri = $b2Info.apiUrl
            [String]$script:SavedB2ApiToken = $b2Info.authorizationToken
            [Uri]$script:SavedB2DownloadUri = $b2Info.downloadUrl

            $b2ReturnInfo = [PSCustomObject]@{
                'AccountID' = $b2Info.accountId
                'ApiUri' = $b2Info.apiUrl
                'DownloadUri' = $b2Info.downloadUrl
                'Token' = $b2Info.authorizationToken
            }

            return $b2ReturnInfo
        }
        catch
        {
            $errorDetail = $_.Exception.Message
            Write-Error -Exception "Unable to authenticate with given APIKey.`n`r$errorDetail" `
                -Message "Unable to authenticate with given APIKey.`n`r$errorDetail" -Category AuthenticationError
        }
    }    

}


function Get-B2Bucket {
    Param
    (
        [Parameter(Mandatory)] [ValidateNotNull()] [ValidateNotNullOrEmpty()] [String] $ApiToken,
        [Parameter(Mandatory)] [ValidateNotNull()] [ValidateNotNullOrEmpty()] [String] $AccountId,
        [Parameter(Mandatory)] [ValidateNotNull()] [ValidateNotNullOrEmpty()] [String] $ApiUri,
        [Parameter(Mandatory)] [ValidateNotNull()] [ValidateNotNullOrEmpty()] [String] $BucketHost
    )

    Begin
    {
        [Hashtable]$sessionHeaders = @{'Authorization'=$ApiToken}
        [String]$sessionBody = @{'accountId'=$AccountID} | ConvertTo-Json
        [Uri]$b2ApiUri = "$ApiUri/b2api/v1/b2_list_buckets"
    }
    Process
    {
        $b2Info = Invoke-RestMethod -Method Post -Uri $b2ApiUri -Headers $sessionHeaders -Body $sessionBody
        foreach($info in $b2Info.buckets)
        {
            if ($bucketHost -eq $info.bucketName) {
                $b2ReturnInfo = [PSCustomObject]@{
                    'BucketName' = $info.bucketName
                    'BucketID' = $info.bucketId
                    'BucketType' = $info.bucketType
                    'AccountID' = $info.accountId
                }
                return $b2ReturnInfo
            }
        }

        return $null
    }

}

function Get-B2UploadUri {
    Param
    (
        [Parameter(Mandatory)] [ValidateNotNull()] [ValidateNotNullOrEmpty()] [String] $BucketHost,
        [Parameter(Mandatory)] [ValidateNotNull()] [ValidateNotNullOrEmpty()] [String] $FileName,
        [Parameter(Mandatory)] [ValidateNotNull()] [ValidateNotNullOrEmpty()] [Uri] $ApiUri,
        [Parameter(Mandatory)] [ValidateNotNull()] [ValidateNotNullOrEmpty()] [String] $ApiToken
    )

    Begin
    {
        [Hashtable]$sessionHeaders = @{'Authorization'=$ApiToken}
        [Uri]$b2ApiUri = "$ApiUri/b2api/v1/b2_get_upload_url"
    }
    Process
    {
        try
        {
            [String]$sessionBody = @{'bucketId'=$bucketHost} | ConvertTo-Json
            $b2Info = Invoke-RestMethod -Method Post -Uri $b2ApiUri -Headers $sessionHeaders -Body $sessionBody
            $b2ReturnInfo = [PSCustomObject]@{
                'BucketId' = $b2Info.BucketId
                'UploadUri' = $b2Info.uploadUrl
                'Token' = $b2Info.authorizationToken
            }

            return $b2ReturnInfo
        }
        catch
        {
            $errorDetail = $_.Exception.Message
            Write-Error -Exception "Unable to retrieve the upload uri.`n`r$errorDetail" `
                -Message "Unable to retrieve the upload uri.`n`r$errorDetail" -Category ReadError
        }
    }

}


function Invoke-B2SUpload {
    Param
    (
        [Parameter(Mandatory)] [ValidateNotNull()] [ValidateNotNullOrEmpty()] [String] $BucketHost,
        [Parameter(Mandatory)] [ValidateNotNull()] [ValidateNotNullOrEmpty()] [String] $TargetPath,
        [Parameter(Mandatory)] [ValidateNotNull()] [ValidateNotNullOrEmpty()] [String] $FileName,
        [Parameter(Mandatory)] [ValidateNotNull()] [ValidateNotNullOrEmpty()] [Uri] $ApiUri,
        [Parameter(Mandatory)] [ValidateNotNull()] [ValidateNotNullOrEmpty()] [String] $ApiToken
    )

    try
    {
        
        [String] $b2FileName = [System.Uri]::EscapeDataString($TargetPath)       
        [String] $b2FileMime = [System.Web.MimeMapping]::GetMimeMapping($fileName)        
        [String]$b2FileSHA1 = (Get-FileHash -Path $fileName -Algorithm SHA1).Hash
        [String]$b2FileAuthor = (Get-Acl -Path $fileName).Owner
        
        $b2FileAuthor = $b2FileAuthor.Substring($b2FileAuthor.IndexOf('\')+1)
        
        [Hashtable]$sessionHeaders = @{
            'Authorization' = $ApiToken
            'X-Bz-File-Name' = $b2FileName
            'Content-Type' = $b2FileMime
            'X-Bz-Content-Sha1' = $b2FileSHA1
            'X-Bz-Info-Author' = $b2FileAuthor
        }
        
        $b2Info = Invoke-RestMethod -Method Post -Uri $ApiUri -Headers $sessionHeaders -InFile $fileName
        
        $b2ReturnInfo = [PSCustomObject]@{
            'Name' = $b2Info.fileName
            'FileInfo' = $b2Info.fileInfo
            'Type' = $b2Info.contentType
            'Length' = $b2Info.contentLength
            'BucketID' = $b2Info.bucketId
            'AccountID' = $b2Info.accountId
            'SHA1' = $b2Info.contentSha1
            'ID' = $b2Info.fileId
        }
        
        return $b2ReturnInfo 
    }
    catch
    {
        $errorDetail = $_.Exception.Message
        Write-Error -Exception "Unable to upload the file.`n`r$errorDetail" `
            -Message "Unable to upload the file.`n`r$errorDetail" -Category InvalidOperation
    }



}



function Invoke-B2SDownload {
    Param
    (
        [Parameter(Mandatory)] [ValidateNotNull()] [ValidateNotNullOrEmpty()] [String] $BucketHost,
        [Parameter(Mandatory)] [ValidateNotNull()] [ValidateNotNullOrEmpty()] [String] $SourcePath,
        [Parameter(Mandatory)] [ValidateNotNull()] [ValidateNotNullOrEmpty()] [String] $FileName,
        [Parameter(Mandatory)] [ValidateNotNull()] [ValidateNotNullOrEmpty()] [Uri] $ApiDownloadUri,
        [Parameter(Mandatory)] [ValidateNotNull()] [ValidateNotNullOrEmpty()] [String] $ApiToken
    )

    Begin
    {
        if(-not (Test-Path -Path $FileName -IsValid))
        {
            throw 'The file path given ($FileName) is not valid.`n`rThe file cannot be saved.'
        }
        [Hashtable]$sessionHeaders = @{'Authorization'=$ApiToken}
    }
    Process
    {
        [Uri]$b2ApiUri = "${ApiDownloadUri}file/$BucketHost/$SourcePath"
            try
            {
                Invoke-RestMethod -Method Get -Uri $b2ApiUri -Headers $sessionHeaders -OutFile $FileName
            }
            catch
            {
                $errorDetail = $_.Exception.Message
                Write-Error -Exception "Unable to upload the file.`n`r$errorDetail" `
                    -Message "Unable to upload the file.`n`r$errorDetail" -Category InvalidOperation
            }
    }

}

# ==============================================================================


# Reconcile
function Set-Reconcile
{
Param( 
    [Parameter(Mandatory)][String] $ReconcileFile,
    [Parameter(Mandatory)][String] $FolderName,
    [String] $RootFolderName,
    [String] $FileFilter,
    [switch] $Feedback = $false
) 

    if ($reconcileFile -eq "")
    {
        $reconcileFile = $default_reconcileFile
    }

    if ($folderName.StartsWith("@")) {
        If (!(Test-Path -Path $folderName.Substring(1) )) {    
            Write-Log "File '$($folderName.Substring(1))' does not exist"
            Write-Host "File '$($folderName.Substring(1))' does not exist" -ForegroundColor Red
            Close-Log
            Exit
        }
    } else {
        If (!(Test-Path -Path $folderName )) {    
            Write-Log "Folder '$folderName' does not exist"
            Write-Host "Folder '$folderName' does not exist" -ForegroundColor Red
            Close-Log
            Exit
        }
    }

    Write-Log "Generating reconciliation file '$reconcileFile'"
    Write-Host "Generating reconciliation file '$reconcileFile'"
    
    $totalFileCount = 0
    $totalFileSize = 0

    if ($rootFolderName -eq "") {
        $rootFolderName = $folderName
    }
    if ($ExcludeHash) {
        $messageFrequency = 1000
    } else {
        $messageFrequency = 500
    }


    Set-Content -Path $reconcileFile  -Value '"FullName","LastWriteTime","CreationTime","LastAccessTime","Length","Hash","ParentFolder","Object","Attributes","Extension"'

    if ($folderName.StartsWith("@")) {
        Write-Log "Using @ file '$($folderName.Substring(1))'"
        Write-Host "Using @ file '$($folderName.Substring(1))'"

        Get-Content -Path $($folderName.Substring(1)) | ForEach-Object {
            if ($_ -ne "") {
                If (!(Test-Path -Path $_ )) {    
                    Write-Log "Folder/file '$($_)' does not exist"
                    Write-Host "Folder/file '$($_)' does not exist" -ForegroundColor Red
                }
                else {
                    Get-ChildItem $_ -Filter $fileFilter -Recurse | Where-Object {!$_.PSIsContainer} | ForEach-Object {

                        $totalFilecount = $totalFileCount + 1
                        $totalFileSize = $totalFileSize + $_.Length 
            
                        if (($totalFilecount % $messageFrequency) -eq 0) {            
                            Write-Log "Read $totalFileCount files and size $(Get-ConvenientFileSize -Size $totalFileSize ).  Currently at folder '$($_.Directory)' " 
                            Write-Host "Read $totalFileCount files and size $(Get-ConvenientFileSize -Size $totalFileSize ).  Currently at folder '$($_.Directory)' " 
                        }
            
                        if ($ExcludeHash) {
                            $sourceHash = ""
                        } else {
                            $sourceHash = (Get-FileHash -Path $_.FullName).Hash
                        }
                        $record = '"'+$_.FullName.Replace($rootFolderName, "")+'","'+$_.LastWriteTime.ToString("yyyy-MM-ddTHH:mm:ss")+'"'
                        $record = $record + ',"'+$_.CreationTime.ToString("yyyy-MM-ddTHH:mm:ss")+'","'+$_.LastAccessTime.ToString("yyyy-MM-ddTHH:mm:ss")+'"'
                        $record = $record + ','+$_.Length+',"'+$sourceHash+'","'+ $_.Directory + '","' + $_.Name + '","' + $_.Attributes+'","'+$_.Extension+'"'
                        Add-Content -Path  $reconcileFile  -Value $record
                    
                    }
                }
            }
        }

    } else {
        Get-ChildItem $folderName -Filter $fileFilter -Recurse | Where-Object {!$_.PSIsContainer} | ForEach-Object {

            $totalFilecount = $totalFileCount + 1
            $totalFileSize = $totalFileSize + $_.Length 

            if (($totalFilecount % $messageFrequency) -eq 0) {            
                Write-Log "Read $totalFileCount files and size $(Get-ConvenientFileSize -Size $totalFileSize ).  Currently at folder '$($_.Directory)' " 
                Write-Host "Read $totalFileCount files and size $(Get-ConvenientFileSize -Size $totalFileSize ).  Currently at folder '$($_.Directory)' " 
            }

            if ($ExcludeHash) {
                $sourceHash = ""
            } else {
                $sourceHash = (Get-FileHash -Path $_.FullName).Hash
            }
            $record = '"'+$_.FullName.Replace($rootFolderName, "")+'","'+$_.LastWriteTime.ToString("yyyy-MM-ddTHH:mm:ss")+'"'
            $record = $record + ',"'+$_.CreationTime.ToString("yyyy-MM-ddTHH:mm:ss")+'","'+$_.LastAccessTime.ToString("yyyy-MM-ddTHH:mm:ss")+'"'
            $record = $record + ','+$_.Length+',"'+$sourceHash+'","'+ $_.Directory + '","' + $_.Name + '","' + $_.Attributes+'","'+$_.Extension+'"'
            Add-Content -Path  $reconcileFile  -Value $record
        
        }

    }

    Write-Log "Total reconcile file count is $totalFileCount and size $(Get-ConvenientFileSize -Size $totalFileSize ) ($totalFileSize)"
    if ($feedback) {
        Write-Host "Total reconcile file count is $totalFileCount and size $(Get-ConvenientFileSize -Size $totalFileSize )" -ForegroundColor Green
    }
}

function Invoke-SinglePack
{
    Param( 
        [Parameter(Mandatory)][String] $ArchiveFolder,
        [Parameter(Mandatory)][String] $ArchiveFile,
        [String] $FileFilter,
        [Boolean] $FirstCompress
    ) 

    if (!(Test-Path -Path $ArchiveFolder -PathType Leaf)) {
        Write-Log "Archive folder '$ArchiveFolder'"
        Write-Host "Archivefolder '$ArchiveFolder'"
    }
    if (Test-FilesExist -FolderName $ArchiveFolder -FileFilter $FileFilter) {
        try {
            if ($FirstCompress) {
                Compress-7Zip -Path $ArchiveFolder -ArchiveFileName $ArchiveFile -Format SevenZip -PreserveDirectoryRoot -Filter $FileFilter   
            } else {
                Compress-7Zip -Path $ArchiveFolder -ArchiveFileName $ArchiveFile -Format SevenZip -PreserveDirectoryRoot -Filter $FileFilter -Append    
            }
            $FirstCompress = $false
        } catch {
            Write-Log "Compress error with folder/file '$ArchiveFolder'.  See any previous errors.  $Error"
            Write-Host "Compress error with folder/file '$ArchiveFolder'.  See any previous errors.  $Error" -ForegroundColor Red
        }
    } else {
        Write-Log "Empty folder/file '$ArchiveFolder'"
        Write-Host "Empty folder/file '$ArchiveFolder'"
    }

    return $FirstCompress
}


# Compress / Package
function Invoke-Pack
{
Param( 
    [Parameter(Mandatory)][String] $TransferFolder,
    [String] $RootFolder,
    [String] $FileFilter,
    [Parameter(Mandatory)][String] $Secret,
    [Parameter(Mandatory)][String] $CompressFile,
    [String] $ReconcileFile
) 

    if ($transferFolder.StartsWith("@")) {
        If (!(Test-Path -Path $transferFolder.Substring(1) )) {    
            Write-Log "File '$($transferFolder.Substring(1))' does not exist"
            Write-Host "File '$($transferFolder.Substring(1))' does not exist" -ForegroundColor Red
            Close-Log
            Exit
        }
    } else {
        If (!(Test-Path -Path $transferFolder )) {    
            Write-Log "Folder '$transferFolder' does not exist"
            Write-Host "Folder '$transferFolder' does not exist" -ForegroundColor Red
            Close-Log
            Exit
        }
    }

    Write-Log "Saving folders/files to archive file '$compressFile'"
    Write-Host "Saving folders/files to archive file '$compressFile'"

    if ($reconcileFile -eq "")
    {
        $reconcileFile = $default_reconcileFile
    }

    if ($fileFilter -eq "")
    {
        $fileFilter = "*"
    }

    if ($transferFolder.EndsWith("*"))
    {
        Write-Log "Archive primary folder is '$transferFolder'"
        $firstCompress = $true
        Get-ChildItem $transferFolder| ForEach-Object {
            $firstCompress = Invoke-SinglePack -ArchiveFolder $_.FullName -ArchiveFile $compressFile -FileFilter $fileFilter -FirstCompress $firstCompress
        }
    } else {
        if ($transferFolder.StartsWith("@")) {
            Write-Log "Using @ file '$($transferFolder.Substring(1))'"
            Write-Host "Using @ file '$($transferFolder.Substring(1))'"
            $firstCompress = $true

            Get-Content -Path $($transferFolder.Substring(1)) | ForEach-Object {
                if ($_ -ne "") {

                    if ($_.EndsWith("*")) {
                        Get-ChildItem $_ | ForEach-Object {
                            $firstCompress = Invoke-SinglePack -ArchiveFolder $_.FullName -ArchiveFile $compressFile -FileFilter $fileFilter -FirstCompress $firstCompress
                        }
                    } else {
                
                        If (!(Test-Path -Path $_ )) {    
                            Write-Log "Folder/file '$($_)' does not exist"
                            Write-Host "Folder/file '$($_)' does not exist" -ForegroundColor Red
                        }
                        else {
                            $firstCompress = Invoke-SinglePack -ArchiveFolder $_ -ArchiveFile $compressFile -FileFilter $fileFilter -FirstCompress $firstCompress
                        }
                    }
                }
            }
        } else {
            Write-Log "Archive folder '$transferFolder'"
            Write-Host "Archive folder '$transferFolder'"
            Compress-7Zip -Path $transferFolder -ArchiveFileName $compressFile -Format SevenZip -Filter $fileFilter    
        }
    }

    If (!(Test-Path -Path $compressFile )) {    
        Write-Log "Archive file '$compressFile' was not created.  See any previous errors"
        Write-Host "Archive file '$compressFile' was not created.  See any previous errors" -ForegroundColor Red
        Close-Log
        Exit
    }

    Set-Reconcile -ReconcileFile $reconcileFile -FolderName $transferFolder -FileFilter $fileFilter -RootFolderName $rootFolder
    If (!(Test-Path -Path $reconcileFile )) {    
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

    Write-Log "Archive file '$compressFile' created from folder '$transferFolder'"
    Write-Host "Archive file '$compressFile' created from folder '$transferFolder'"  -ForegroundColor Green
}


# Send package
function Invoke-PutArchive
{
Param( 
    [Parameter(Mandatory)][String] $CompressFile,
    [Parameter(Mandatory)][String] $TargetPath,
    [String] $SecretFile,
    [String] $TargetProfile,
    [String] $AccountId,
    [String] $AccountKey
) 

    if ($compressFile -eq "") {
        Write-Log "Archive file name required" 
        Write-Host "Archive file name required"  -ForegroundColor Red
        Close-Log
        return
    }

    if ($targetProfile -eq "") {
        $getEnvName = $(Get-SoftwareName) + "_PROFILE"
        if ([System.Environment]::GetEnvironmentVariable($getEnvName) -ne "" -and $null -ne [System.Environment]::GetEnvironmentVariable($getEnvName)) {
            $targetProfile = [System.Environment]::GetEnvironmentVariable($getEnvName)
        } 
        if ($null -eq $targetProfile -or $targetProfile -eq "") {
            $targetProfile = $default_profile
        }
    }

    if (!(Test-Path -Path $compressFile )) {
        Write-Log "Archive file '$compressFile' not found"
        Write-Host "Archive file '$compressFile' not found"  -ForegroundColor Red
        Close-Log
        return
    }
    if ($secretFile -eq "") {
        $secretFile = $compressFile + ".key"
    }

    $remoteType = $false

    if ($targetPath.StartsWith("s3://")) {
        $remoteType = $true

        [int] $offset = "s3://".Length
        $parts = $targetPath.Substring($offset).Split("/")
        $bucketHost = $parts[0]
        $offset = $offset + $bucketHost.Length + 1

        if ($bucketHost -eq "") {
            Write-Log "Bucket name required" 
            Write-Host "Bucket name required"  -ForegroundColor Red
            Close-Log
            return
        }

        Set-AWSCredential -ProfileName $targetProfile

        $targetObject = $targetPath.Substring($offset)
        Write-Log "Transferring '$compressFile' file to host '$bucketHost' folder '$targetObject'"
        Write-Host "Transferring '$compressFile' file to host '$bucketHost' folder '$targetObject'"
        Write-S3Object -BucketName $bucketHost -File $compressFile -Key $targetObject
        if (Test-Path -Path $secretFile) {
            $targetObject = $targetPath.Substring($offset) + ".key"
            Write-Log "Transferring '$secretFile' file to host '$bucketHost' folder '$targetObject'"
            Write-Host "Transferring '$secretFile' file to host '$bucketHost' folder '$targetObject'"
            Write-S3Object -BucketName $bucketName -File $secretFile -Key $targetObject 
        }
        $targetObject = $targetPath.Substring($offset)
        Write-Log "Archive file '$compressFile' stored on S3 bucket '$bucketHost' at '$targetObject'"
        Write-Host "Archive file '$compressFile' stored on S3 bucket '$bucketHost' at '$targetObject'" -ForegroundColor Green

    }



    if ($targetPath.StartsWith("b2://")) {
        $remoteType = $true

        [int] $offset = "b2://".Length
        $parts = $targetPath.Substring($offset).Split("/")
        $bucketHost = $parts[0]
        $offset = $offset + $bucketHost.Length + 1

        if ($null -eq $accountId -or $accountId -eq "") {
            $accountId = $targetProfile
        }

        if ($accountKey -eq "") {
            $getEnvName = $(Get-SoftwareName) + "_ACCOUNTKEY"
            if ([System.Environment]::GetEnvironmentVariable($getEnvName) -ne "" -and $null -ne [System.Environment]::GetEnvironmentVariable($getEnvName)) {
                $accountKey = [System.Environment]::GetEnvironmentVariable($getEnvName)
            } 
            if ($null -eq $accountKey -or $accountKey -eq "") {
                Write-Log "Account key required" 
                Write-Host "Account key required"  -ForegroundColor Red
                Close-Log
                return
            }
        }

        $b2ApiToken = Get-B2ApiToken -AccountId $accountId -AccountKey $accountKey

        $b2Bucket = Get-B2Bucket -ApiToken $b2ApiToken.Token -AccountId $b2ApiToken.accountId -ApiUri $b2ApiToken.ApiUri -BucketHost $bucketHost
        if ($null -eq $b2Bucket -or $b2Bucket.BucketID -eq "") {
            Write-Log "Bucket '$bucketHost' not found" 
            Write-Host "Bucket '$bucketHost' not found" -ForegroundColor Red
            Close-Log
            return
        }

        $b2UploadUri = Get-B2UploadUri -BucketHost $b2Bucket.bucketId -FileName $compressFile -ApiUri $b2ApiToken.ApiUri -ApiToken $b2ApiToken.Token 
        $targetObject = $targetPath.Substring($offset)
        Write-Log "Transferring '$compressFile' file to host '$bucketHost' folder '$targetObject'"
        Write-Host "Transferring '$compressFile' file to host '$bucketHost' folder '$targetObject'"
        $b2Upload = Invoke-B2SUpload -BucketHost $b2UploadUri.bucketId -TargetPath $targetObject  -FileName $compressFile -ApiUri $b2UploadUri.uploadUri -ApiToken $b2UploadUri.Token
        Write-Log "Upload: $b2Upload"
        if (Test-Path -Path $secretFile) {
            $targetObject = $targetPath.Substring($offset) + ".key"
            Write-Log "Transferring '$secretFile' file to host '$bucketHost' folder '$targetObject'"
            Write-Host "Transferring '$secretFile' file to host '$bucketHost' folder '$targetObject'"
            $b2Upload = Invoke-B2SUpload -BucketHost $b2UploadUri.bucketId -TargetPath $targetObject  -FileName $secretFile -ApiUri $b2UploadUri.uploadUri -ApiToken $b2UploadUri.Token
            Write-Log "Upload: $b2Upload"
        }
        $targetObject = $targetPath.Substring($offset)
        Write-Log "Archive file '$compressFile' stored on Backblaze bucket '$bucketHost' at '$targetObject'"
        Write-Host "Archive file '$compressFile' stored on Backblaze bucket '$bucketHost' at '$targetObject'" -ForegroundColor Green

    }

    if (!($remoteType)) {
        Write-Log "Unknown remote path '$targetFolder.'.  No transfer performed" 
        Write-Host "Unknown remote path '$targetFolder.'.  No transfer performed"  -ForegroundColor Red
        Write-Host "Recognised transfer prefixes: "
        Write-Host "    s3://         : Send to S3 compatible location"
        Write-Host " "    
        Write-Host "If you are saving to local drives or network shared folders,"    
        Write-Host "please use your OS tools to move the file"    
    Write-Host " "    
    }


}


# Receive package
function Invoke-GetArchive
{
Param( 
    [Parameter(Mandatory)][String] $CompressFile,
    [Parameter(Mandatory)][String] $SourcePath,
    [String] $SecretFile,
    [String] $SourceProfile,
    [String] $AccountId,
    [String] $AccountKey
) 
    
        if ($compressFile -eq "") {
            Write-Log "Archive file name required" 
            Write-Host "Archive file name required"  -ForegroundColor Red
            Close-Log
            return
        }
    
        if ($sourceProfile -eq "") {
            $getEnvName = $(Get-SoftwareName) + "_PROFILE"
            if ([System.Environment]::GetEnvironmentVariable($getEnvName) -ne "" -and $null -ne [System.Environment]::GetEnvironmentVariable($getEnvName)) {
                $sourceProfile = [System.Environment]::GetEnvironmentVariable($getEnvName)
            } 
            if ($null -eq $sourceProfile -or $sourceProfile -eq "") {
                $sourceProfile = $default_profile
            }
        }
    
    
        $remoteType = $false
    
        if ($sourcePath.StartsWith("s3://")) {
            $remoteType = $true

            [int] $offset = "s3://".Length
            $parts = $sourcePath.Substring($offset).Split("/")
            $bucketHost = $parts[0]
            $offset = $offset + $bucketHost.Length + 1

            Set-AWSCredential -ProfileName $sourceProfile
    
            $sourceObject = $sourcePath.Substring($offset)
            Write-Log "Fetching '$compressFile' file from host $bucketHost folder $sourceObject"
            Write-Host "Fetching '$compressFile' file from host $bucketHost folder $sourceObject"
            $null = Read-S3Object -BucketName $bucketHost -File $compressFile -Key $sourceObject
            if (!(Test-Path -Path $compressFile)) {
                Write-Log "Archive file '$sourceObject' not found." 
                Write-Host "Archive file '$sourceObject' not found."  -ForegroundColor Red
            } else {
                $sourceObject = $sourcePath.Substring($offset) + ".key"
                $secretFile = $compressFile + ".key"
                Write-Log "Fetching '$secretFile' file from host '$bucketHost' folder '$sourceObject'"
                Write-Host "Fetching '$secretFile' file from host '$bucketHost' folder '$sourceObject'"
                $null = Read-S3Object -BucketName $bucketHost -File $secretFile -Key $sourceObject 
                if (!(Test-Path -Path $secretFile)) {
                    Write-Log "Secret file '$sourceObject' not found. Required if you are using recipient keys" 
                    Write-Host "Secret file '$sourceObject' not found. Required if you are using recipient keys" 
                }
                $sourceObject = $sourcePath.Substring($offset)
                Write-Log "Archive file '$compressFile' fetched from S3 '$sourcePath'"
                Write-Host "Archive file '$compressFile' fetched from S3 '$sourcePath'" -ForegroundColor Green
            }
    
        }
    

    
        if ($sourcePath.StartsWith("b2://")) {
            $remoteType = $true

            [int] $offset = "b2://".Length
            $parts = $sourcePath.Substring($offset).Split("/")
            $bucketHost = $parts[0]
            $offset = $offset + $bucketHost.Length + 1

            if ($null -eq $accountId -or $accountId -eq "") {
                $accountId = $sourceProfile
            }
    
            if ($accountKey -eq "") {
                $getEnvName = $(Get-SoftwareName) + "_ACCOUNTKEY"
                if ([System.Environment]::GetEnvironmentVariable($getEnvName) -ne "" -and $null -ne [System.Environment]::GetEnvironmentVariable($getEnvName)) {
                    $accountKey = [System.Environment]::GetEnvironmentVariable($getEnvName)
                } 
                if ($null -eq $accountKey -or $accountKey -eq "") {
                    Write-Log "Account key required" 
                    Write-Host "Account key required"  -ForegroundColor Red
                    Close-Log
                    return
                }
            }
    
            $b2ApiToken = Get-B2ApiToken -AccountId $accountId -AccountKey $accountKey

            $b2Bucket = Get-B2Bucket -ApiToken $b2ApiToken.Token -AccountId $b2ApiToken.accountId -ApiUri $b2ApiToken.ApiUri -BucketHost $bucketHost
            if ($null -eq $b2Bucket -or $b2Bucket.BucketID -eq "") {
                Write-Log "Bucket '$bucketHost' not found" 
                Write-Host "Bucket '$bucketHost' not found" -ForegroundColor Red
                Close-Log
                return
            }
    
            $sourceObject = $sourcePath.Substring($offset)
            Write-Log "Fetching '$compressFile' file from host '$bucketHost' folder '$sourceObject'"
            Write-Host "Fetching '$compressFile' file from host '$bucketHost' folder '$sourceObject'"
            Invoke-B2SDownload -BucketHost $bucketHost -SourcePath $sourceObject -FileName $compressFile -ApiDownloadUri $b2ApiToken.DownloadUri -ApiToken $b2ApiToken.Token
            if (!(Test-Path -Path $compressFile)) {
                Write-Log "Archive file '$sourceObject' not found." 
                Write-Host "Archive file '$sourceObject' not found."  -ForegroundColor Red
            } else {
                $sourceObject = $sourcePath.Substring($offset) + ".key"
                $secretFile = $compressFile + ".key"
                Write-Log "Fetching '$secretFile' file from host '$bucketHost' folder '$sourceObject'"
                Write-Host "Fetching '$secretFile' file from host '$bucketHost' folder '$sourceObject'"
                Invoke-B2SDownload -BucketHost $bucketHost -SourcePath $sourceObject -FileName $secretFile -ApiDownloadUri $b2ApiToken.DownloadUri -ApiToken $b2ApiToken.Token
                if (!(Test-Path -Path $secretFile)) {
                    Write-Log "Secret file '$sourceObject' not found. Required if you are using recipient keys" 
                    Write-Host "Secret file '$sourceObject' not found. Required if you are using recipient keys" 
                }
                $sourceObject = $sourcePath.Substring($offset)
                Write-Log "Archive file '$compressFile' fetched from Backblaze '$sourcePath'"
                Write-Host "Archive file '$compressFile' fetched from Backblaze '$sourcePath'" -ForegroundColor Green
            }
        
        }


        if (!($remoteType)) {
            Write-Log "Unknown remote path '$sourcePath'.  No get performed" 
            Write-Host "Unknown remote path '$sourcePath'.  No get performed"  -ForegroundColor Red
            Write-Host "Recognised transfer prefixes: "
            Write-Host "    s3://bucket/path/path     : Fetch from S3 compatible location"
            Write-Host "    b2://bucket/path/path     : Fetch from Backblaze location"
            Write-Host " "    
            Write-Host "If you are fetching from local drives or network shared folders,"    
            Write-Host "please use your OS tools to move the file"    
            Write-Host " "    
        }
    

}


# Unpack package
function Invoke-Unpack
{
Param( 
    [Parameter(Mandatory)][String] $RestoreFolder,
    [Parameter(Mandatory)][String] $Secret,
    [Parameter(Mandatory)][String] $CompressFile
) 

    If (!(Test-Path -Path $CompressFile )) {    
        Write-Log "Archive file '$CompressFile' does not exist"
        Write-Host "Archive file '$CompressFile' does not exist" -ForegroundColor Red
        Close-Log
        Exit
    }

    Write-Log "Restoring files transferred to '$restoreFolder'"
    Write-Log "Archive file is '$compressFile'"

    # Uncompress the data files
    Expand-7Zip -ArchiveFileName $compressFile -TargetPath $restoreFolder -Password $secret
    Write-Log "Contents unpacked from archive file '$compressFile' to folder '$restoreFolder'"
    Write-Host "Contents unpacked from archive file '$compressFile' to folder '$restoreFolder'" -ForegroundColor Green
}


# Reconcile
function Invoke-Reconcile
{
Param( 
    [Parameter(Mandatory)][String] $ReconcileFile,
    [Parameter(Mandatory)][String] $Folder,
    [String] $TargetReconcileFile,
    [String] $RootFolder,
    [Switch] $ExtendedCheck
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
    $errorCreateCount = 0
    $missingFileCount = 0
    $missingHash = $false

    # For each entry in the reconcile file
    #     find the file and compare hash
    Import-Csv $reconcileFile | ForEach-Object {
        $totalFileCount = $totalFileCount +1 
        if ($rootFolder -ne "") {
            $adjustedName = $_.FullName.Replace($rootFolder, "\")
            $restoreFileName = $(Join-Path -Path $folder -ChildPath $adjustedName)    
        } else {
            $restoreFileName = $(Join-Path -Path $folder -ChildPath $_.FullName)    
        }
        If (Test-Path -Path $restoreFileName ) {    
            if ($_.Hash -ne "") {
                $targetHash= (Get-FileHash -Path $restoreFileName).Hash
                if ($_.Hash -ne $targetHash) {
                    $errorCount = $errorCount + 1
                    Write-Log "Hash mismatch for file '$restoreFileName' with target value $targetHash"
                }
            } else {
                $missingHash = $true
            }
            if ((Get-Item -Path $restoreFileName).CreationTime.ToString("yyyy-MM-ddTHH:mm:ss") -ne $_.CreationTime) {
                Write-Log "Creation mismatch for file '$restoreFileName' with target value $((Get-Item -Path $restoreFileName).CreationTime.ToString("yyyy-MM-ddTHH:mm:ss"))"
                $errorCreateCount = $errorCreateCount + 1

                $dateTimeValue = [Datetime]::ParseExact($_.CreationTime, 'yyyy-MM-ddTHH:mm:ss', $null)
                $fileValue = (Get-Item -Path $restoreFileName).CreationTime
                $diff = ($dateTimeValue - $fileValue).Seconds
                # Allow +/- 2 second discrepancy
                if (($diff.Seconds -lt -2) -or ($diff.Seconds -gt 2)) {
                    $errorCount = $errorCount + 1
                }
            }
            if ((Get-Item -Path $restoreFileName).Length -ne $_.Length) {
                $errorCount = $errorCount + 1
                Write-Log "Length mismatch for file '$restoreFileName' with target value $(Get-Item -Path $restoreFileName).Length)"
            }

            # Note that last / write access time is not checked by default as it will comonly be changed after restore
            if ($extendedCheck) {
                if ((Get-Item -Path $restoreFileName).LastAccessTime.ToString("yyyy-MM-ddTHH:mm:ss") -ne $_.LastAccessTime) {
                    $errorCount = $errorCount + 1
                    Write-Log "Last access mismatch for file '$restoreFileName' with target value $((Get-Item -Path $restoreFileName).LastAccessTime.ToString("yyyy-MM-ddTHH:mm:ss"))"
                }
                if ((Get-Item -Path $restoreFileName).LastWriteTime.ToString("yyyy-MM-ddTHH:mm:ss") -ne $_.LastWriteTime) {
                    $errorCount = $errorCount + 1
                    Write-Log "Last write mismatch for file '$restoreFileName' with target value $((Get-Item -Path $restoreFileName).LastWriteTime.ToString("yyyy-MM-ddTHH:mm:ss"))"
                }
            }

            $totalFileSize = $totalFileSize + (Get-Item -Path $restoreFileName).Length             
        } else {
            $missingFileCount = $missingFileCount + 1
            $errorCount = $errorCount + 1
            Write-Log "Non existant target file '$restoreFileName'"
        }
    }

    Write-Log "Total file storage size is $(Get-ConvenientFileSize -Size $totalFileSize ) ($totalFileSize)"
    Write-Host "Total file storage size is $(Get-ConvenientFileSize -Size $totalFileSize )"

    if ($missingHash)
    {
        Write-Log "Reconcile file had one or many or all blank hash entries"
        Write-Host "Reconcile file had one or many or all blank hash entries"  -ForegroundColor Yellow
    }

    Write-Log "Total file count is $totalFileCount with $errorCount errors"
    Write-Log "There are $missingFileCount missing files"

    if ($errorCreateCount -gt 0) {
        Write-Log "File create mismatch count is $errorCreateCount" 
        Write-Host "File create mismatch count is $errorCreateCount" -ForegroundColor Red
    }

    if ($errorCount -gt 0) {
        Write-Host "Total file count is $totalFileCount with $errorCount errors" -ForegroundColor Red
    } else {
        Write-Host "Total file count is $totalFileCount with $errorCount errors"  -ForegroundColor Green
    }
    if ($missingFileCount -gt 0) {
        Write-Host "There are $missingFileCount missing files" -ForegroundColor Red
    }
}


# Main code logic starts here
function Invoke-Main {
    
    $actioned = $false

    if ($action -eq "Install") {
        $actioned = $true
        if ($cloudProfile -eq "") {
            Install-Module -Name 7Zip4Powershell -Scope CurrentUser
            Install-Module -Name AWS.Tools.Installer -Scope CurrentUser
            Install-Module -Name AWS.Tools.S3  -Scope CurrentUser    
        } else {
            Install-Module -Name 7Zip4Powershell -Scope $cloudProfile
            Install-Module -Name AWS.Tools.Installer -Scope $cloudProfile
            Install-Module -Name AWS.Tools.S3  -Scope $cloudProfile
        }
    }

    if ($action -eq "Pack") {
        $actioned = $true

        if ($RecipientKeyName -eq "") {
            $getEnvName = $(Get-SoftwareName) + "_RECIPIENTKEYNAME"
            if ([System.Environment]::GetEnvironmentVariable($getEnvName) -ne "" -and $null -ne [System.Environment]::GetEnvironmentVariable($getEnvName)) {
                $RecipientKeyName = [System.Environment]::GetEnvironmentVariable($getEnvName)
            }
        }

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

        if ($ArchiveFileName -eq "") {
            $ArchiveFileName = $default_archiveFile.Replace("##date##", $default_dateLocal)
        }

        if ($SecretKey -eq "") {
            if ($secretFileName -eq "")
            {
                $secretFileName = $ArchiveFileName + ".key"
            }
            $secret = New-RandomPassword -Length 80
            Protect-CmsMessage -To $recipientKeyName -OutFile $secretFileName -Content $secret 
        } else {
            $secret = $SecretKey
        }

        Invoke-Pack -TransferFolder $path -Secret $secret -CompressFile $ArchiveFileName -ReconcileFile $reconcileFileName -RootFolder $rootFolderName -FileFilter $fileFilter
    }


    if ($action -eq "Put") {
        $actioned = $true
        
        if ($ArchiveFileName -eq "") {
            Write-Log "Archive file name required" 
            Write-Host "Archive file name required"  -ForegroundColor Red
            Close-Log
            return
        }

        if (!(Test-Path -Path $ArchiveFileName )) {
            Write-Log "Archive file '$ArchiveFileName' not found"
            Write-Host "Archive file '$ArchiveFileName' not found"  -ForegroundColor Red
            Close-Log
            return
        }

        Invoke-PutArchive -CompressFile $archiveFileName -TargetPath $path -SecretFile $secretFileName -TargetProfile $cloudProfile
    }


    if ($action -eq "Get") {
        $actioned = $true
        
        if ($ArchiveFileName -eq "") {
            Write-Log "Archive file name required" 
            Write-Host "Archive file name required"  -ForegroundColor Red
            Close-Log
            return
        }
        
        Invoke-GetArchive -CompressFile $archiveFileName -SourcePath $path -SecretFile $secretFileName -SourceProfile $cloudProfile
    }


    if ($action -eq "Unpack") {
        $actioned = $true

        if ($RecipientKeyName -eq "") {
            $getEnvName = $(Get-SoftwareName) + "_RECIPIENTKEYNAME"
            if ([System.Environment]::GetEnvironmentVariable($getEnvName) -ne "" -and $null -ne [System.Environment]::GetEnvironmentVariable($getEnvName)) {
                $RecipientKeyName = [System.Environment]::GetEnvironmentVariable($getEnvName)
            }
        }

        if (($RecipientKeyName -eq "") -and ($SecretKey -eq "")) {
            Write-Log "Recipient Key Name or Secret Key required for unpacking" 
            Write-Host "Recipient Key Name or Secret Key required for unpacking" -ForegroundColor Red
            Close-Log
            return
        } 
        if ($ArchiveFileName -eq "") {
                Write-Log "Archive file Name required for unpacking" 
                Write-Host "Archive file Name required for unpacking" -ForegroundColor Red
                Close-Log
                return
        } 
        
        if ($SecretKey -eq "") {
            if ($secretFileName -eq "")
            {
                $secretFileName = $ArchiveFileName + ".key"
            }
            $secret = Unprotect-CmsMessage -To $recipientKeyName -Path $secretFileName
        } else {
            $secret = $SecretKey
        }
        Invoke-Unpack -RestoreFolder $path -Secret $secret -CompressFile $ArchiveFileName
        
    }


    if ($action -eq "ReconcileFile") {
        $actioned = $true
        if ($reconcileFileName -eq "")
        {
            $reconcileFileName = $default_reconcileFile
        }
        Set-Reconcile -ReconcileFile $reconcileFileName -FolderName $path -Feedback -RootFolderName $rootFolderName -FileFilter $fileFilter
    }


    if ($action -eq "Reconcile") {
        $actioned = $true
        if ($reconcileFileName -eq "")
        {
            $reconcileFileName = $default_reconcileFile
        }
        $localReconcileFile = Join-Path -Path $path -ChildPath $reconcileFileName
        Invoke-Reconcile -ReconcileFile $localReconcileFile -Folder $path -RootFolder $rootFolderName
    }

    if ($action -eq "ArchiveInformation") {
        $actioned = $true
        if (($RecipientKeyName -eq "") -and ($SecretKey -eq "")) {
            Write-Log "Recipient Key Name or Secret Key required for 7Zip information" 
            Write-Host "Recipient Key Name or Secret Key required for 7Zip information"  -ForegroundColor Red
            Close-Log
            return
        } 
        
        if ($SecretKey -eq "") {
            if ($secretFileName -eq "")
            {
                $secretFileName = $ArchiveFileName + ".key"
            }
            $secret = Unprotect-CmsMessage -To $recipientKeyName -Path $secretFileName
        } else {
            $secret = $SecretKey
        }
        Write-Log "Retrieving archive information"
        Write-Host "Retrieving archive information"
        
        Get-7ZipInformation -ArchiveFileName $ArchiveFileName -Password $secret
    }


    if ($action -eq "MakeCert") {
        $actioned = $true
        if (($RecipientKeyName -eq "") -and ($SecretKey -eq "")) {
            Write-Log "Recipient Key Name required to create a standard certificate" 
            Write-Host "Recipient Key Name required to create a standard certificate"  -ForegroundColor Red
            Close-Log
            return
        } 
        if ($Path -ne "Cert:\CurrentUser\My") {
            Write-Log "The -Path value needs to be 'Cert:\CurrentUser\My'" 
            Write-Host "The -Path value needs to be 'Cert:\CurrentUser\My'"  -ForegroundColor Red
            Close-Log
            return
        } 

        Write-Log "Making a file encryption certificate"
        Write-Host "Making a file encryption certificate"
        
        New-SelfSignedCertificate -Subject $RecipientKeyName -KeyFriendlyName $RecipientKeyName -DnsName $RecipientKeyName -CertStoreLocation $Path -KeyUsage KeyEncipherment,DataEncipherment, KeyAgreement -Type DocumentEncryptionCert
    }


    if ($action -eq "ListCert") {
        $actioned = $true
        if ($Path -ne "Cert:\CurrentUser\My") {
            Write-Log "The -Path value needs to be 'Cert:\CurrentUser\My'" 
            Write-Host "The -Path value needs to be 'Cert:\CurrentUser\My'"  -ForegroundColor Red
            Close-Log
            return
        } 

        Write-Log "Listing encryption certificates"
        Write-Host "Listing encryption certificates"
        
        if ($RecipientKeyName -eq "")
        {
            Get-Childitem -Path $Path -DocumentEncryptionCert
        } else {
            Write-Host ""
            Write-Host "   PSParentPath: Microsoft.PowerShell.Security\Certificate::$Path"
            Write-Host ""
            Write-Host "Thumbprint                                Subject"
            Write-Host "----------                                -------"
            Get-Childitem -Path $Path -DocumentEncryptionCert | ForEach-Object {
                if ($_.Subject -eq ("CN=$RecipientKeyName"))
                {
                    Write-Host "$($_.Thumbprint)  $($_.Subject)"
                }
            }
        }
    }


    if (!($actioned))
    {
        Write-Log "Unknown action '$action'.  No processing performed" 
        Write-Host "Unknown action '$action'.  No processing performed"  -ForegroundColor Red
        Write-Host "Recognised actions: "
        Write-Host "    Pack                 : Pack folder contents into secure 7Zip file"
        Write-Host "    Put                  : Put or send the archive file to remote destination"
        Write-Host "    Get                  : Get or fetch the archive from remote location"
        Write-Host "    Unpack               : Unpack folder contents from secure 7Zip file"
        Write-Host "    Reconcile            : Reconcile files in unpack folder with list of packed files"
        Write-Host "    ReconcileFile        : Generate a reconcile file without packing"
        Write-Host "    Install              : Install required packages"
        Write-Host "    ArchiveInformation   : Fetch archive information from archive file"
        
        Write-Host ""
        Write-Host "For help use command "
        Write-Host "    Get-Help .\ptrFiles.ps1"
    }

    Close-Log
}


$dateTimeStart = Get-Date -f "yyyy-MM-dd HH:mm:ss"
Write-Log "***********************************************************************************"
Write-Log "*   Start of processing: [$dateTimeStart]"
Write-Log "***********************************************************************************"


Write-Log "Script parameters follow"
ForEach ($boundParam in $PSBoundParameters.GetEnumerator())
{
    if ($boundParam.Key -eq "SecretKey") {
        Write-Log "Parameter: $($boundParam.Key)   Value: ************** "
    } else {
        Write-Log "Parameter: $($boundParam.Key)   Value: $($boundParam.Value) "
    }
}
Write-Log ""


Invoke-Main
