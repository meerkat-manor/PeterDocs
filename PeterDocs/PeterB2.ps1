
$default_reconcileFile = "##protect_transfer_reconcile_files##.csv"
$default_profile = "default"
$default_archiveFile = ".\ptr_file_##date##.7z"

function Open-Log {

    $dateTimeStart = Get-Date -f "yyyy-MM-dd HH:mm:ss"
    Write-Log "***********************************************************************************"
    Write-Log "*   Start of processing: [$dateTimeStart]"
    Write-Log "***********************************************************************************"

}

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
    return [String] "PETERDOCS"
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

<#
 .Synopsis
   Packs a source folder(s) into an encrypted 7ZIP archive file
   that can be securely transported to a remote lcoation or
   even used as a secure permmanent backup.

   PeterDocs : Protect, Transfer, Reconcile Document Files

 .Description
   Packages source folder contents into a 7ZIP file, adding a reconciliation 
   file to the 7ZIP file and then encrypting the contents.  The source folder
   is not altered and only read rights are required. A log file is written 
   at exceution to record activity.

 
 .Parameter SourceFolder
  The path to the files and folders to pack. 
  The path name can include a trailing * as a wildcard to only include a subset of 
  directories.

  When using the trailing * for names, the filtering is only applied to immediate
  folder names under the parent folder.  The filter does not cascade to lower folders.

  The path can be a local drive, mapped network drive or a network shared folder
  location such as \\MediaStor\MyLibrary.

  The source folder parameter can also be a file containing a list of paths, one per line.
  To use a list file, prefix the source folder value with a "@" and name the file. 
  Do not use a folder for @ defined path.

  A file (@ prefix) containing a list of paths cannot contain generic path names, that 
  is paths with trailing wildcard of "*"

 .Parameter RecipientKey
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

 .Parameter ArchiveFile
  The location and name of the 7ZIP file.  If not supplied a default 7ZIP file name
  will be generated in the current directory for the pack action.

  The default name will take the form ".\transfer_protect_yyyyMMdd_hhmm.7z"

  For unpack actions, the archive file name parameter is mandatory.

 .Parameter RootFolder
  The root folder, which should be used if using wildcard (*) for the
  path.  A guess will be made as to value if not supplied, which will
  work in many circumstances.

 .Parameter FileFilter
  A filter on file names.  This does not filter directories.
  An example to only include JPEG file is "*.jpg".  You can also
  filter on picture file names starting with "IMG*.jpg"

 .Parameter ReconcileFile
  The name of the reconfile file name to generate during pack or use 
  during unpack.  This is a file name without path.  If no value is 
  supplied, then a default name is generated.
  The reconcile file is included into the root of the 7ZIP file.
  Once a reconcile is executed, you can delete this file from the 
  restored location.

  The default name is "##protect_transfer_reconcile_files##.csv"

 .Parameter SecretFile
  The secret file name is used with RecipientKey to secure the
  internally generated password for the 7ZIP file.  When unpacking the
  7ZIP file you will need access to this file if RecipientKey
  was used. If not supplied a default name is used.  This file is 
  encrypted with RecipientKey.

  The default name is the archive file name with postfix  ".key"

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
  - PETERDOCS_RECIPIENTKEY

 
 .Example
   # Pack and encrypt all files in folder ".\transferpack\" using a private-public key
   # A file with the postifx ".key" is also generated alongside the 7ZIP file
   Invoke-Pack -SourceFolder ".\transferpack\" -RecipientKeyName data@mycompany
 
#>

function Invoke-Pack
{
Param( 
    [Parameter(Mandatory)][String] $SourceFolder,
    [String] $RecipientKey,
    [String] $SecretKey,
    [String] $ArchiveFile,
    [String] $ReconcileFile, 
    [String] $FileFilter ="*",
    [String] $SecretFile, 
    [switch] $ExcludeHash,
    [String] $RootFolder,
    [String] $LogPath

) 

    Open-Log
    
    Write-Log "Function parameters follow"
    Write-Log "Parameter: SourceFolder   Value: $SourceFolder "
    Write-Log "Parameter: RecipientKey   Value: $RecipientKey "
    if ($null -eq $SecretKey) {
        Write-Log "Parameter: SecretKey   Value: (null)) "
    } else {
        Write-Log "Parameter: SecretKey   Value: ************** "
    }
    Write-Log "Parameter: ArchiveFile   Value: $ArchiveFile "
    Write-Log "Parameter: ReconcileFile   Value: $ReconcileFile "
    Write-Log "Parameter: FileFilter   Value: $FileFilter "
    Write-Log "Parameter: SecretFile   Value: $SecretFile "
    Write-Log "Parameter: ExcludeHash   Value: $ExcludeHash "
    Write-Log "Parameter: LogPath   Value: $LogPath "
    Write-Log ""

    if ($SourceFolder.StartsWith("@")) {
        If (!(Test-Path -Path $SourceFolder.Substring(1) )) {    
            Write-Log "File '$($SourceFolder.Substring(1))' does not exist"
            Write-Host "File '$($SourceFolder.Substring(1))' does not exist" -ForegroundColor Red
            Close-Log
            Exit
        }
    } else {
        If (!(Test-Path -Path $SourceFolder )) {    
            Write-Log "Folder '$SourceFolder' does not exist"
            Write-Host "Folder '$SourceFolder' does not exist" -ForegroundColor Red
            Close-Log
            Exit
        }
    }


    if ($RecipientKey -eq "") {
        $getEnvName = $(Get-SoftwareName) + "_RECIPIENTKEY"
        if ([System.Environment]::GetEnvironmentVariable($getEnvName) -ne "" -and $null -ne [System.Environment]::GetEnvironmentVariable($getEnvName)) {
            $RecipientKey = [System.Environment]::GetEnvironmentVariable($getEnvName)
        }
    }

    if (($RecipientKey -eq "") -and ($SecretKey -eq "")) {
        Write-Log "Recipient Key or Secret Key required for packing" 
        Write-Host "Recipient Key or Secret Key required for packing"  -ForegroundColor Red
        Close-Log
        return
    } 
    
    if ($RootFolder -eq "") {
        if ($SourceFolder.EndsWith("*")) {
            Write-Log "Root folder required for packing when using wild card for Source Folder" 
            Write-Host "Root folder required for packing when using wild card for Source Folder"  -ForegroundColor Red
            Close-Log
            return
        } else {
            $RootFolder = $SourceFolder
        }
    }

    if ($ArchiveFile -eq "") {
        $ArchiveFile = $default_archiveFile.Replace("##date##", (Get-Date -Format "yyyyMMdd_HHmm"))
    }

    if ($SecretKey -eq "") {
        if ($SecretFile -eq "")
        {
            $SecretFile = $ArchiveFile + ".key"
        }
        $secret = New-RandomPassword -Length 80
        Protect-CmsMessage -To $recipientKey -OutFile $SecretFile -Content $secret 
    } else {
        $secret = $SecretKey
    }


    Write-Log "Saving folders/files to archive file '$ArchiveFile'"
    Write-Host "Saving folders/files to archive file '$ArchiveFile'"

    if ($ReconcileFile -eq "")
    {
        $ReconcileFile = $default_reconcileFile
    }

    if ($FileFilter -eq "")
    {
        $FileFilter = "*"
    }

    if ($SourceFolder.EndsWith("*"))
    {
        Write-Log "Archive primary folder is '$SourceFolder'"
        $firstCompress = $true
        Get-ChildItem $SourceFolder| ForEach-Object {
            $firstCompress = Invoke-SinglePack -ArchiveFolder $_.FullName -ArchiveFile $ArchiveFile -FileFilter $FileFilter -FirstCompress $firstCompress
        }
    } else {
        if ($SourceFolder.StartsWith("@")) {
            Write-Log "Using @ file '$($SourceFolder.Substring(1))'"
            Write-Host "Using @ file '$($SourceFolder.Substring(1))'"
            $firstCompress = $true

            Get-Content -Path $($SourceFolder.Substring(1)) | ForEach-Object {
                if ($_ -ne "") {

                    if ($_.EndsWith("*")) {
                        Get-ChildItem $_ | ForEach-Object {
                            $firstCompress = Invoke-SinglePack -ArchiveFolder $_.FullName -ArchiveFile $ArchiveFile -FileFilter $FileFilter -FirstCompress $firstCompress
                        }
                    } else {
                
                        If (!(Test-Path -Path $_ )) {    
                            Write-Log "Folder/file '$($_)' does not exist"
                            Write-Host "Folder/file '$($_)' does not exist" -ForegroundColor Red
                        }
                        else {
                            $firstCompress = Invoke-SinglePack -ArchiveFolder $_ -ArchiveFile $ArchiveFile -FileFilter $FileFilter -FirstCompress $firstCompress
                        }
                    }
                }
            }
        } else {
            Write-Log "Archive folder '$SourceFolder'"
            Write-Host "Archive folder '$SourceFolder'"
            Compress-7Zip -Path $SourceFolder -ArchiveFileName $ArchiveFile -Format SevenZip -Filter $FileFilter    
        }
    }

    If (!(Test-Path -Path $ArchiveFile )) {    
        Write-Log "Archive file '$ArchiveFile' was not created.  See any previous errors"
        Write-Host "Archive file '$ArchiveFile' was not created.  See any previous errors" -ForegroundColor Red
        Close-Log
        Exit
    }

    Set-Reconcile -ReconcileFile $ReconcileFile -FolderName $SourceFolder -FileFilter $FileFilter -RootFolderName $rootFolder
    If (!(Test-Path -Path $ReconcileFile )) {    
        Write-Log "Reconcile file '$ReconcileFile' was not created.  See any previous errors"
        Write-Host "Reconcile file '$ReconcileFile' was not created.  See any previous errors" -ForegroundColor Red
        Close-Log
        return
    }

    Write-Log "Add reconcile file '$ReconcileFile' to file '$ArchiveFile'"
    $fullReconcileName = (Get-Item $ReconcileFile).FullName
    $fullZipName = (Get-Item $ArchiveFile).FullName
    Compress-7Zip -Path $fullReconcileName -ArchiveFileName $fullZipName -Format SevenZip -Append -Password $secret -EncryptFilenames
    Remove-Item $fullReconcileName

    Write-Log "Archive file '$ArchiveFile' created from folder '$SourceFolder'"
    Write-Host "Archive file '$ArchiveFile' created from folder '$SourceFolder'"  -ForegroundColor Green

    Close-Log
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

<#
Export-ModuleMember -Function 'Get-SoftwareName'

Export-ModuleMember -Function 'Open-Log'
Export-ModuleMember -Function 'Write-Log'
Export-ModuleMember -Function 'Close-Log'

Export-ModuleMember -Function 'New-RandomPassword'

Export-ModuleMember -Function 'Set-Reconcile'
Export-ModuleMember -Function 'Invoke-Pack'
Export-ModuleMember -Function 'Invoke-PutArchive'
Export-ModuleMember -Function 'Invoke-GetArchive'
Export-ModuleMember -Function 'Invoke-Unpack'
Export-ModuleMember -Function 'Invoke-Reconcile'
#>