
<#
 .Synopsis
  PeterDocs is intended to create a secure archive file that
  can be transferred to a remote location and restored the contents

 .Description
  The archive file can be secured either by symmetric key or an
  asymetric public-private key.

  An alternative approach to securely transferring document files
  is to use backup and restore software that does encryption and
  can verify the restored backup files.

 .Notes
 The archive file is encrypted using the native 7ZIP function and if you
 use symmetric keys then you supply and control this value.  If you use a 
 public-private key then the script will generate a long and random
 secret symmetric key and use this value with 7ZIP.

 The long symmetric key is stored in an accompanying ".key" file that
 is itself encrypted with the public key of the recipient.  The recipient
 of the archive file will need to be supplied with the ".key" file
 along with the archive file.

 If you ar using the symmetric key then the script will enforce password
 complexity and length on the key value.
 

#>


$global:default_reconcileFile = "##protect_transfer_reconcile_files##.csv"
$global:LogPathName = ""


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

    if (($null -eq $global:LogPathName) -or ($global:LogPathName -eq ""))
    {
        $global:LogPathName = Join-Path -Path ".\" -ChildPath "Logs"
    }
    $logName = $(Get-SoftwareName) + "_$date.log"
    $sFullPath = Join-Path -Path $global:LogPathName -ChildPath $logName 

    if (!(Test-Path -Path $global:LogPathName)) {
        $null = New-Item -Path $global:LogPathName -ItemType Directory
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
    [int] $length = 30,
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

function Test-PasswordQuality
{
    Param( 
        [Parameter(Mandatory)][String] $TestPassword
    ) 

    $qualityMatch = $true

    $patternsToMatch = "[^a-zA-Z0-9]", "[^\w]", "[A-Z\p{Lu}\s]", "[a-z\p{Ll}\s]","[\d]"
    foreach ($pattern in $patternsToMatch) {
        if ($TestPassword -notmatch $pattern) {
            Write-Warning -Message "The password does not match regex pattern $pattern!"
            $qualityMatch = $false
        }
    }

    if ($TestPassword.Length -lt 10) {
        Write-Warning -Message "The password does not match minimum length requirements [10]!"
        $qualityMatch = $false
    }
    
    return $qualityMatch
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


<#
 .Synopsis
  Creates a CSV file for reconciliation at the destination.

 .Description
  The process creates a CSV file that can be packaged with
  the archive and used by the reconciliation process. The 
  generation and inclusion of the reconcile file when 
  generating an archive file is automatic.

  The file can be also used as a metadata source for 
  restored files.
 
 .Parameter SourceFolder
  The path to the files and folders to include in the CSV file. You need read
  access to the folder, its sub folders and file. The path name can include 
  a trailing * as a wildcard to only include a subset of directories.

  When using the trailing * for names, the filtering is only applied to immediate
  folder names under the parent folder.  The filter does not cascade to lower folders.

  The path can be a local drive, mapped network drive or a network shared folder
  location such as \\MediaStore\MyLibrary.

  The source folder parameter can also be a file containing a list of paths, one per line.
  To use a list file, prefix the source folder value with a "@" and name the file. 
  Do not use a folder for @ defined path.

  A file (@ prefix) containing a list of paths cannot contain generic path names, that 
  is paths with trailing wildcard of "*"

 .Parameter ReconcileFile
  The name of the CSV file name to generate.

 .Parameter RootFolder
  The root folder, which should be used if using wildcard (*) for the
  path.  A guess will be made as to value if not supplied, which will
  work in many circumstances.

 .Parameter FileFilter
  A filter on file names.  This does not filter directories.
  An example to only include JPEG file is "*.jpg".  You can also
  filter on picture file names starting with "IMG*.jpg"

 .Parameter ProcessFileCount
  Approximate number of files to process.  If the value is unknown, use 0.
  The number is used to display the progress message and should not be 
  taken as the accurate count of files.

 .Parameter ExcludeHash
  Exclude the file hash from the reconcile file.  As producing a file
  hash takes compute cycles during pack, you can select to bypass this 
  generation to speed up the packaging.  Excluding the hash does reduce 
  the functionality of the reconciliation at unpack.

 .Parameter LogPath
  The log folder where log files are written.  If the folder does not
  exist then it is created.  You need write access rights to this location.

 .Notes

  The following environment variables are supported:
  - PETERDOCS_LOGPATH
 
 .Example
   # Create a reconcile file for folder "C:\sourcefiles\"
   Build-PeterReconcile -SourceFolder "C:\sourcefiles\" -ReconcileFile ".\myreconcile.csv"

#>

function Build-PeterReconcile
{
Param( 
    [Parameter(Mandatory)][String] $SourceFolder,
    [Parameter(Mandatory)][String] $ReconcileFile,
    [String] $RootFolder,
    [String] $FileFilter,
    [int] $ProcessFileCount,
    [switch] $ExcludeHash,
    [switch] $IncludeExif,
    [switch] $Feedback,
    [String] $LogPath
) 

    if (($null -ne $LogPath) -and ($LogPath -ne ""))
    {
        $global:LogPathName = $LogPath
    }

    if ($Feedback) {
        Open-Log
            
        Write-Log "Function 'Build-PeterReconcile' parameters follow"
        Write-Log "Parameter: SourceFolder   Value: $SourceFolder "
        Write-Log "Parameter: ReconcileFile   Value: $ReconcileFile "
        Write-Log "Parameter: RootFolder   Value: $RootFolder "
        Write-Log "Parameter: FileFilter   Value: $FileFilter "
        Write-Log "Parameter: ProcessFileCount   Value: $ProcessFileCount "
        Write-Log "Parameter: ExcludeHash   Value: $ExcludeHash "
        Write-Log "Parameter: IncludeExif   Value: $IncludeExif "
        Write-Log "Parameter: Feedback   Value: $Feedback "
        Write-Log "Parameter: LogPath   Value: $LogPath "
        Write-Log ""
    }

    if ($ReconcileFile -eq "")
    {
        $ReconcileFile = $default_reconcileFile
    }

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

    Write-Log "Generating reconciliation file '$ReconcileFile'"
    Write-Host "Generating reconciliation file '$ReconcileFile'"
    
    $totalFileCount = 0
    $totalFileSize = 0

    if ($RootFolder -eq "") {
        $RootFolder = $SourceFolder
    }
    if ($ExcludeHash) {
        $messageFrequency = 1000
    } else {
        $messageFrequency = 500
    }

    Write-Progress -Activity "Creating reconciliation entries in file $ReconcileFile" -Status "Start" 

    Set-Content -Path $ReconcileFile  -Value '"FullName","LastWriteTime","CreationTime","LastAccessTime","Length","Hash","ParentFolder","Object","Attributes","Extension"'

    if ($SourceFolder.StartsWith("@")) {
        Write-Log "Using @ file '$($SourceFolder.Substring(1))'"
        Write-Host "Using @ file '$($SourceFolder.Substring(1))'"

        Get-Content -Path $($SourceFolder.Substring(1)) | ForEach-Object {
            if ($_ -ne "") {
                If (!(Test-Path -Path $_ )) {    
                    Write-Log "Folder/file '$($_)' does not exist"
                    Write-Host "Folder/file '$($_)' does not exist" -ForegroundColor Red
                }
                else {
                    Get-ChildItem $_ -Filter $FileFilter -Recurse | Where-Object {!$_.PSIsContainer} | ForEach-Object {

                        $totalFilecount = $totalFileCount + 1
                        $totalFileSize = $totalFileSize + $_.Length 
            
                        if (($totalFilecount % $messageFrequency) -eq 0) {            
                            Write-Log "Read $totalFileCount files and size $(Get-ConvenientFileSize -Size $totalFileSize ).  Currently at folder '$($_.Directory)' " 
                        }
                        if ( $ProcessFileCount -gt 0) {
                            Write-Progress -Activity "Creating reconciliation entries in file $ReconcileFile" -Status "Read $totalFileCount files and size $(Get-ConvenientFileSize -Size $totalFileSize ).  Currently at folder '$($_.Directory)'" -PercentComplete (($totalFileCount / $ProcessFileCount) * 100) 
                        } else {
                            Write-Progress -Activity "Creating reconciliation entries in file $ReconcileFile" -Status "Read $totalFileCount files and size $(Get-ConvenientFileSize -Size $totalFileSize ).  Currently at folder '$($_.Directory)'" -PercentComplete -1 
                        }
            
                        if ($ExcludeHash) {
                            $sourceHash = ""
                        } else {
                            $sourceHash = (Get-FileHash -Path $_.FullName).Hash
                        }
                        $record = '"'+$_.FullName.Replace($RootFolder, "")+'","'+$_.LastWriteTime.ToString("yyyy-MM-ddTHH:mm:ss")+'"'
                        $record = $record + ',"'+$_.CreationTime.ToString("yyyy-MM-ddTHH:mm:ss")+'","'+$_.LastAccessTime.ToString("yyyy-MM-ddTHH:mm:ss")+'"'
                        $record = $record + ','+$_.Length+',"'+$sourceHash+'","'+ $_.Directory + '","' + $_.Name + '","' + $_.Attributes+'","'+$_.Extension+'"'

                        if ($IncludeExif) {
                            $null = Get-ImageFileContents -ImageFile $($_.FullName)
                        }

                        Add-Content -Path  $ReconcileFile  -Value $record
                    
                    }
                }
            }
        }

    } else {
        Get-ChildItem $SourceFolder -Filter $FileFilter -Recurse | Where-Object {!$_.PSIsContainer} | ForEach-Object {

            $totalFilecount = $totalFileCount + 1
            $totalFileSize = $totalFileSize + $_.Length 

            if (($totalFilecount % $messageFrequency) -eq 0) {            
                Write-Log "Read $totalFileCount files and size $(Get-ConvenientFileSize -Size $totalFileSize ).  Currently at folder '$($_.Directory)' " 
            }
            if ( $ProcessFileCount -gt 0) {
                Write-Progress -Activity "Creating reconciliation entries in file $ReconcileFile" -Status "Read $totalFileCount files and size $(Get-ConvenientFileSize -Size $totalFileSize ).  Currently at folder '$($_.Directory)'" -PercentComplete (($totalFileCount / $ProcessFileCount) * 100) 
            } else {
                Write-Progress -Activity "Creating reconciliation entries in file $ReconcileFile" -Status "Read $totalFileCount files and size $(Get-ConvenientFileSize -Size $totalFileSize ).  Currently at folder '$($_.Directory)'" -PercentComplete -1
            }

            if ($ExcludeHash) {
                $sourceHash = ""
            } else {
                $sourceHash = (Get-FileHash -Path $_.FullName).Hash
            }
            $record = '"'+$_.FullName.Replace($RootFolder, "")+'","'+$_.LastWriteTime.ToString("yyyy-MM-ddTHH:mm:ss")+'"'
            $record = $record + ',"'+$_.CreationTime.ToString("yyyy-MM-ddTHH:mm:ss")+'","'+$_.LastAccessTime.ToString("yyyy-MM-ddTHH:mm:ss")+'"'
            $record = $record + ','+$_.Length+',"'+$sourceHash+'","'+ $_.Directory + '","' + $_.Name + '","' + $_.Attributes+'","'+$_.Extension+'"'

            if ($IncludeExif) {
                $null = Get-ImageFileContents -ImageFile $($_.FullName)
            }

            Add-Content -Path  $ReconcileFile  -Value $record
        
        }

    }

    Write-Progress -Activity "Creating reconciliation entries in file $ReconcileFile" -Completed  

    Write-Log "Total reconcile file count is $totalFileCount and size $(Get-ConvenientFileSize -Size $totalFileSize ) ($totalFileSize)"
    if ($Feedback) {
        Write-Host "Total reconcile file count is $totalFileCount and size $(Get-ConvenientFileSize -Size $totalFileSize )" -ForegroundColor Green
        Close-Log
    }

}

function Invoke-SinglePack
{
    Param( 
        [Parameter(Mandatory)][String] $ArchiveFolder,
        [Parameter(Mandatory)][String] $ArchiveFileName,
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
                Compress-7Zip -Path $ArchiveFolder -ArchiveFileName $ArchiveFileName -Format SevenZip -PreserveDirectoryRoot -Filter $FileFilter   
            } else {
                Compress-7Zip -Path $ArchiveFolder -ArchiveFileName $ArchiveFileName -Format SevenZip -PreserveDirectoryRoot -Filter $FileFilter -Append    
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


<#
 .Synopsis
   Packs a source folder(s) into an encrypted 7ZIP archive file
   that can be securely transported to a remote lcoation or
   even used as a secure permmanent backup.

 .Description
   Packages source folder contents into a 7ZIP file, adding a reconciliation 
   file to the 7ZIP file and then encrypting the contents.  The source folder
   is not altered and only read rights are required. A log file is written 
   at exceution to record activity.

 
 .Parameter SourceFolder
  The path to the files and folders to pack into the archive. You require
  read access to the source folder, its sub folders and files. 
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
  is paths with trailing wildcard of "*".

 .Parameter RecipientKey
  The recipient of the package which is used to find the appropriate
  certificate for encrypting with the public key.  Either the RecipientKey 
  or the SecretKey is required for packing or unpacking the 7ZIP file.
  Using the RecipientKey is the most secure transfer option as a
  asymmetric cryptographic key is used that can only be decrypted by the 
  holder of the private key.

  If you are using the RecipientKey, then the 7ZIP file contents can only
  be unzipped by the holder of the private key and the SecretFile file.
  If you don't have the private, which you should not unless you are sending
  to yourself, then you cannot unpack the 7ZIP file.

 .Parameter SecretKey
  A tradiitional secret to encrypt or decrypt the 7ZIP package. Either the RecipientKey 
  or the SecretKey is required for packing or unpacking the 7ZIP file.  This method
  uses a symmetric cryptographic key exchange which is less secure then the 
  RecipientKey approach.

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
  - PETERDOCS_LOGPATH

 .Example
   # Pack and encrypt all files in folder ".\transferpack\" using a private-public key
   # A default archive named file is created which includes a date and time in the name.
   # A file with the postifx ".key" is also generated alongside the 7ZIP file
   Compress-Peter -SourceFolder ".\transferpack\" -RecipientKeyName data@mycompany
 
#>

function Compress-Peter
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

    if (($null -ne $LogPath) -and ($LogPath -ne ""))
    {
        $global:LogPathName = $LogPath
    }

    Open-Log
    
    Write-Log "Function 'Compress-Peter' parameters follow"
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
        $ArchiveFile = $(Get-SoftwareName) + $(Get-Date -Format "yyyyMMdd_HHmm") + ".7z"
    }

    if ($SecretKey -eq "") {
        if ($SecretFile -eq "")
        {
            $SecretFile = $ArchiveFile + ".key"
        }
        $secret = New-RandomPassword -Length 80
        Protect-CmsMessage -To $recipientKey -OutFile $SecretFile -Content $secret 
    } else {
        if (!(Test-PasswordQuality -TestPassword $SecretKey)) {
            Write-Log "Secret Key does not meet complexity rules" 
            Write-Host "Secret Key does not meet complexity rules"  -ForegroundColor Red
            Close-Log
            return    
        }
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

    
    $archiveInfo = Get-7ZipInformation -ArchiveFileName $ArchiveFile
    [int] $archiveFileCount = $archiveInfo.FilesCount

    if ($ExcludeHash) {
        Build-PeterReconcile -ReconcileFile $ReconcileFile -SourceFolder $SourceFolder -FileFilter $FileFilter -RootFolder $rootFolder -ExcludeHash -ProcessFileCount $archiveFileCount
    } else {
        Build-PeterReconcile -ReconcileFile $ReconcileFile -SourceFolder $SourceFolder -FileFilter $FileFilter -RootFolder $rootFolder -ProcessFileCount $archiveFileCount
    }
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



<#
 .Synopsis
   Packs a source folder(s) into an encrypted 7ZIP archive file
   that can be securely transported to a remote lcoation or
   even used as a secure permmanent backup.

 .Description
   Packages source folder contents into a 7ZIP file, adding a reconciliation 
   file to the 7ZIP file and then encrypting the contents.  The source folder
   is not altered and only read rights are required. A log file is written 
   at exceution to record activity.


 .Parameter ArchiveFile
  The location and name of the 7ZIP file.  If not supplied a default 7ZIP file name
  will be generated in the current directory for the pack action.

  The default name will take the form ".\transfer_protect_yyyyMMdd_hhmm.7z"

  For unpack actions, the archive file name parameter is mandatory.
 
 .Parameter SourceFolder
  The path to the files and folders to pack into the archive. You require
  read access to the source folder, its sub folders and files. 
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
  is paths with trailing wildcard of "*".

 .Parameter SecretFile
  The secret file name is used with RecipientKey to secure the
  internally generated password for the 7ZIP file.  When unpacking the
  7ZIP file you will need access to this file if RecipientKey
  was used. If not supplied a default name is used.  This file is 
  encrypted with RecipientKey.

  The default name is the archive file name with postfix  ".key"

 .Parameter TargetProfile

 .Parameter AccountId

 .Parameter AccountKey


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
  - PETERDOCS_LOGPATH

 .Example
   # 
   # 
   Send-Peter -ArchiveFile "mybackup.7z" -TargetPath 
 
#>

function Send-Peter
{
Param( 
    [Parameter(Mandatory)][String] $ArchiveFile,
    [Parameter(Mandatory)][String] $TargetPath,
    [String] $SecretFile,
    [String] $TargetProfile,
    [String] $AccountId,
    [String] $AccountKey,
    [String] $LogPath
) 

    if (($null -ne $LogPath) -and ($LogPath -ne ""))
    {
        $global:LogPathName = $LogPath
    }

    Open-Log

    Write-Log "Function 'Send-Peter' parameters follow"
    Write-Log "Parameter: ArchiveFile   Value: $ArchiveFile "
    Write-Log "Parameter: TargetPath   Value: $TargetPath "
    Write-Log "Parameter: SecretFile   Value: $SecretFile "
    Write-Log "Parameter: TargetProfile   Value: $TargetProfile "
    Write-Log "Parameter: AccountId   Value: $AccountId "
    Write-Log "Parameter: AccountKey   Value: $AccountKey "
    Write-Log "Parameter: LogPath   Value: $LogPath "
    Write-Log ""

    if ($TargetProfile -eq "") {
        $getEnvName = $(Get-SoftwareName) + "_PROFILE"
        if ([System.Environment]::GetEnvironmentVariable($getEnvName) -ne "" -and $null -ne [System.Environment]::GetEnvironmentVariable($getEnvName)) {
            $targetProfile = [System.Environment]::GetEnvironmentVariable($getEnvName)
        } 
        if ($null -eq $targetProfile -or $targetProfile -eq "") {
            $targetProfile = "default"
        }
    }

    if (!(Test-Path -Path $ArchiveFile )) {
        Write-Log "Archive file '$ArchiveFile' not found"
        Write-Host "Archive file '$ArchiveFile' not found"  -ForegroundColor Red
        Close-Log
        return
    }
    if ($SecretFile -eq "") {
        $SecretFile = $ArchiveFile + ".key"
    }

    $remoteType = $false

    if ($TargetPath.StartsWith("s3://")) {
        $remoteType = $true

        [int] $offset = "s3://".Length
        $parts = $TargetPath.Substring($offset).Split("/")
        $bucketHost = $parts[0]
        $offset = $offset + $bucketHost.Length + 1

        if ($bucketHost -eq "") {
            Write-Log "Bucket name required" 
            Write-Host "Bucket name required"  -ForegroundColor Red
            Close-Log
            return
        }

        Try {
            Set-AWSCredential -ProfileName $TargetProfile

            $targetObject = $TargetPath.Substring($offset)
            Write-Log "Transferring '$TargetPath' file to host '$bucketHost' folder '$targetObject'"
            Write-Host "Transferring '$TargetPath' file to host '$bucketHost' folder '$targetObject'"
            Write-S3Object -BucketName $bucketHost -File $ArchiveFile -Key $targetObject
            if (Test-Path -Path $SecretFile) {
                $targetObject = $TargetPath.Substring($offset) + ".key"
                Write-Log "Transferring '$SecretFile' file to host '$bucketHost' folder '$targetObject'"
                Write-Host "Transferring '$SecretFile' file to host '$bucketHost' folder '$targetObject'"
                Write-S3Object -BucketName $bucketName -File $SecretFile -Key $targetObject 
            }
            $targetObject = $TargetPath.Substring($offset)
            Write-Log "Archive file '$ArchiveFile' stored on AWS S3 bucket '$bucketHost' at '$targetObject'"
            Write-Host "Archive file '$ArchiveFile' stored on AWS S3 bucket '$bucketHost' at '$targetObject'" -ForegroundColor Green
        } Catch {
            Write-Log "Error in sending archive file '$ArchiveFile' to AWS S3 with error: $($_)"
            Write-Host "Error in sending archive file '$ArchiveFile' to AWS S3 with error: $($_)" -ForegroundColor Red
        }
    }



    if ($targetPath.StartsWith("b2://")) {
        $remoteType = $true

        [int] $offset = "b2://".Length
        $parts = $TargetPath.Substring($offset).Split("/")
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

        Try {
            $b2ApiToken = Get-B2ApiToken -AccountId $AccountId -AccountKey $AccountKey
        } Catch {
            Write-Log "Authentication error with account '$AccountID'" 
            Write-Host "Authentication error with account '$AccountID'" -ForegroundColor Red
            Close-Log
            return
        }

        if ($null -eq $b2ApiToken.Token -or $b2ApiToken.Token -eq "")
        {
            Write-Log "Authentication error with account '$AccountID' as no API Token" 
            Write-Host "Authentication error with account '$AccountID' as no API Token" -ForegroundColor Red
            Close-Log
            return
        }
        
        $b2Bucket = Get-B2Bucket -ApiToken $b2ApiToken.Token -AccountId $b2ApiToken.accountId -ApiUri $b2ApiToken.ApiUri -BucketHost $bucketHost
        if ($null -eq $b2Bucket -or $b2Bucket.BucketID -eq "") {
            Write-Log "Bucket '$bucketHost' not found" 
            Write-Host "Bucket '$bucketHost' not found" -ForegroundColor Red
            Close-Log
            return
        }

        $b2UploadUri = Get-B2UploadUri -BucketHost $b2Bucket.bucketId -FileName $ArchiveFile -ApiUri $b2ApiToken.ApiUri -ApiToken $b2ApiToken.Token 
        $targetObject = $TargetPath.Substring($offset)
        Write-Log "Transferring '$ArchiveFile' file to host '$bucketHost' folder '$targetObject'"
        Write-Host "Transferring '$ArchiveFile' file to host '$bucketHost' folder '$targetObject'"
        $b2Upload = Send-B2Upload -BucketHost $b2UploadUri.bucketId -TargetPath $targetObject  -FileName $ArchiveFile -ApiUri $b2UploadUri.uploadUri -ApiToken $b2UploadUri.Token
        Write-Log "Upload: $b2Upload"
        if (Test-Path -Path $SecretFile) {
            $targetObject = $TargetPath.Substring($offset) + ".key"
            Write-Log "Transferring '$SecretFile' file to host '$bucketHost' folder '$targetObject'"
            Write-Host "Transferring '$SecretFile' file to host '$bucketHost' folder '$targetObject'"
            $b2Upload = Send-B2Upload -BucketHost $b2UploadUri.bucketId -TargetPath $targetObject  -FileName $SecretFile -ApiUri $b2UploadUri.uploadUri -ApiToken $b2UploadUri.Token
            Write-Log "Upload: $b2Upload"
        }
        $targetObject = $TargetPath.Substring($offset)
        Write-Log "Archive file '$ArchiveFile' stored on Backblaze bucket '$bucketHost' at '$targetObject'"
        Write-Host "Archive file '$ArchiveFile' stored on Backblaze bucket '$bucketHost' at '$targetObject'" -ForegroundColor Green

    }

    if (!($remoteType)) {
        Write-Log "Unknown remote path '$TargetPath.'.  No transfer performed" 
        Write-Host "Unknown remote path '$TargetPath.'.  No transfer performed"  -ForegroundColor Red
        Write-Host "Recognised transfer prefixes: "
        Write-Host "    s3://         : Send to AWS S3 location"
        Write-Host "    b3://         : Send to Backblaze location"
        Write-Host " "    
        Write-Host "If you are saving to local drives or network shared folders,"    
        Write-Host "please use your OS tools to move the file"    
        Write-Host " "    
    }

    Close-Log
}



<#
 .Synopsis
   Packs a source folder(s) into an encrypted 7ZIP archive file
   that can be securely transported to a remote lcoation or
   even used as a secure permmanent backup.

 .Description
   Packages source folder contents into a 7ZIP file, adding a reconciliation 
   file to the 7ZIP file and then encrypting the contents.  The source folder
   is not altered and only read rights are required. A log file is written 
   at exceution to record activity.


 .Parameter ArchiveFile
  The location and name of the 7ZIP file.  If not supplied a default 7ZIP file name
  will be generated in the current directory for the pack action.

  The default name will take the form ".\transfer_protect_yyyyMMdd_hhmm.7z"

  For unpack actions, the archive file name parameter is mandatory.
 
 .Parameter SourceFolder
  The path to the files and folders to pack into the archive. You require
  read access to the source folder, its sub folders and files. 
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
  is paths with trailing wildcard of "*".

 .Parameter SecretFile
  The secret file name is used with RecipientKey to secure the
  internally generated password for the 7ZIP file.  When unpacking the
  7ZIP file you will need access to this file if RecipientKey
  was used. If not supplied a default name is used.  This file is 
  encrypted with RecipientKey.

  The default name is the archive file name with postfix  ".key"

 .Parameter TargetProfile

 .Parameter AccountId

 .Parameter AccountKey


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
  - PETERDOCS_PROFILE
  - PETERDOCS_ACCOUNTKEY
  - PETERDOCS_LOGPATH

 .Example
   # 
   # 
   Receive-Peter -ArchiveFile "mybackup.7z" -TargetPath 
 
#>

function Receive-Peter
{
Param( 
    [Parameter(Mandatory)][String] $SourcePath,
    [Parameter(Mandatory)][String] $ArchiveFile,
    [String] $SecretFile,
    [String] $SourceProfile,
    [String] $AccountId,
    [String] $AccountKey,
    [String] $LogPath
) 
        
    if (($null -ne $LogPath) -and ($LogPath -ne ""))
    {
        $global:LogPathName = $LogPath
    }

    Open-Log

    Write-Log "Function 'Receive-Peter' parameters follow"
    Write-Log "Parameter: SourcePath   Value: $SourcePath "
    Write-Log "Parameter: ArchiveFile   Value: $ArchiveFile "
    Write-Log "Parameter: SecretFile   Value: $SecretFile "
    Write-Log "Parameter: SourceProfile   Value: $SourceProfile "
    Write-Log "Parameter: AccountId   Value: $AccountId "
    Write-Log "Parameter: AccountKey   Value: $AccountKey "
    Write-Log "Parameter: LogPath   Value: $LogPath "
    Write-Log ""

    if ($SourceProfile -eq "") {
        $getEnvName = $(Get-SoftwareName) + "_PROFILE"
        if ([System.Environment]::GetEnvironmentVariable($getEnvName) -ne "" -and $null -ne [System.Environment]::GetEnvironmentVariable($getEnvName)) {
            $sourceProfile = [System.Environment]::GetEnvironmentVariable($getEnvName)
        } 
        if ($null -eq $sourceProfile -or $sourceProfile -eq "") {
            $sourceProfile = "default"
        }
    }


    $remoteType = $false

    if ($SourcePath.StartsWith("s3://")) {
        $remoteType = $true

        [int] $offset = "s3://".Length
        $parts = $SourcePath.Substring($offset).Split("/")
        $bucketHost = $parts[0]
        $offset = $offset + $bucketHost.Length + 1

        Set-AWSCredential -ProfileName $sourceProfile

        $sourceObject = $SourcePath.Substring($offset)
        Write-Log "Fetching '$ArchiveFile' file from host $bucketHost folder $sourceObject"
        Write-Host "Fetching '$ArchiveFile' file from host $bucketHost folder $sourceObject"
        $null = Read-S3Object -BucketName $bucketHost -File $ArchiveFile -Key $sourceObject
        if (!(Test-Path -Path $ArchiveFile)) {
            Write-Log "Archive file '$sourceObject' not found." 
            Write-Host "Archive file '$sourceObject' not found."  -ForegroundColor Red
        } else {
            $sourceObject = $SourcePath.Substring($offset) + ".key"
            $secretFile = $ArchiveFile + ".key"
            Write-Log "Fetching '$secretFile' file from host '$bucketHost' folder '$sourceObject'"
            Write-Host "Fetching '$secretFile' file from host '$bucketHost' folder '$sourceObject'"
            $null = Read-S3Object -BucketName $bucketHost -File $secretFile -Key $sourceObject 
            if (!(Test-Path -Path $secretFile)) {
                Write-Log "Secret file '$sourceObject' not found. Required if you are using recipient keys" 
                Write-Host "Secret file '$sourceObject' not found. Required if you are using recipient keys" 
            }
            $sourceObject = $SourcePath.Substring($offset)
            Write-Log "Archive file '$ArchiveFile' fetched from AWS S3 '$SourcePath'"
            Write-Host "Archive file '$ArchiveFile' fetched from AWS S3 '$SourcePath'" -ForegroundColor Green
        }

    }



    if ($SourcePath.StartsWith("b2://")) {
        $remoteType = $true

        [int] $offset = "b2://".Length
        $parts = $SourcePath.Substring($offset).Split("/")
        $bucketHost = $parts[0]
        $offset = $offset + $bucketHost.Length + 1

        if ($null -eq $AccountId -or $AccountId -eq "") {
            $AccountId = $SourceProfile
        }

        if ($AccountKey -eq "") {
            $getEnvName = $(Get-SoftwareName) + "_ACCOUNTKEY"
            if ([System.Environment]::GetEnvironmentVariable($getEnvName) -ne "" -and $null -ne [System.Environment]::GetEnvironmentVariable($getEnvName)) {
                $AccountKey = [System.Environment]::GetEnvironmentVariable($getEnvName)
            } 
            if ($null -eq $AccountKey -or $AccountKey -eq "") {
                Write-Log "Account key required" 
                Write-Host "Account key required"  -ForegroundColor Red
                Close-Log
                return
            }
        }

        Try {
            $b2ApiToken = Get-B2ApiToken -AccountId $AccountId -AccountKey $AccountKey
        } Catch {
            Write-Log "Authentication error with account '$AccountID'" 
            Write-Host "Authentication error with account '$AccountID'" -ForegroundColor Red
            Close-Log
            return
        }

        if ($null -eq $b2ApiToken.Token -or $b2ApiToken.Token -eq "")
        {
            Write-Log "Authentication error with account '$AccountID' as no API Token" 
            Write-Host "Authentication error with account '$AccountID' as no API Token" -ForegroundColor Red
            Close-Log
            return
        }

        $b2Bucket = Get-B2Bucket -ApiToken $b2ApiToken.Token -AccountId $b2ApiToken.accountId -ApiUri $b2ApiToken.ApiUri -BucketHost $bucketHost
        if ($null -eq $b2Bucket -or $b2Bucket.BucketID -eq "") {
            Write-Log "Bucket '$bucketHost' not found" 
            Write-Host "Bucket '$bucketHost' not found" -ForegroundColor Red
            Close-Log
            return
        }

        $sourceObject = $SourcePath.Substring($offset)
        Write-Log "Fetching '$ArchiveFile' file from host '$bucketHost' folder '$sourceObject'"
        Write-Host "Fetching '$ArchiveFile' file from host '$bucketHost' folder '$sourceObject'"
        Receive-B2Download -BucketHost $bucketHost -SourcePath $sourceObject -FileName $ArchiveFile -ApiDownloadUri $b2ApiToken.DownloadUri -ApiToken $b2ApiToken.Token
        if (!(Test-Path -Path $ArchiveFile)) {
            Write-Log "Archive file '$sourceObject' not found." 
            Write-Host "Archive file '$sourceObject' not found."  -ForegroundColor Red
        } else {
            $sourceObject = $SourcePath.Substring($offset) + ".key"
            $secretFile = $ArchiveFile + ".key"
            Write-Log "Fetching '$secretFile' file from host '$bucketHost' folder '$sourceObject'"
            Write-Host "Fetching '$secretFile' file from host '$bucketHost' folder '$sourceObject'"
            Receive-B2Download -BucketHost $bucketHost -SourcePath $sourceObject -FileName $secretFile -ApiDownloadUri $b2ApiToken.DownloadUri -ApiToken $b2ApiToken.Token
            if (!(Test-Path -Path $secretFile)) {
                Write-Log "Secret file '$sourceObject' not found. Required if you are using recipient keys" 
                Write-Host "Secret file '$sourceObject' not found. Required if you are using recipient keys" 
            }
            $sourceObject = $SourcePath.Substring($offset)
            Write-Log "Archive file '$ArchiveFile' fetched from Backblaze '$SourcePath'"
            Write-Host "Archive file '$ArchiveFile' fetched from Backblaze '$SourcePath'" -ForegroundColor Green
        }
    
    }


    if (!($remoteType)) {
        Write-Log "Unknown remote path '$SourcePath'.  No get performed" 
        Write-Host "Unknown remote path '$SourcePath'.  No get performed"  -ForegroundColor Red
        Write-Host "Recognised transfer prefixes: "
        Write-Host "    s3://bucket/path/path     : Fetch from AWS S3 location"
        Write-Host "    b2://bucket/path/path     : Fetch from Backblaze location"
        Write-Host " "    
        Write-Host "If you are fetching from local drives or network shared folders,"    
        Write-Host "please use your OS tools to move the file"    
        Write-Host " "    
    }

    Close-Log
}


<#
 .Synopsis
  Unpacks the contents of an encrypted 7ZIP archive file to 
  a target restore folder.

 .Description
  An archive file is unzipped into the restore folder specified.

  The archive file is expected to be encrypted and decryption details
  are needed to be provided.

 .Parameter ArchiveFile
  The location and name of the 7ZIP file.

  The archive file parameter is mandatory.
 
 .Parameter RestoreFolder
  The target path to the restore folder location into which files are unpacked. 
  You need to have write access rights to the location.

  The path can be a local drive, mapped network drive or a network shared folder
  location such as \\MediaStor\MyLibrary.

  The restore folder parameter is mandatory.

 .Parameter RecipientKey
  The recipient of the package which is used to find the appropriate
  certificate for dencryption.  Either the RecipientKeyName or the
  SecretKey is required for unpacking the 7ZIP file.

  If you are using the RecipientKeyName, then the 7ZIP file contents can only
  be unzipped by the holder of the private key and the SecretFileName file.
  If you don't have the private, which you should not unless you are sending
  to yourself, then you cannot unpack the 7ZIP file.

  You must also have corresponding secret file with the archive file.

 .Parameter SecretKey
  A tradiitional secret to encrypt or decrypt the 7ZIP package. Either the RecipientKeyName 
  or the SecretKey is required for packing or unpacking the 7ZIP file.  This method
  uses a symmetric cryptographic key exchange which is less secure then the 
  RecipientKeyName approach.

  Note: Currently the script doe snot user Secure Strings

 .Parameter SecretFile
  The secret file name is used with RecipientKey to secure the
  internally generated password for the 7ZIP file.  When unpacking the
  7ZIP file you will need access to this file if RecipientKey
  was used. If not supplied a default name is used.  This file is 
  encrypted with RecipientKey.

  The default name is the archive file name with postfix  ".key"

 .Parameter LogPath
  The log folder where log files are written.  If the folder does not
  exist then it is created.  You need write access rights to this location.

 .Notes
  This script has been written to use 7ZIP as it is open source
  and provides a secure encryption mechanism, plus portability on Windows,
  Linux and MacOS.

  It is also beneficial that 7ZIP has efficient compression algorithms.

  The script does not check if you have sufficient free storage for the  
  contents on the retsore folder.  It is your responsibility to ensure 
  sufficient storage space exists.

  The following environment variables are supported:
  - PETERDOCS_RECIPIENTKEY
  - PETERDOCS_LOGPATH

 
 .Example
   # Unpack all the files in the archive file "myarchive.7z" into folder
   # ".\retsoredpack\" using a private-public key as decrypt and
   # checking for default file "myarchive.7z.key"
   Expand-Peter -ArchiveFile "myarchive.7z" -RestoreFolder ".\restorepack\" -RecipientKey data@mycompany
 
 .Example
   # Unpack all the files in the archive file "myarchive.7z" into folder
   # ".\restorepack\" using a secret of "longAndComplex9!key"
   Expand-Peter -ArchiveFile "myarchive.7z" -RestoreFolder ".\restorepack\" -SecretKey "longAndComplex9!key"
 
#>

function Expand-Peter
{
Param( 
    [Parameter(Mandatory)][String] $ArchiveFile,
    [Parameter(Mandatory)][String] $RestoreFolder,
    [String] $RecipientKey,
    [String] $SecretKey,
    [String] $SecretFile, 
    [String] $LogPath
) 

    if (($null -ne $LogPath) -and ($LogPath -ne ""))
    {
        $global:LogPathName = $LogPath
    }

    Open-Log
    
    Write-Log "Function 'Expand-Peter' parameters follow"
    Write-Log "Parameter: ArchiveFile   Value: $ArchiveFile "
    Write-Log "Parameter: RestoreFolder   Value: $RestoreFolder "
    Write-Log "Parameter: RecipientKey   Value: $RecipientKey "
    if ($null -eq $SecretKey) {
        Write-Log "Parameter: SecretKey   Value: (null)) "
    } else {
        Write-Log "Parameter: SecretKey   Value: ************** "
    }
    Write-Log "Parameter: SecretFile   Value: $SecretFile "
    Write-Log "Parameter: LogPath   Value: $LogPath "
    Write-Log ""

    
    If (!(Test-Path -Path $ArchiveFile )) {    
        Write-Log "Archive file '$ArchiveFile' does not exist"
        Write-Host "Archive file '$ArchiveFile' does not exist" -ForegroundColor Red
        Close-Log
        return
    }

    if ($RecipientKey -eq "") {
        $getEnvName = $(Get-SoftwareName) + "_RECIPIENTKEY"
        if ([System.Environment]::GetEnvironmentVariable($getEnvName) -ne "" -and $null -ne [System.Environment]::GetEnvironmentVariable($getEnvName)) {
            $RecipientKey = [System.Environment]::GetEnvironmentVariable($getEnvName)
        }
    }

    if (($RecipientKey -eq "") -and ($SecretKey -eq "")) {
        Write-Log "Recipient Key name or Secret Key required for unpacking" 
        Write-Host "Recipient Key name or Secret Key required for unpacking" -ForegroundColor Red
        Close-Log
        return
    } 
    
    if ($SecretKey -eq "") {
        if ($SecretFile -eq "")
        {
            $SecretFile = $ArchiveFile + ".key"
        }
    
        If (!(Test-Path -Path $SecretFile )) {    
            Write-Log "Secret file '$SecretFile' does not exist"
            Write-Host "Secret file '$SecretFile' does not exist" -ForegroundColor Red
            Close-Log
            return
        }
    
        $secret = Unprotect-CmsMessage -To $RecipientKey -Path $SecretFile
    } else {
        $secret = $SecretKey
    }

    Write-Log "Restoring files to '$RestoreFolder'"
    Write-Log "Archive file is '$ArchiveFile'"

    # Uncompress the data files
    Expand-7Zip -ArchiveFileName $ArchiveFile -TargetPath $RestoreFolder -Password $secret
    Write-Log "Contents unpacked from archive file '$ArchiveFile' to folder '$RestoreFolder'"
    Write-Host "Contents unpacked from archive file '$ArchiveFile' to folder '$RestoreFolder'" -ForegroundColor Green

    Close-Log
}



<#
 .Synopsis
  Reconcile a list of files in a CSV to the files
  in a retsored folder.

 .Description
  The process reads every record in a CSV file and locates the file
  in the restore folder.  The attributes of the file on disk are then
  compared to details held on the CSV file.

  Mismatches such as existence of the file or the size are reported.
 
 .Parameter RestoreFolder
  The target path to the restore folder location.

  The path can be a local drive, mapped network drive or a network shared folder
  location such as \\MediaStor\MyLibrary.

  The restore folder parameter cannot be alist file, i.e. begins with a "@" symbol.

  The restore folder parameter is mandatory.

 .Parameter ReconcileFile
  The name of the reconfile file name to use.

  If the file location and name is not provided, the default file is
  used and its existence in the current directory or the restore folder
  is used.

 .Parameter ExtendedCheck
  Switch to enable extended checking.  The default is false because
  in many restores same attributes are changed.

 .Parameter LogPath
  The log folder where log files are written.  If the folder does not
  exist then it is created.  You need write access rights to this location.

 .Notes
  This script will reconcile CSV file contents with the files
  in the specified folder.  It does not check for extra files
  in the folder.
   
  The following environment variables are supported:
  - PETERDOCS_LOGPATH

 .Example
   # Reconcile folder ".\restorefolder\" using default reconcile file
   Compare-Peter -RestoreFolder ".\transferfolder\" 
 
 .Example
   # Reconcile folder ".\restorefolder\" using the reconcile
   # file located at "C:\reconcileme.csv"
   Compare-Peter -RestoreFolder ".\transferfolder\"  -ReconcileFile "C:\reconcileme.csv"
#>

function Compare-Peter
{
Param( 
    [Parameter(Mandatory)][String] $RestoreFolder,
    [String] $ReconcileFile,
    [String] $RootFolder,
    [Switch] $ExtendedCheck,
    [String] $LogPath
) 

    if (($null -ne $LogPath) -and ($LogPath -ne ""))
    {
        $global:LogPathName = $LogPath
    }

    Open-Log
    
    Write-Log "Function 'Compare-Peter' parameters follow"
    Write-Log "Parameter: RestoreFolder   Value: $RestoreFolder "
    Write-Log "Parameter: ReconcileFile   Value: $ReconcileFile "
    Write-Log "Parameter: RootFolder   Value: $RootFolder "
    Write-Log "Parameter: ExtendedCheck   Value: $ExtendedCheck "
    Write-Log "Parameter: LogPath   Value: $LogPath "
    Write-Log ""

    If (!(Test-Path -Path $RestoreFolder )) {    
        Write-Log "Folder '$RestoreFolder' does not exist"
        Write-Host "Folder '$RestoreFolder' does not exist"  -ForegroundColor Red
        Close-Log
        return
    }

    if ($ReconcileFile -eq "")
    {
        $ReconcileFile = Join-Path -Path $RestoreFolder -ChildPath $default_reconcileFile
        Write-Log "Using default reconciliation file '$ReconcileFile'"
        Write-Host "Using default reconciliation file '$ReconcileFile'" 
        If (!(Test-Path -Path $ReconcileFile )) {    
            $checkReconcileFile = Join-Path -Path ".\" -ChildPath $default_reconcileFile
            If (Test-Path -Path $checkReconcileFile ) {    
                $ReconcileFile = $checkReconcileFile
            }
        }
    }
    If (!(Test-Path -Path $ReconcileFile )) {    
        Write-Log "Reconciliation file '$ReconcileFile' does not exist"
        Write-Host "Reconciliation file '$ReconcileFile' does not exist" -ForegroundColor Red
        Close-Log
        return
    }

    Write-Log "Reconciling documents transferred"
    Write-Host "Reconciling documents transferred"

    Write-Log "Using reconciliation file '$ReconcileFile'"
    
    $totalFileCount = 0
    $totalFileSize = 0
    $errorCount = 0
    $errorCreateCount = 0
    $missingFileCount = 0
    $missingHash = $false

    Import-Csv $ReconcileFile | ForEach-Object {
        $totalFileCount = $totalFileCount +1 
        if ($RootFolder -ne "") {
            $adjustedName = $_.FullName.Replace($RootFolder, "\")
            $restoreFileName = $(Join-Path -Path $RestoreFolder -ChildPath $adjustedName)    
        } else {
            $restoreFileName = $(Join-Path -Path $RestoreFolder -ChildPath $_.FullName)    
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

            # Note that last / write access time is not checked by default as it will commonly be changed after restore
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
        Write-Warning "Reconcile file had one or many or all blank hash entries" 
    }

    Write-Log "Total file count is $totalFileCount with $errorCount errors"
    Write-Log "There are $missingFileCount missing files"

    if ($errorCreateCount -gt 0) {
        Write-Log "File create mismatch count is $errorCreateCount" 
        Write-Host "File create mismatch count is $errorCreateCount" -ForegroundColor Red
    }

    if ($errorCount -gt 0) {
        Write-Host "Total file count is $totalFileCount with $errorCount errors"  -ForegroundColor Red
    } else {
        Write-Host "Total file count is $totalFileCount with $errorCount errors"  -ForegroundColor Green
    }
    if ($missingFileCount -gt 0) {
        Write-Host "There are $missingFileCount missing files"  -ForegroundColor Red
    }

    Close-Log
}

$getEnvName = $(Get-SoftwareName) + "_LOGPATH"
if ([System.Environment]::GetEnvironmentVariable($getEnvName) -ne "" -and $null -ne [System.Environment]::GetEnvironmentVariable($getEnvName)) {
    $global:LogPathName = [System.Environment]::GetEnvironmentVariable($getEnvName)
}
