<#
 .Synopsis
   Allows the secure transfer and reconciliation of a large number of files

   PTR : Protect, Transfer, Reconcile files

 .Description
   Packages source folder contents into a 7ZIP file, adding a reconciliation 
   file to the 7ZIP file and then encrypting the contents.  Send 
   * this script
   * the 7ZIP package file 
   * plus optional SecretFile ( if using RecipientKey )
   to the target or recipient.
   
   The source folder is not altered and only read rights are required. A log
   file is written at exceution to record activity.

   The SecretFile can be sent via email, while the 7ZIP can go different routes 
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
   "PETERDOCS_yyyy-MM-dd.log"

   You will need to have installed the 7Zip4Powershell PowerShell cmdlet 
   before using the pack or unpack actions.  You can install the cmdlet
   by executing 
   .\ptrDocs.ps1 -Action install -Path ".\" 


 .Parameter Task
  Action to perform, which can be:
  - Compress            : Archive the contents of a folder(s)
  - Put                 : Send the archive to AWS S3 or Backblaze
  - Get                 : Receive the archive from AWS S3 or Backblaze
  - Expand              : Unpack the archive, but no reconfile is performed
  - Compare             : Reconcile the contents in the restored folder
  - NewReconcile        : Generate reconfile file.  The pack process does this automatically.
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

  SecretKey can also be specifed with Environment variable 
  "PETERDOCS_SECRETKEY"

  Note: Currently the script does not user Secure Strings

 .Parameter ArchiveFile
  The location and name of the 7ZIP file.  If not supplied a default 7ZIP file name
  will be generated in the current directory for the pack action.

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
  The name of the reconcile file name to generate during pack or use 
  during unpack.  This is a file name without path.  If no value is 
  supplied, then a default name is generated.
  The reconcile file is included into the root of the 7ZIP file.
  Once a reconcile is executed, you can delete this file from the 
  restored location.

  The default name is "##peter_files##.csv"

 .Parameter SecretFile
  The secret file name is used with RecipientKey to secure the
  internally generated password for the 7ZIP file.  When unpacking the
  7ZIP file you will need access to this file if RecipientKey
  was used. If not supplied a default name is used.  This file is 
  encrypted with RecipientKey.

  The default name is the archive file name with postfix  ".key"

 .Parameter CloudProfile
  The profile name to use for Install and Put/Get actions.  The
  default for Install is "UserScope".  The default for "Put" or "GET"
  is "default"
  Profile name can also be specifed with Environment variable 
  "PETERDOCS_PROFILE"

 .Parameter ExcludeHash
  Exclude the file hash from the reconcile file.  As producing a file
  hash takes compute cycles during pack, you can select to bypass this 
  generation to speed up the packaging.  Excluding the hash does reduce 
  the functionality of the reconciliation at unpack.

 .Parameter IncludeExif
  Include Exif details into separate file for picture files.

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
  - PETERDOCS_SECRETKEY
  - PETERDOCS_PROFILE
  - PETERDOCS_ACCOUNTKEY
  - PETERDOCS_LOGPATH

 
 .Example
   # Pack and encrypt all files in folder ".\transferpack\" using a private-public key
   # A file with the postifx ".key" is also generated alongside the 7ZIP file
   .\PeterTask.ps1 -Task compress -Path ".\transferpack\" -RecipientKey data@mycompany
 
 .Example
   # Unpack all files in 7ZIP file "transfer_protect_yyyMMdd_hhmm.7z" to folder ".\targetdir" using a private-public key
   # You will need the file "transfer_protect_yyyMMdd_hhmm.7z.key" to unpack the encrypted 7ZIP file
   .\PeterTask.ps1 -Task expand -ArchiveFile "transfer_protect_yyyMMdd_hhmm.7z" -Path ".\targetdir" -RecipientKey data@mycompany
 
 .Example
   # Reconcile files in folder ".\targetdir"
   .\PeterTask.ps1 -Task compare -Path ".\targetdir" 

 .Example
   # Pack and encrypt all files in folder ".\transferpack\" using a password
   .\PeterTask.ps1 -Task compress -Path ".\transferpack\" -SecretKey "fjks932c-x=23ds"
 
 .Example
   # Unpack all files in 7ZIP file "transfer_protect_yyyMMdd_hhmm.7z" to folder ".\targetdir" using a password
   .\PeterTask.ps1 -Task expand -ArchiveFile "transfer_protect_yyyMMdd_hhmm.7z" -Path ".\targetdir" -SecretKey "fjks932c-x=23ds"

 .Example
   # Pack and encrypt all files in folder ".\transferpack\02*" where the folder name starts with "02" using a password
   .\PeterTask.ps1 -Task compress -Path ".\transferpack\02*" -SecretKey "fjks932c-x=23ds"

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [ValidateSet("Compress","Expand","Compare","NewReconcile","Put","Get","ArchiveInformation")]
    [Alias("Action")]
    [String] $Task, 

    [Parameter(Mandatory)]
    [Alias("Directory","DirectoryPath","Folder","FolderPath")]
    [String] $Path, 

    [Alias("Recipient")]
    [String] $RecipientKey,

    [Alias("Password")]
    [String] $SecretKey, 

    [Alias("CompressFile")]
    [String] $ArchiveFile, 

    [String] $RootFolder,

    [Alias("Filter")]
    [String] $FileFilter,

    [String] $ReconcileFile, 

    [String] $SecretFile, 

    [Alias("Profile", "Username")]
    [String] $CloudProfile,

    [Alias("Hash")]
    [switch] $ExcludeHash,

    [Alias("Exif")]
    [switch] $IncludeExif,
       
    [String] $VolumeSize = "-1",

    [String] $LogPath = ""

)

Import-Module .\PeterDocs

    $actioned = $false

    if ($task -eq "Compress") {
        $actioned = $true
        Compress-Peter -SourceFolder $path -SecretKey $SecretKey  -SecretFile $SecretFile -RecipientKey $RecipientKey -ArchiveFile $archiveFile -ReconcileFile $reconcileFile -RootFolder $rootFolder -FileFilter $fileFilter -VolumeSize $VolumeSize -LogPath $LogPath -ExcludeHash:$ExcludeHash -IncludeExif:$IncludeExif
    }


    if ($task -eq "Put") {
        $actioned = $true       
        Send-Peter -ArchiveFile $archiveFile -TargetPath $path -SecretFile $secretFile -TargetProfile $cloudProfile -LogPath $LogPath
    }


    if ($task -eq "Get") {
        $actioned = $true
        Receive-Peter -ArchiveFile $archiveFile -SourcePath $path -SecretFile $secretFile -SourceProfile $cloudProfile -LogPath $LogPath
    }


    if ($task -eq "Expand") {
        $actioned = $true
        Expand-Peter -RestoreFolder $path -SecretKey $secretKey -SecretFile $secretFile  -RecipientKey $RecipientKey -ArchiveFile $ArchiveFile -LogPath $LogPath 
    }


    if ($task -eq "NewReconcile") {
        $actioned = $true
        if ($null -eq $reconcileFile -or $reconcileFile -eq "") {
          Write-Error "Reconcile file name required (-ReconcileFile)"
          return
        }
        New-PeterReconcile -ReconcileFile $reconcileFile -SourceFolder $path -Feedback -RootFolder $rootFolder -FileFilter $fileFilter -LogPath $LogPath  -ExcludeHash:$ExcludeHash -IncludeExif:$IncludeExif
    }


    if ($task -eq "Compare") {
        $actioned = $true
        Compare-Peter -ReconcileFile $reconcileFile -RestoreFolder $path -RootFolder $rootFolder -LogPath $LogPath -ExcludeHash:$ExcludeHash 
    }

    if ($task -eq "ArchiveInformation") {
        $actioned = $true
        if (($RecipientKey -eq "") -and ($SecretKey -eq "")) {
            Write-Error "Recipient Key or Secret Key required for 7Zip information"
            return
        } 
        
        if ($SecretKey -eq "") {
            if ($SecretFile -eq "")
            {
                $SecretFile = $ArchiveFileName + ".key"
            }
            if (!(Test-Path -Path $SecretFile)) {
              Write-Log "Secret file '$SecretFile' not found" 
              Write-Host "Secret file '$SecretFile' not found"  -ForegroundColor Red
              Close-Log
              return
            }
            $secret = Unprotect-CmsMessage -To $RecipientKey -Path $SecretFile
        } else {
            $secret = $SecretKey
        }
        Write-Host "Retrieving archive information"      
        Get-7ZipInformation -ArchiveFileName $ArchiveFile -Password $secret
    }


    if (!($actioned))
    {
        Write-Host "Unknown action '$task'.  No processing performed"  -ForegroundColor Red
        Write-Host "Recognised actions: "
        Write-Host "    Compress             : Pack folder contents into secure 7Zip file"
        Write-Host "    Put                  : Put or send the archive file to remote destination"
        Write-Host "    Get                  : Get or fetch the archive from remote location"
        Write-Host "    Expand               : Unpack folder contents from secure 7Zip file"
        Write-Host "    Compare              : Reconcile files in unpack folder with list of packed files"
        Write-Host "    NewReconcile         : Generate a reconcile file without packing"
        Write-Host "    ArchiveInformation   : Fetch archive information from archive file"
        
        Write-Host ""
        Write-Host "For help use command "
        Write-Host "    Get-Help .\ptrDocs.ps1"
    }

