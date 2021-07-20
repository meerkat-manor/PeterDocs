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

 .Parameter CloudProfile
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

Import-Module .\PeterFiles

$default_dateLocal = Get-Date -Format "yyyyMMdd_HHmm"
$default_archiveFile = ".\ptr_file_##date##.7z"
$default_reconcileFile = "##protect_transfer_reconcile_files##.csv"



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
