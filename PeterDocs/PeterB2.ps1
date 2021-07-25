
$default_reconcileFile = "##protect_transfer_reconcile_files##.csv"
$default_profile = "default"
$default_archiveFile = ".\ptr_file_##date##.7z"



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
            Write-Error -Exception "Unable to authenticate with given API Key.`n`r$errorDetail" `
                -Message "Unable to authenticate with given API Key.`n`r$errorDetail" -Category AuthenticationError
            #throw "Unable to authenticate with given APIKey.`n`r$errorDetail"
            throw $_
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

