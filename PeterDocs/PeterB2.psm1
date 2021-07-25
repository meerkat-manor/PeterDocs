

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


function Send-B2Upload {
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



function Receive-B2Download {
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


