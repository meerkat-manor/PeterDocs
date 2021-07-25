

Function Get-ExifContents {
param(
    $ImageStream, 
    [int] $ExifCode
)

    Try {
        if (-not $ImageStream.PropertyIdList.Contains($ExifTagCode))
        {
            $Value = "<empty>"
        } else {
            $PropertyItem = $ImageStream.GetPropertyItem($ExifCode)
            $valueBytes = $PropertyItem.Value
            $Value = [System.Text.Encoding]::ASCII.GetString($valueBytes)
        }
    }
    Catch{
        $Value = "<empty>"     
    }

    return $Value
}
    
    
Function Get-ImageFileContents {
param(
    [String] $ImageFile
)

    Try {
        $fullPath = (Resolve-Path $ImageFile).Path
        $fs = [System.IO.File]::OpenRead($fullPath)
        $image = [System.Drawing.Image]::FromStream($fs, $false, $false)

        $maker = Get-ExifContents -ImageStream $image -ExifCode 271
        $model = Get-ExifContents -ImageStream $image -ExifCode 272
        $version = Get-ExifContents -ImageStream $image -ExifCode 305
        $dateTime = Get-ExifContents -ImageStream $image -ExifCode 306
        $latRef = Get-ExifContents -ImageStream $image -ExifCode 1
        $longRef = Get-ExifContents -ImageStream $image -ExifCode 3
    
        $ExifData = [PSCustomObject][ordered]@{
            File = $ImageFile
            CameraMaker = $maker
            CameraModel = $model
            SoftwareVersion = $version
            DateTaken = $dateTime
        }

        $image.dispose()
        $fs.Close()

        Write-Host " File '$($ExifData.File)' and maker '$($ExifData.CameraMaker)' "

        return $ExifData
    }
    Catch {
        Write-Error "Error Opening '$ImageFile'"
        if ($image) {
            $image.dispose()
        }
        if ($fs) {
            $fs.close()
        }
        return $null
    }
}

    