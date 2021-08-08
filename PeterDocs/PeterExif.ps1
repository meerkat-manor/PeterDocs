

Add-Type -AssemblyName System.Drawing

function Get-ExifContents {
    param(
        [Parameter(Mandatory)]
        $ImageStream, 
        [Parameter(Mandatory)]
        [int] $ExifCode,
        [Switch] $Numeric,
        [int] $Size = 0,   
        [int] $Parts = 1
    )

    Try {
        $list_id = $ImageStream.PropertyIdList
        if ($list_id.IndexOf($ExifCode) -eq -1) {
            if ($Numeric) {
                $Value = 0     
            } else {
                $Value = ""     
            }
        } else {

            if ($Numeric -and $Size -eq 0) {
                $Size = 8
            }

            $PropertyItem = $ImageStream.GetPropertyItem($ExifCode)
            if ($null -eq $PropertyItem) {
                if ($Numeric) {
                    $Value = 0     
                } else {
                    $Value = ""     
                }
            } else {
                $valueBytes = $PropertyItem.Value
                if ($null -eq $valueBytes) {
                    if ($Numeric) {
                        $Value = 0     
                    } else {
                        $Value = ""     
                    }
                } else {
                    if ($Numeric) {
                        $Value = MakeNumber -Num $valueBytes -Size $Size -Parts $Parts
                    } else {
                        $value = ""
                        0..($valueBytes.Length-1) | ForEach-Object {
                            if ($valueBytes[$_] -ne 0) {
                                $value = $value + [System.Text.Encoding]::ASCII.GetString($valueBytes[$_])
                            }
                        }
                        if ($null -ne $value -and $Size -gt 0 -and $Size -lt $Value.Length) {
                            $Value = $Value.Substring(0,$Size)
                        }
                    }
                }
            }

        }
    }
    Catch{
        if ($Numeric) {
            Write-Host "Type $($valueBytes.GetType())"
            Write-Host "Error in exif: $_"
        } else {
            Write-Host "Error in exif: $_"
        }
        $Value = ""     
    }

    return $Value
}

function Get-ByteMultiplier {
    param(
        [Parameter(Mandatory)]
        [int] $Factor
    )

    $byteMultiplier = 1
    1..$Factor | ForEach-Object {
        $byteMultiplier = $byteMultiplier * 256
    }

    return $byteMultiplier
}

function MakeNumber {
    param(
        [Parameter(Mandatory)]
        [byte[]] $Num,
        [int] $Size,
        [int] $Parts = 1
    )

    if ($null -eq $Num) {
        return "<null>"
    }

    if ($Num.Length -eq $Size -and $Parts -eq 1) {
        if ($Size -eq 1) {
            return ($Num[0])
        }
        if ($Size -eq 2) {
            return ( $Num[0] + 256 * $Num[1] )
        }
    }

    # GPS cords
    if ($Num.Length -eq 24 -and $Parts -eq 3) {
        $First =$Num[0] + (Get-ByteMultiplier 1) * $Num[1] + (Get-ByteMultiplier 2) * $Num[2] + (Get-ByteMultiplier 3) * $Num[3] ;
        $Second=$Num[8] + (Get-ByteMultiplier 1) * $Num[9] + (Get-ByteMultiplier 2) * $Num[10] + (Get-ByteMultiplier 3) * $Num[11] ; 
        $Third=$Num[16] + 256 * $Num[17] + 65536 * $Num[18] + 16777216 * $Num[19] ; 
        return @($first, $second, $third)
    }


    # Shutter
    if ($Num.Length -eq 8 -and $Parts -eq 2) {
        $First =$Num[0] + (Get-ByteMultiplier 1) * $Num[1] + (Get-ByteMultiplier 2) * $Num[2] + (Get-ByteMultiplier 3) * $Num[3] ;
        $Second=$Num[4] + (Get-ByteMultiplier 1) * $Num[5] + (Get-ByteMultiplier 2) * $Num[6] + (Get-ByteMultiplier 3) * $Num[7] ; 
        if ($first -gt 2147483648) {
            $first = $first  - (Get-ByteMultiplier 4)
        } 
        if ($Second -gt 2147483648) {
            $Second= $Second - (Get-ByteMultiplier 4)
        }
        if ($Second -eq 0) {
            $Second= 1
        } 
    
        if (($first -eq 1) -and ($Second -ne 1)) {
            $first = "1"
        } 
    
        return @($first, $second)
    }


    $First =$Num[0] + (Get-ByteMultiplier 1) * $Num[1] + (Get-ByteMultiplier 2) * $Num[2] + (Get-ByteMultiplier 3) * $Num[3] ;
    return $first

}


function Get-ImageFileExif {
    param(
        [Parameter(Mandatory)]
        [String] $ImageFile
    )

    if (!(Test-Path -Path $ImageFile)) {
        Write-Host "File not found: $ImageFile"
        break
    }
    Try {

        $fullPath = (Resolve-Path $ImageFile).Path

        $fileStreamArgs = @($fullPath
            [System.IO.FileMode]::Open
            [System.IO.FileAccess]::Read
            [System.IO.FileShare]::Read
            1024,
            [System.IO.FileOptions]::SequentialScan
        )

        Try {
            $fs = New-Object System.IO.FileStream -ArgumentList $fileStreamArgs
            $image = [System.Drawing.Image]::FromStream($fs)
        } Catch {
            # Error likely because not an image file
            return $null
        }

        $val = Get-ExifContents -ImageStream $image -ExifCode 37378 -Numeric -Size 8 -Parts 2
        if ($null -eq $val -or $val -eq "") {
            $Aperture = ""
        } else {
            if ($val.Length -eq 2) {
                $Aperture = "$($val[0]/$val[1])" 
            } else {
                $Aperture = $val[0]
            }
        }

        # Flash
        $val = Get-ExifContents -ImageStream $image -ExifCode 37385 -Numeric -Size 2
        if (($val % 2) -eq 1){
            $Flash = $true
        } else {
            $Flash = $false
        }

        # Shutterspeed
        $val = Get-ExifContents -ImageStream $image -ExifCode 33434 -Numeric -Size 8 -Parts 2
        if ($null -eq $val -or $val -eq "") {
            $Shutterspeed = ""
        } else {
            if ($val.Length -eq 2) {
                $Shutterspeed = "$($val[0])/$($val[1])" 
            } else {
                $Shutterspeed = $val[0]
            }
        }

        # Latitude
        $val = Get-ExifContents -ImageStream $image -ExifCode 2 -Numeric -Size 24 -Parts 3
        if ($null -eq $val -or $val -eq "") {
            $Latitude = ""
        } else {
            if ($val.Length -eq 3) {
                $Latitude = "$($val[0]).$($val[1]).$($val[2])" 
            } else {
                $Latitude = $val[0]
            }
        }
        # Longitude
        $val = Get-ExifContents -ImageStream $image -ExifCode 4 -Numeric -Size 24 -Parts 3
        if ($null -eq $val -or $val -eq "") {
            $Longitude = ""
        } else {
            if ($val.Length -eq 3) {
                $Longitude = "$($val[0]).$($val[1]).$($val[2])" 
            } else {
                $Longitude = $val[0]
            }
        }


        $ExifData = [PSCustomObject][ordered]@{
            File = $ImageFile

            DateTaken = Get-ExifContents -ImageStream $image -ExifCode 36867 -Size 19
            DateDigitized = Get-ExifContents -ImageStream $image -ExifCode 36868 -Size 19
            DateModified = Get-ExifContents -ImageStream $image -ExifCode 306 -Size 19

            Author = Get-ExifContents -ImageStream $image -ExifCode 40093
            Title = Get-ExifContents -ImageStream $image -ExifCode 40091 #270
            Subject = Get-ExifContents -ImageStream $image -ExifCode 40095
            Comments = Get-ExifContents -ImageStream $image -ExifCode 40092 #37510
            Keywords = Get-ExifContents -ImageStream $image -ExifCode 40094

            Artist = Get-ExifContents -ImageStream $image -ExifCode 315
            Copyright = Get-ExifContents -ImageStream $image -ExifCode 33432

            Height = Get-ExifContents -ImageStream $image -ExifCode 40963 -Numeric
            Width = Get-ExifContents -ImageStream $image -ExifCode 40962 -Numeric
            PixelX = Get-ExifContents -ImageStream $image -ExifCode 40962 -Numeric -Size 8
            PixelY = Get-ExifContents -ImageStream $image -ExifCode 40963 -Numeric -Size 8
            ResolutionX = Get-ExifContents -ImageStream $image -ExifCode 282 -Numeric
            ResolutionY = Get-ExifContents -ImageStream $image -ExifCode 283 -Numeric

            CameraMaker = Get-ExifContents -ImageStream $image -ExifCode 271
            CameraModel = Get-ExifContents -ImageStream $image -ExifCode 272
            CameraLabel = Get-ExifContents -ImageStream $image -ExifCode 51105
            SoftwareVersion = Get-ExifContents -ImageStream $image -ExifCode 305

            LatitudeRef = Get-ExifContents -ImageStream $image -ExifCode 1
            Latitude = $Latitude
            LongitudeRef = Get-ExifContents -ImageStream $image -ExifCode 3
            Longitude = $Longitude

            ExifVersion = Get-ExifContents -ImageStream $image -ExifCode 36864

            Flash = $Flash
            Iso = Get-ExifContents -ImageStream $image -ExifCode 34855 -Numeric 
            FocalLength = Get-ExifContents -ImageStream $image -ExifCode 37386 -Numeric -Size 2
            ShutterSpeed = $Shutterspeed
            Aperture = $Aperture
            FNumber = Get-ExifContents -ImageStream $image -ExifCode 33437 -Numeric -Size 4

        }

        $image.dispose()
        $fs.Close()

        return $ExifData
    }
    Catch {
        Write-Host "Error: $_"
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



function Set-ExifCsvHeader {

    
    $ExifData = [PSCustomObject][ordered]@{
        File = ""

        DateTaken = ""
        DateDigitized = ""
        DateModified = ""

        Author = ""
        Title = ""
        Subject = ""
        Comments = ""
        Keywords = ""

        Artist = ""
        Copyright = ""

        Height = 0
        Width = 0
        PixelX = 0
        PixelY = 0
        ResolutionX = 0
        ResolutionY = 0

        CameraMaker = ""
        CameraModel = ""
        CameraLabel = ""
        SoftwareVersion = ""

        LatitudeRef = ""
        Latitude = ""
        LongitudeRef = ""
        Longitude = ""

        ExifVersion = ""

        Flash = $false
        Iso = 0
        FocalLength = 0
        ShutterSpeed = ""
        Aperture = 0
        FNumber = 0

    }

    $exifRecord = ''
    $first = $true
    $ExifData.PSObject.Properties | foreach-object {
        if ($first) {
            $exifRecord = '"' + $_.Name + '"'
        } else{
            $exifRecord = $exifRecord + ',"' + $_.Name + '"'
        }
        $first = $false
    }

    return $exifRecord

}

function Set-ExifCsvRecord {
    param(
        [Parameter(Mandatory)]
        [PSCustomObject] $ExifData
    )

    $exifRecord = ''
    $first = $true
    $ExifData.PSObject.Properties | foreach-object {
        if ($first) {
            $exifRecord = '"' + $_.value + '"'
        } else{
            $exifRecord = $exifRecord + ',"' + $_.value + '"'
        }
        $first = $false
    }

    return $exifRecord

}