# Usage

## Usage PeterDocs

The syntax is for each function is below:

```powershell
Compress-Peter
    -SourceFolder <string>    
    [-RecipientKey <string>] | [-SecretKey <string>]
    [-ArchiveFile <string>]
    [-ReconcileFile <string>]
    [-FileFilter <string>]
    [-SecretFile <string>]
    [-ExcludeHash]
    [-IncludeExif]
    [-RootFolder  <string>]
    [-VolumeSize <string>]
    [-LogPath <string>]
    [<CommonParameters>]

Expand-Peter
    -ArchiveFile <string>
    -RestoreFolder <string>    
    [-RecipientKey <string>] | [-SecretKey <string>]
    [-SecretFile <string>]
    [-LogPath <string>]
    [<CommonParameters>]

New-PeterReconcile
    -SourceFolder <string>    
    -ReconcileFile <string>
    [-RootFolder <string>]
    [-FileFilter <string>]
    [-ProcessFileCount <long>]
    [-ExcludeHash]
    [-IncludeExif]
    [-Feedback]
    [-LogPath <string>]
    [<CommonParameters>]

Compare-Peter
    -RestoreFolder <string>    
    [-ReconcileFile <string>]
    [-RootFolder <string>}
    [-ExcludeHash]
    [-ExtendedCheck]
    [-LogPath <string>]
    [<CommonParameters>]

```

## Usage PeterTask

For using the PeterTask, syntax is as simple as shown below. Behind the scenes the
PeterTask calls the functions above:

```powershell

PeterTask
    -Task {Compress, Expand, Compare, NewReconcile, Put, Get, ArchiveInformation}
    -Path <string>
    [-RecipientKey <string>] | [-SecretKey <string>]
    [-ArchiveFile  <string>]
    [-RootFolder  <string>]
    [-FileFilter <string>]
    [-ReconcileFile <string>]
    [-SecretFile <string>]
    [-CloudProfile <string>]
    [-ExcludeHash]
    [-IncludeExif]
    [-LogPath <string>]
    [<CommonParameters>]

```

**NOTE** Please do not use the VolumeSize parameter as it will fail due to a current
issue with the underlying 7zip4 Powershell module.
