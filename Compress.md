# Compress and Protect

## Source Documents

## Why

## When

## How

To perform the create the archive file you execute the ```Compress-Peter``` function.

```powershell
Compress-Peter
    -SourceFolder <String>
    -RecipientKey <String>
    -SecretKey <String>
    -ArchiveFile <String>
    -ReconcileFile <String>
    -FileFilter <String>
    -SecretFile <String> 
    -ExcludeHash
    -RootFolder <String>
    -LogPath <String>
```

The function requires a ```SourceFolder```.

Either a ```RecipientKey``` or ```SecretKey``` is required.

If no ```ArchiveFile``` name is specified a default name is used.

You can ignore the remaining parameters if you are happy with the defaults.

## What

The ```Compress-Peter``` compressess the contet of the ```SourceFolder``` and saves the result
as the encrypted ```ArchiveFile```.  The archive file also contains the reconciliation file
so that the recipient of the archive is able to reconcile the restore at the remote location.

If a ```RecipientKey``` is used then an extra file (```SecretFile``) is also created.  Do not
loose this file as without it you cannot decrypt the archive contents.

## Send Usage

Please read next the documentation on [sending the archive](SendArchive.md)
