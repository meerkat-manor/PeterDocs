# Advanced Usage

There are various options for using PeterDocs.  The following sections will cover some of these.

## File Filter

The ``-FileFilter`` parameter allows selection of files that are to be included into the archive file.
The parameter only applies to the compress function or buidling the reconciliation file.

For example:

```powershell
Compress-Peter -SourceFolder "~/Pictures/" -Secret "c0mpleX%S3cret"  -FileFilter "*.jpg"
```

will only include files with the extension ".jpg"

```powershell
Compress-Peter -SourceFolder "~/Pictures/" -Secret "c0mpleX%S3cret"  -FileFilter "IMG9*.jpg"
```

will only include files with the extension ".jpg" and starting with the characters "IMG90"

## ReconcileFile

The ``-ReconcileFile`` parameter allows specification of the reocnciliation file if you
wish to select your own name.

For example:

```powershell
Compress-Peter -SourceFolder "~/Pictures/" -Secret "c0mpleX%S3cret"  -ReconcileFile "reconcile_batch2.csv"
```

will generate a reconcile file named "reconcile_batch2.csv" and place it into the 7Zip archive.  Remember
to specify the reconcile file on the compare, something like this:

```powershell
Compare-Peter -RestoreFolder "c:\backup\pictures"  -ReconcileFile "reconcile_batch2.csv"
```

## SecretFile

The ``-SecretFile`` parameter allows specification of the secret file if you
wish to select your own name.  This parameter is only applicable with the
``-RecipientKey`` parameter

For example:

```powershell
Compress-Peter -SourceFolder "~/Pictures/" -RecipientKey "meerkat@merebox.com"  -SecretFile "mypictures.key"
```

will generate a secret file named "mypictures.key".  Remember to send this file to your recipient
and to specify the secret file on the expand, something like this:

```powershell
Expand-Peter -RestoreFolder "c:\backup\pictures"  -RecipientKey "meerkat@merebox.com"  -SecretFile "mypictures.key" -ArchiveFile "myarchive.7z" 
```

## LogPath

The ``-LogPath`` parameter allows definition of the folder that will contain the
execution log.  The name of the log file is automatically generated for you and
includes the date.

## Compression Level

By setting the Compression level to a value recognized by the 7Zip4Powershell module you can gain more control
of the compresison.  The main use case here is for documents that are already compressed and would
not benefit from future compression.  To use this feature you need to set the environment variable.

If all documents are JPEG pictures then setting this value can speed up the compress process
and potentially save a few kilobytes of 7Zip archive size.

An example for archiving a source folder with already compressed files is:

```powershell
$env:PETERDOCS_7ZIPLEVEL="None"
Compress-Peter -SourceFolder "./zip_files" -RecipientKey "meerkat@merebox.com" -ArchiveFile .\myarchive.7z -ExcludeHash
```
