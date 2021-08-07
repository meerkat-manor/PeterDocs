# Compress and Protect

## Source Documents

PeterDocs is intended to be used with documents (files) that need to be transferred
or cloned to a remote location securely.  The documents can be binary or text documents,
including personal photographs or sensitive Microsoft Word documents.

At the remote location a reconciliation can be performed to verify that the documents
have been recieved and no alteration occurred.

## Why

When you have a sensitive document or many documents to transfer or clone, it is
efficient to compress, consolidate and encrypt the documents into one archive file and
then restore this archive file at the destination.

## When

You create the archive file when you are ready to transfer the documents.

## How

To create the archive file you execute the ```Compress-Peter``` function.

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

The function requires a ```SourceFolder```.  You need to have
read rights of the source folder and the source folder can be a
lcoal drive or a network drive.

Either a ```RecipientKey``` or ```SecretKey``` is required.

If no ```ArchiveFile``` name is specified a default name is used.

You can ignore the remaining parameters if you are happy with the defaults.

## What

The ```Compress-Peter``` compressess the contet of the ```SourceFolder``` and saves the result
as the encrypted ```ArchiveFile```.  The archive file also contains the reconciliation file
so that the recipient of the archive is able to reconcile the restore at the remote location.

The archive file contains a snapshot of all the existing documents in the source folder,
subject to any filter applied.

If a ```RecipientKey``` is used then an extra file (```SecretFile``) is also created.  Do not
loose this file as without it you cannot decrypt the archive contents.

The ```SourceFolder``` is not written to or updated.

If subsequent changes are made to the documents or more documents are added, then you need
execute the compress again.  The PeterDocs process does not have the capability to
generate delta archive files.

## Send Usage

Once the archive file is created you will commonly send or transfer it to anohter
location where it wll be unpacked.

Please read next the documentation on [sending the archive](SendArchive.md)
