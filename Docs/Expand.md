# Expand Archive

## Why

The objective is to restore or clone the documents in a new location.

## When

The documents can be restored/cloned after the archive file and key file
(if applicable) are received at the new location.

## How

To perform the expand and restore/clone you execute the ```Expand-Peter``` function.

```powershell
Expand-Peter
    -ArchiveFile <String>
    -RestoreFolder <String>
    -RecipientKey <String>
    -SecretKey <String>
    -SecretFile <String>
    -LogPath <String>
```

If you encrypted the archive file with a ```RecipientKey``` then you will need
the private key of the recipient and the ".key" file.  You can specify the
```SecretFile``` if it is not the default name of the archive file followed
by the extension ".key"

You cannot decrypt the archive file if you do not have the private key or the
".key" file.

To expand the archive you will need write access to the ```RestoreFolder``` location.

## What

The ```Expand-Peter``` decrypts the archive file and expands the contents into
the specified restore folder.  It does not perform a reconciliation which is the
next step.

## Reconcile Usage

Please read next the documentation on [reconciling the archive](Reconcile.md)
