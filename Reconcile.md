# Reconcile

A reconcile file is generated as part of the Compress process and packed with the 7ZIP file.

## Why

When transferring or cloning documenmts to another location, you will want to
verify that the same documents have been restored unaltered at the destination.

## When

After the documents have been expanded and restored at the target
the next step to perform is reconcile the restored documents
against the reconcile file.

## How

The archive file and therefore the restore includes a reconciliation file
in the root folder.  The reconciliation file is a CSV formatted file
listing all the documents and associated metadata.

To perform the reconciliation you execute the ```Compare-Peter``` function.

```powershell
Compare-Peter 
    -RestoreFolder <String>
    -ReconcileFile <String> 
    -RootFolder <String>
    -ExtendedCheck
    -LogPath <String>
```

## What

The reconciliation checks:

1. Path to the document
2. Name of the document
3. Size of the document
4. Hash of document
5. Creation date and time of the document

The document last update and time is not checked because the value
will reflect the date and time of restore.

The reconciliation summary is displayed in the terminal and the log
wil lhave more information.

If any errors are listed, please investigate the discrepancy.

__Note__: For some restored documents the creation date and time may
have a variation of +/- 2 seconds and this is ignored by the reconciliation
process.

## Finale

Once you have reconciled the documents, you have completed the process.
