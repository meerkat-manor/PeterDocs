# PeterDocs - Protect, Transfer, Reconcile Documents

## Summary

PeterDocs is for [Protecting](Encryption.md), [Transferring](SendArchive.md) and [Reconciling](Reconcile.md) documents
on a remote computer where the computers are isolated or on different networks and not accessible via
file network shares.

The PowerShell module is available on [PowerShell Gallery](https://www.powershellgallery.com/packages/PeterDocs)

The process uses a Windows PowerShell module and script.  Both the source and target computers
that execute the code are required to have Windows PowerShell installed.

Use the script to create an encrypted archive of the source folder and its contents, then
transfer the archive file to your target, where the content are unpacked using the decryption
key. After archive contents are restored you can execute the reconcile function
to verify that the contents are transferred, unaltered.

See [Quick Start](QuickStart.md) if you are ready to start and don't need the details.

If you have access to both source and target folders as shared folders or even
on the same computer, then you should consider using tools such as:

* Microsoft ROBOCOPY  - See [Alternate Uses](./Docs/AlternateUses.md)
* rsync

Alternatively, you can use backup and restore utilities on the folder, and rely that
the contents are restored correctly.  If you want this to be secure, ensure
the backup is encrypted.

**Note**: If you require reconciliation (comparison) of files between the source
and target, then you may be required to use additional software.  An example is
JAM Software FileList.

**Note**: Disk size utilities are not suitable for transferring/copying content

## Background

The script was born out of necessity to transfer a large volume of photographs
from a media server to cloud storage for backup.  Commonly photographs are stored in many
folders and can be large in number and size because of the increased
resolution of digital cameras.

The backup also required to be secure from accidental distribution.  The backup is not secured
from accidental or malicious deletion, which require different controls.

## Usage

Some basic commands in sequence are demonstrated below.  Please alter before use:

```powershell
# Create the archive file
Compress-Peter -SourceFolder "~/Pictures/" -Secret "c0mpleX%S3cret" 
# Send the archive to S3
Send-Peter -ArchiveFile "PETERDOCS_20210625_1245.7z" -TargetPath "s3://bucketname/pathpeter/PETERDOCS_20210625_1245.7z"
# Fetch the archive from S3
Receive-Peter -ArchiveFile "myarchive.7z" -SourcePath "s3://bucketname/pathpeter/PETERDOCS_20210625_1245.7z" 
# Expand the archive 
Expand-Peter -RestoreFolder "c:\backup\pictures" -Secret "c0mpleX%S3cret" -ArchiveFile "myarchive.7z"      
# Compare the restored files
Compare-Peter -RestoreFolder "c:\backup\pictures"
```

The above commands are using the default settings for certain options.

Packages source folder contents into a 7ZIP file, adding a reconciliation
file to the 7ZIP file and then encrypting the contents.  Send

* this script or instructions on where to get the script
* the 7ZIP package file
* plus optional Secret File ( if using Recipient Key ) to the target or recipient.

Alternatively you can direct the recipient to the PowerShell Gallery and ask them to
download the PeterDocs module and invoke the restore and reconcile commands from
within a PowerShell terminal window.

The source folder is not altered and only read rights are required. A log
file is written at execution to record activity.

The Secret File can be sent via email, while the 7ZIP can go different routes
due to possible size such as:

* Cloud storage provider
* HTTPS web file upload
* SFTP transfer
* USB stick

At the target, unpack the contents to a folder and reconcile the results.  You
will need write access on the target storage. A log file is written at execution
to record activity.

Your bulk file transfer is encrypted in transit.  Note that if you use the
SecretKey method the encrypted contents will only be as secure as the strength
of your secret.

You can use storage providers such as Dropbox, AWS S3, Google Drive, OneDrive or BackBlaze
and your documents have additional protection.

A log file is produced on execution.  Repeated executions on the same day
will add text content to the same log file.  The default log name takes the form:
"PETERDOCS_yyyy-MM-dd.log"

You will need to install the PeterDocs module from the PowerShell gallery or
via local file NuGet package file if Internet access is limited.

See the [Advanced Usage](Docs/Advanced.md) for more advanced options.

## Limitations

### Secure string

The current version does not use secure strings for password protection 
within the code.  You data is stil protected with encryption.

## Path length

There is a limitation with the PowerShell functions used within PeterDocs
of file paths having to be 260 characters in length or less.

If you have long file paths, the processing will fail.  A possible 
work around is to use mapped net work drive even on your local sourced
file.  The command in PowerShell would be something like:

```powershell
New-PSDrive "X" -PSProvider FileSysytem -Root "$Source" 
```

## Further Reading

[Design](Docs/Design.md)

[Install](Docs/Install.md)

[Compress](Docs/Compress.md)
