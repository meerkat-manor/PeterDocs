# PeterDocs - Protect, Transfer, Reconcile Dcouments

## Summary

PeterDocs is for [Protecting](Encryption.md), [Transferring](SendArchive.md) and [Reconciling](Reconcile.md) documents
on a remote computer where the computers are isolated or on different networks.

The process uses a Windows PowerShell module and script.  Both the source and target computers
that execute the code are required to have Windows PowerShell installed.

Use the script to create an encrypted archive of the source folder and its contents, then
transfer the archive file to your target, where the content are unpacked using the decryption
key. After archive contents are restored you can execute the reconcile function
to veriy that the contents are transferred, unaltered.

If you have access to both source and target folders, then you should consider
using tools such as:

* Microsoft ROBOCOPY
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
from a media server to cloud storage.  Commonly photographs are stored in many
folders and can be large in number and size because of the increased
resolution of digital cameras.

## Usage

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
will need write access on the target storage. A log file is written at exceution
to record activity.

Your bulk file transfer is encrypted in transit.  Note that if you use the
SecretKey method the ecnrypted contents will only be as secure as the strength
of your secret.

You can use storage providers such as Dropbox, AWS S3, Google Drive, OneDrive or BackBlaze
and your documents have additonal protection.

A log file is produced on execution.  Repeated executions on the same day
will add text content to the same log file.  The default log name takes the form:
"PETERDOCS_yyyy-MM-dd.log"

You will need to install the PeterDocs module from the PowerShell gallery or
via local file NuGet package file if Internet access is limited.

## Further Reading

[Design](Design.md)

[Install](Install.md)

[Compress](Compress.md)
