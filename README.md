# ptrFiles - Protect, Transfer, Reconcile Files

## Summary

ptrFiles is for Protecting, Transfering and Reconciling Files on remote computer
where the computers are isolated or on different networks.

The process uses a Windows PowerShell script and both the source and target computers
that execute the code are required to be installed with Windows PowerShell.

The folder contents at source are archived and encrypted into a single file.  You 
transfer the file to your target, where the content are unpacked using the decryption
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

The script was born out a necessity to transfer a large volume of photographs
from one server to another, where shared network drives was not a feasible
solution.

## Usage

Packages source folder contents into a 7ZIP file, adding a reconciliation
file to the 7ZIP file and then encrypting the contents.  Send

* this script
* the 7ZIP package file 
* plus optional SecretFilename ( if using RecipientKeyName ) to the target or recipient.

The source folder is not altered and only read rights are required. A log
file is written at exceution to record activity.

The SecretFileName can be sent via email, while the 7ZIP can go different routes
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
"ptr_files_yyyy-MM-dd.log"

You will need to have installed the 7Zip4Powershell PowerShell cmdlet 
before using the pack or unpack actions.  You can install the cmdlet
by executing 
.\ptrFiles.ps1 -Action install -Path ".\"
