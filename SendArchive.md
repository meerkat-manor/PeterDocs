# Send Archive

## Why

You need to send the archive file to the destination where it is to be restored.

If the destination is directly accessible from your current location, and you
don't need reconciliation, then consider using other tools such as
```Robocopy``` or ```rsync```.

You can use other tools you have available to upload the archive file to
cloud storage.

## When

Send the archive file once it is created.

## How

To send the archive file you use the ```Send-Peter``` function.  It is your choice
on whether you use the ```Send-Peter``` function to send the archive file and ".key"
file or another program or command line.

```powershell
Send-Peter
    -ArchiveFile <String>
    -TargetPath <String>
    -SecretFile <String>
    -TargetProfile <String>
    -AccountId  <String>
    -AccountKey <String>
    -LogPath <String>
```

The ```ArchiveFile`` is the name of the 7ZIP archive file you created.

The ```TargetPath``` is specified as follows:

* s3://bucketname/path/path/archivefile.7z
* b2://bucketname/path/path/archivefile.7z

The "s3" prefix is to upload to AWS S3.  The "b2" prefix
is to upload to Backblaze.

If you are uploading to AWS you can specify the AWS profile name
in parameter ```TargetProfile```.  In this situtation the profile
needs to exist in the AWS credentials on your local device and user profile.

If you are uploading to Backblaze you specify the ```AccountId``` and the
```AccountKey```.  For better security you can save the Account Key as an
environment variable named ```PETERDOCS_ACCOUNTKEY```

You override the ```SecretFile``` file name location on the local device,
if it is not the default name and location.

## What

The function will upload the archive file and key file (if applicable) to
cloud storage.

## Receive Usage

Please read next the documentation on [receiving the archive](ReceiveArchive.md)
