# Receive Archive

## Why

Once the archive file is sent, you need to download it from its intermediate
location if the source and destination locations are not directly connected.

You can user other tools you have available to download the archive file.

## When

The archive is received after it sent.  The assumption is that cloud storage
is being used as an intermediary.

## How

To receive the archive file you sent using the ```Send-Peter``` function you can
execute the ```Receive-Peter``` function.

```powershell
Receive-Peter
    -SourcePath <String>
    -ArchiveFile <String>
    -SecretFile <String>
    -SourceProfile <String>
    -AccountId <String>
    -AccountKey <String>
    -LogPath <String>
```

The ```SourcePath``` is specified as follows:

* s3://bucketname/path/path/archivefile.7z
* b2://bucketname/path/path/archivefile.7z

The "s3" prefix is to download from AWS S3.  The "b2" prefix
is to download from Backblaze.

If you are downloading from AWS you can specify the AWS profile name
in parameter ```SourceProfile```.  In this situation the profile
needs to exist in the AWS credentials on your local device and user profile.

If you are downloading from Backblaze you specify the ```AccountId``` and the
```AccountKey```.  For better security you can save the Account Key as an
environment variable named ```PETERDOCS_ACCOUNTKEY```

You can override the ```SecretFile``` file name location on the local device,
but it is recommended to leave at defaults for a better experience.

## What

The function will retrieve the archive file either from an AWS S3 bucket or
from a Backblaze bucket.

If your archive file is on a web site or network folder then you will need to
use other tools to download the archive file and the key file.

The function will not expand or reconcile the restore at the destination.

Please ensure you have sufficient storage to accommodate the local copy of the
archive and space to unpack it.

## Expand Usage

Please read next the documentation on [expand the archive](Expand.md)
