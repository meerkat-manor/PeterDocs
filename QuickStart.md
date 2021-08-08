# PeterDocs - Quick Start

If you are in a hurry, comfortable to use ``PeterTask.ps1`` and want to accept the defaults
then this is what you need to do.

1. Download PowerShell file [PeterTask.ps1](https://raw.github.com/) to a lcoal directory.
2. Open a PowerShell terminal where the above file is stored locally and execute command

    ```powershell
        Install-Module -Name PeterDocs  -Scope CurrentUser    
    ```

3. Run command below substituting the names as applicable

    ```powershell
        .\PeterTask.ps1 -Task Compress -ArchiveFile .\myfiles.7z  -Path <document path> -SecretKey <complex password>
    ```

4. Send the 7Zip file to where you wish to save or restore. _Hint:_ See [SendArchive](./Docs/SendArchive.md)
5. If you are restoring then run command below substituting the names as applicable

    ```powershell
        .\PeterTask.ps1 -Task Expand -ArchiveFile .\myfiles.7z  -Path <restore path> -SecretKey <complex password>
    ```

6. If you restored and want to reconcile the restore then run command below substituting the names as applicable

    ```powershell
        .\PeterTask.ps1 -Task Compare -Path <restore path> 
    ```

## Advanced security

If you are sending the documents and only want the recipient to be able to unpack the contents then
read the [Encryption](./Docs/Encryption.md) document.

Using **-RecipientKey** option in above commands secures the contents to only the recipient using
asymmetric encryption on an internal complex password.
