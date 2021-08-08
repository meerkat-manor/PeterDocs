# PeterDocs - Quick Start

If you are in a hurry, comfortable to use ``PeterTask.ps1`` and want to accept the defaults
then this is what you need to do.

1. Download PowerShell file [PeterTask.ps1](https://raw.githubusercontent.com/meerkat-manor/PeterDocs/main/PeterTask.ps1) to a local directory.
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

## Just Compare

If your interest is in the reconciliation function of PeterDocs, then assuming you
have two directories, source and target, then the steps to just reconcile are:


1. Download PowerShell file [PeterTask.ps1](https://raw.githubusercontent.com/meerkat-manor/PeterDocs/main/PeterTask.ps1) to a local directory.
2. Open a PowerShell terminal where the above file is stored locally and execute command

    ```powershell
        Install-Module -Name PeterDocs  -Scope CurrentUser    
    ```

3. Run command below substituting the names as applicable

    ```powershell
        .\PeterTask.ps1 -Task NewReconcile -ReconcileFile .\myfiles.csv  -Path <source path>
    ```

4. Send, if required, the generated CSV file to your destination (target)
5. Now compare the destination.  Don't forget to run steps 1. and 2. above on your destination

    ```powershell
        .\PeterTask.ps1 -Task Compare -ReconcileFke .\myfiles.csv -Path <target path> 
    ```

## Advanced security

If you are sending the documents and only want the recipient to be able to unpack the contents then
read the [Encryption](./Docs/Encryption.md) document.

Using **-RecipientKey** option in above commands secures the contents to only the recipient using
asymmetric encryption on an internal complex password.
