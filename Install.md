# Install

PeterDocs is a module that can be donwloaded or installed from
[PowerShell Gallery](https://xx.com/)

## Pre-requisites

PowerShell must be installed before you can use the PeterDocs module.

## Automated install

A generic script is available to allow you to install the required
modules.  The same script can be used to exceute as a sample to
execute the actual packing, unpacking and reconciliation.

You can get the generic script from [Github as ptrDocs.ps1](https://raw.githubusercontent.com/meerkat-manor/ptrFiles/main/ptrDocs.ps1)

After downloading the file, execute the script as follows to install the modules

```powershell
.\ptrDocs.ps1 -Action install -Path .\
```

## Manual install

Execute the following commands to install the module under the current user

```powershell
    Install-Module -Name 7Zip4Powershell -Scope CurrentUser
    Install-Module -Name AWS.Tools.Installer -Scope CurrentUser
    Install-Module -Name AWS.Tools.S3  -Scope CurrentUser    
    Install-Module -Name Meerkat.PeterDocs  -Scope CurrentUser    
```

Execute the following commands to install the module for all users.  You will
need administrator rights.

```powershell
    Install-Module -Name 7Zip4Powershell -Scope AllUsers 
    Install-Module -Name AWS.Tools.Installer -Scope AllUsers 
    Install-Module -Name AWS.Tools.S3  -Scope AllUsers 
    Install-Module -Name Meerkat.PeterDocs  -Scope AllUsers    
```

## Compress Usage

Please read next the documentation on [creating an archive file](Compress.md)
