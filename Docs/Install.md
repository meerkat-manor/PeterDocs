# Install

PeterDocs is a module that can be donwloaded or installed from
[PowerShell Gallery](https://xx.com/)

## Pre-requisites

PowerShell must be installed before you can use the PeterDocs module.

## Automated install

When you install ```PeterDocs``` from the PowerShell Gallery, the
required dependencies are installed for you

Execute the following command to install the module under the current user

```powershell
    Install-Module -Name PeterDocs  -Scope CurrentUser    
```

Execute the following command to install the module for all users.  You will
need administrator rights.

```powershell
    Install-Module -Name PeterDocs  -Scope AllUsers    
```

## Compress Usage

Please read next the documentation on [creating an archive file](Compress.md)

## Offline install

If the computer you wish to use PeterDocs module on does not have Internet access,
a common situation for secured servers, then you will need to install the
PeterDocs module manually by following the instructions below.

Please familiarize yourself with all the instructions before commencing so that you are aware of
all steps to be followed.

On a **computer with Internet (PowerShell Gallery) access** do the following steps

1. First check you have PowerShell version 5 or later

```powershell
$PSVersionTabe.PSVersion
```

2. Download the PeterDocs module

```powershell
Save-Module -Name PeterDocs -Path C:\Temp
```

A few folders will be created in C:\Temp.  The names of the folders are
7Zip4PowerShell, AWS.Tools.Common, AWS.Tools.S3, and PeterDocs

3. Compress the new 7Zip4PowerShell, AWS.Tools.Common, AWS.Tools.S3, PeterDocs folders into a single ZIP file
4. Copy the ZIP file to the offline computer

On the **computer lacking Internet (PowerShell Gallery) access** do the following steps

1. First check you have PowerShell version 5 or later

```powershell
$PSVersionTabe.PSVersion
```

2. Run the following command to determine where the ZIP needs to be unpacked

```powershell
$env:PSModulePath -Split ";"
```

3. Take a note of the name of the Windows PowerShell Modules folder that is linked to your account.
We will install the module linking to you account as you may not be authorised to the global location.

4. Unpack the ZIP contents into the folder name noted above.  This should restore the
7Zip4PowerShell, AWS.Tools.Common, AWS.Tools.S3, PeterDocs folders
as a child of the Windows PowerShell Module folder

5. To check the module is installed, run the following command

```powershell
Import-Module PeterDocs
```

The summary details on PeterDocs should be displayed.
