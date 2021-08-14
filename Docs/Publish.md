# Publishing PeterDocs

To publish the PeterDocs module to the PowerShell Gallery, follow these instructions.

**Note** Only the author or delegate for PeterDocs will be authorized to perform this action.

1. Ensure you have incremented the version number in ``PeterDocs.psm1`` and ``PeterDocs.psd1``
2. Open PowerShell terminal
3. Retrieve the PowerShell Gallery API key and set it
4. Do a Whatif check on the module before publishing
5. Publish the module

```powershell
$apiKey = ""

Publish-Module -Path .\PeterDocs\ -NuGetApiKey $apiKey -WhatIf -Verbose

Publish-Module -Name .\PeterDocs\PeterDocs.psd1 -NuGetApiKey $apiKey

```
