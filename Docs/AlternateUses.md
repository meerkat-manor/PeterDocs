# Alternative Use Cases

While ``PeterDocs`` has been built with the objective to transfer documents from
one computer to another where the computers are on isolated networks, there are
alternatives uses.

## Documents on the same network

You can use ``PeterDocs`` to reconcile files transferred using the Windows
``Robocopy`` command.  Robocopy is installed by default on your Windows
system.

Robocopy does require your source and target folders to be accessible from
the coputer that is executing the command.

To use ``PeterDocs`` and ``Robocopy`` install PeterDocs from the PowerShell Gallery
and execute the below commands in a PowerShell terminal, changing the values to suit.

```powershell
New-PeterReconcile -ReconcileFile .\myrobocopy.csv -SourceFolder <Source> -ExcludeHash 
robocopy <Source> <Destination> /mt /e /z /j /copy:DAT /dcopy:DAT /r:100 /eta /log+:robocopy_run.log /tee
Compare-Peter -ReconcileFile .\myrobocopy.csv -RestoreFolder <Destination> -ExcludeHash
```

The source and destination folders can be network paths i.e. start with \\\\

The above robocopy command retries 100 times failed copies.  The default is a million with a 30 second
wait time between retries.  Probably not a realistic time before failing.

If you want to verify the HASH for each file copied, then remove the ``-ExcludeHash`` directive.  Be
warned that generating a hash on both source and destination will take some time if you
have many files.

Further information on Robocopy can be found on the internet such as:

* [https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
* [https://pureinfotech.com/robocopy-transfer-files-fast-network-windows-10/](https://pureinfotech.com/robocopy-transfer-files-fast-network-windows-10/)
* [https://www.techrepublic.com/article/how-to-quickly-back-up-just-your-data-in-windows-10-with-robocopys-multi-threaded-feature/](https://www.techrepublic.com/article/how-to-quickly-back-up-just-your-data-in-windows-10-with-robocopys-multi-threaded-feature/)
* [https://www.youtube.com/watch?v=gTzTeHmKMKw](https://www.youtube.com/watch?v=gTzTeHmKMKw)

You need to consider the **security** of the network path when using robocopy.  The copy will use the underlying
network transport layer and protocol.  If you are not using SMBv3 protocol then the file contents may not
be secure in transit.

## Picture EXIF data

You can use ``PeterDocs`` to extract EXIF data from your picture files.  To do
this just install PeterDocs from the PowerShell Gallery and execute the
below command in a PowerShell terminal, changing the values to suit.

```powershell
New-PeterReconcile -ReconcileFile .\mypictures_metadata.csv -SourceFolder <Source> -ExcludeHash -IncludeExif
```

At the conclusion of the exceution, you will have a file named ``##peter_exif##.csv`` that
contains your pictures metadata.  You will also have a CSV file with picture file
general metadata named ``mypictures_metadata.csv`` such as creation time and size.

Further information on EXIF can be found on the internet such as:

* [https://en.wikipedia.org/wiki/Exif](https://en.wikipedia.org/wiki/Exif)
* [https://photographylife.com/what-is-exif-data](https://photographylife.com/what-is-exif-data)
* [https://exiftool.org/](https://exiftool.org/)
