param (
    [Parameter(Mandatory)]
    [String] $Source, 
    [Parameter(Mandatory)]
    [String] $Destination
)

# Note that there is a path limitation for files of 260 characters
# beyond which PeterDocs will fail
# You could also use drive mapping to overcome this
#  New-PSDrive "X" -PSProvider FileSysytem -Root "$Source" 

$step ="Starting"
Try {
    $step ="Creating initial reconcile"
    New-PeterReconcile -ReconcileFile .\myrobocopy.csv -SourceFolder $Source 
    $step ="Running robocopy"
    Write-Host "Running robocopy for source '$Source' and destination '$Destination'"
    # Change the command line switches to suit
    robocopy `"$Source`"   "$Destination" /e /copy:DAT /dcopy:DAT /log+:./robocopy.log /r:1000 /w:10
    if ($LastExitCode -lt 8) {
        Write-Host "Robocopy succeeded"
    } else {
        Write-Host "Robocopy failed with exit code:" $LastExitCode
        throw "Robocopy error"
    }
    $step ="Running copy reconcile"
    Compare-Peter -ReconcileFile .\myrobocopy.csv -RestoreFolder $Destination 
    # You can modify the code here to add a success email notification
} Catch {
    Write-Host "Error: $_"
    Write-Error "Processing encountered error at step '$step'"
    # You can modify the catch to add a simlpe email notification on errors
}
