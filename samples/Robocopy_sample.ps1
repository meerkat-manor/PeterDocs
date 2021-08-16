param (
    [Parameter(Mandatory)]
    [String] $Source, 
    [Parameter(Mandatory)]
    [String] $Destination
)


$step ="Starting"
Try {
    $step ="Creating initial reconcile"
    New-PeterReconcile -ReconcileFile .\myrobocopy.csv -SourceFolder $Source 
    $step ="Running robocopy"
    Write-Host "Running robocopy for source '$Source' and destination '$Destination'"
    # Change the command line switches to suit
    robocopy `"C:\Users\tom\Small Share\misc_05`"   `"$Destination`" /e /copy:DAT /dcopy:DAT /log+:./robocopy.log
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
