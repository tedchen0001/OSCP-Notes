$ScheduledTasks = Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*" -and $_.TaskName -notlike "*TEST*"}

foreach ($item in $ScheduledTasks) {

    [string]$Name       = ($item.TaskName)
    [string]$Action     = ($item.Actions | Select-Object -ExpandProperty Execute)
    [datetime]$Start    = ($item.Triggers | Select-Object -ExpandProperty StartBoundary)
    [string]$Repetition = ($item.Triggers.Repetition | Select-Object -ExpandProperty interval)
    [string]$Duration   = ($item.Triggers.Repetition | Select-Object -ExpandProperty duration)

    $splat = @{

    'Name'       = $Name
    'Action'     = $Action
    'Start'      = $Start
    'Repetition' = $Repetition
    'Duration'   = $Duration

    }

    $obj = New-Object -TypeName PSObject -property $splat

    $obj | Write-Output
}