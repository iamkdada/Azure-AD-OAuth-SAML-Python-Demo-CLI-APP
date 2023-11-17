$dir = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition


$env:PYTHONPATH = if ([string]::IsNullOrWhiteSpace($env:PYTHONPATH)) {
    $dir
} else {
    "$dir;$env:PYTHONPATH"
}


& python -m dada_cli @args