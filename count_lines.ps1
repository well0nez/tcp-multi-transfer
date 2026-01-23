# Count Lines of Code

Write-Host "=== RUST FILES (src/) ===" -ForegroundColor Cyan
$rustFiles = Get-ChildItem -Path .\src -Recurse -Filter *.rs
foreach ($file in $rustFiles) {
    $lines = (Get-Content $file.FullName | Measure-Object -Line).Lines
    $name = $file.FullName -replace [regex]::Escape((Get-Location).Path + '\'), ''
    Write-Host ("{0,-50} {1,5} lines" -f $name, $lines)
}

Write-Host ""
Write-Host "=== PYTHON FILES (server/) ===" -ForegroundColor Cyan
$pyFiles = Get-ChildItem -Path .\server -Recurse -Filter *.py
foreach ($file in $pyFiles) {
    $lines = (Get-Content $file.FullName | Measure-Object -Line).Lines
    $name = $file.FullName -replace [regex]::Escape((Get-Location).Path + '\'), ''
    Write-Host ("{0,-50} {1,5} lines" -f $name, $lines)
}

Write-Host ""
Write-Host "=== TOTALS ===" -ForegroundColor Green
$rustTotal = ($rustFiles | Get-Content | Measure-Object -Line).Lines
$pyTotal = ($pyFiles | Get-Content | Measure-Object -Line).Lines
Write-Host ("Rust (src/):      {0,5} lines" -f $rustTotal)
Write-Host ("Python (server/): {0,5} lines" -f $pyTotal)
Write-Host ("TOTAL:            {0,5} lines" -f ($rustTotal + $pyTotal)) -ForegroundColor Yellow