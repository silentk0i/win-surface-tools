param([string]$BinaryPath = 'build\bin\x64\Release\win-obj-enum.exe', [switch]$Administrator)

$ErrorActionPreference = 'Stop'
$binary = (Resolve-Path -LiteralPath $BinaryPath).Path
$directory = Join-Path (Get-Location) 'build\tests\reports\cli'
New-Item -ItemType Directory -Force -Path $directory | Out-Null

function Invoke-ReportCli([string]$arguments) {
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $binary
    $start.Arguments = $arguments
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.Encoding]::UTF8
    $process = [Diagnostics.Process]::Start($start)
    $outputTask = $process.StandardOutput.ReadToEndAsync()
    $errorTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $result = @{ Code = $process.ExitCode; Output = $outputTask.Result; Errors = $errorTask.Result }
    $process.Dispose()
    return $result
}

$fixtureName = 'win-obj-export-' + [guid]::NewGuid().ToString('N') + '-' + [char]0x03a9
$fixture = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::ManualReset, 'Local\' + $fixtureName)
try {
    $html = Join-Path $directory ('access ' + [char]0x03a9 + '.html')
    $llm = Join-Path $directory ('access ' + [char]0x03a9 + '.llm.txt')
    $collectorOptions = if ($Administrator) { ' --admin-collect --admin-debug' } else { '' }
    $result = Invoke-ReportCli ('event' + $collectorOptions + ' --access --json --match "' + $fixtureName + '" --html "' + $html + '" --llm "' + $llm + '"')
    if (!(Test-Path -LiteralPath $html) -or !(Test-Path -LiteralPath $llm)) { throw ('Reports not created: ' + $result.Errors) }
    $jsonl = @($result.Output -split '\r?\n' | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
    $jsonlAccess = @($jsonl | Where-Object { $_.record -eq 'access' })
    $data = [regex]::Match([IO.File]::ReadAllText($html), '<script id="report-data" type="application/json">([\s\S]*?)</script>').Groups[1].Value | ConvertFrom-Json
    if ($data.objects.Count -ne 1 -or $jsonlAccess.Count -ne 1) { throw 'Export row count mismatch' }
    if (!@($jsonlAccess[0].processes | Where-Object { $_.process.pid -eq $PID -and $_.relation -eq 'handle-holder' }).Count) { throw 'JSONL missing fixture holder' }
    if (!@($data.objects[0].processes | Where-Object { $data.processes[$_[0]].pid -eq $PID -and $_[1] -eq 'handle-holder' }).Count) { throw 'HTML missing fixture holder' }
    if ($data.token.elevated -or $data.token.impersonating -or $data.token.execution -ne 'primary' -or $data.token.fingerprint.Length -ne 64) { throw 'Invalid user primary context' }
    if (@($jsonlAccess[0].attempts | Where-Object { $_.opened -and (!$_.context_verified -or $_.context_error) }).Count) { throw 'Unverified grant exported' }
    if ($Administrator) {
        if (!$data.administrator.received -or $data.administrator.error -or !$data.administrator.token.elevated -or !$data.administrator.debugEnabled) { throw 'Administrator collector context missing' }
        $holder = @($data.objects[0].processes | Where-Object { $data.processes[$_[0]].pid -eq $PID -and $_[1] -eq 'handle-holder' })
        if (!$holder.Count -or $holder[0][2] -ne 3 -or !$data.processes[$holder[0][0]].imagePath) { throw 'Administrator process metadata did not merge with user evidence' }
        if ($data.objects[0].discoverySource -ne 3 -or $data.userContextError) { throw 'Discovery source or user baseline invalid' }
    }
    if (!$data.objects[0].name.EndsWith($fixtureName)) { throw 'Unicode name did not round-trip' }
    $profile = $data.profiles[$data.objects[0].profile]
    if ($profile.Count -ne $jsonlAccess[0].attempts.Count) { throw 'Export lost attempts' }
    if ([bool]$data.completed -ne ($result.Code -eq 0)) { throw 'Scan completion not preserved' }
    $compact = [IO.File]::ReadAllText($llm)
    if (!$compact.Contains($fixtureName) -or !$compact.Contains('MAXIMUM_ALLOWED')) { throw 'LLM report lost identity or maximum observation' }
}
finally { $fixture.Dispose() }

foreach ($arguments in @(
    'event --html "' + $html + '" --llm "' + $html + '"'
    'event --html "' + (Join-Path $directory 'missing\report.html') + '"'
    'event --html'
    'event --llm --access'
    'event --process-budget 0'
    'event --process-budget 300001'
    'event --process-budget invalid'
    'event --admin-debug'
    'event --process-budget'
)) {
    $invalid = Invoke-ReportCli $arguments
    if ($invalid.Code -ne 1 -or $invalid.Output) { throw ('Invalid export arguments accepted: ' + $arguments) }
}

$emptyHtml = Join-Path $directory 'empty.html'
$emptyLlm = Join-Path $directory 'empty.llm.txt'
$emptyResult = Invoke-ReportCli ('sessions --match "' + $fixtureName + '" --html "' + $emptyHtml + '" --llm "' + $emptyLlm + '"')
$empty = [regex]::Match([IO.File]::ReadAllText($emptyHtml), '<script id="report-data" type="application/json">([\s\S]*?)</script>').Groups[1].Value | ConvertFrom-Json
if ($empty.objects.Count -ne 0 -or $empty.access) { throw 'Empty discovery-only export failed' }
$disabledPath = Join-Path $directory 'disabled.html'
$disabledResult = Invoke-ReportCli ('sessions --no-processes --html "' + $disabledPath + '"')
$disabled = [regex]::Match([IO.File]::ReadAllText($disabledPath), '<script id="report-data" type="application/json">([\s\S]*?)</script>').Groups[1].Value | ConvertFrom-Json
if ($disabled.processScan.requested -or $disabled.processes.Count) { throw 'Disabled process collection still ran' }
if (@($disabled.objects | Where-Object { $_.processStatus -ne 'not-collected' -or $_.processes.Count }).Count) { throw 'Disabled status lost' }
$budgetPath = Join-Path $directory 'budget.html'
$budgetResult = Invoke-ReportCli ('event --process-budget 1 --html "' + $budgetPath + '"')
$budget = [regex]::Match([IO.File]::ReadAllText($budgetPath), '<script id="report-data" type="application/json">([\s\S]*?)</script>').Groups[1].Value | ConvertFrom-Json
if (!$budget.processScan.requested -or !$budget.processScan.budgetExhausted -or $budget.processScan.complete) { throw 'Short process budget not reported as partial' }
Write-Output ('CLI report tests passed: ' + $binary)
