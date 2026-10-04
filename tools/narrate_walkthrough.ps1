param(
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)

Add-Type -AssemblyName System.Speech
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\docs\WALKTHROUGH.md') -Raw -Encoding UTF8
$matches = [regex]::Matches($source, '(?ms)^## Scene (\d+) [^\r\n]+\r?\n\r?\n(.*?)(?=^## Scene |\z)')
if ($matches.Count -ne 6) { throw "Expected six scenes, found $($matches.Count)" }
$voice = New-Object System.Speech.Synthesis.SpeechSynthesizer
$voice.SelectVoice('Microsoft David Desktop')
$voice.Rate = 2
foreach ($scene in $matches) {
    $number = [int]$scene.Groups[1].Value
    $speech = $scene.Groups[2].Value.Trim()
    $target = Join-Path $OutputDirectory ('scene-{0:00}.wav' -f $number)
    $voice.SetOutputToWaveFile($target)
    $voice.Speak($speech)
    $voice.SetOutputToNull()
}
$voice.Dispose()
