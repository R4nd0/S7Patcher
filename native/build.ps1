param([Parameter(Mandatory=$true)][string]$OutputDirectory, [switch]$LocalPairLab, [switch]$LocalNetworkPump)
$ErrorActionPreference = 'Stop'
$nativeSource = $PSScriptRoot
$nativeOutput = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $nativeOutput | Out-Null
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (!(Test-Path -LiteralPath $vswhere)) { throw 'Visual Studio C++ Build Tools are required.' }
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$installation) { throw 'The x86/x64 C++ toolchain was not found.' }
$vcvars = Join-Path $installation 'VC\Auxiliary\Build\vcvarsall.bat'
$compilerEnvironment = & $env:ComSpec /d /c "call `"$vcvars`" x64_x86 >nul && set"
if ($LASTEXITCODE -ne 0) { throw 'Cannot initialize the x86 toolchain.' }
foreach ($line in $compilerEnvironment) {
    $position = $line.IndexOf('=')
    if ($position -gt 0) { [Environment]::SetEnvironmentVariable($line.Substring(0,$position), $line.Substring($position+1), 'Process') }
}
$common = @('/nologo','/std:c++17','/EHsc','/MT','/W4','/WX','/D_CRT_SECURE_NO_WARNINGS','/D_WINSOCK_DEPRECATED_NO_WARNINGS')
if ($LocalPairLab) { $common += '/DS7_LOCAL_PAIR_LAB' }
if ($LocalNetworkPump) { $common += '/DS7_LOCAL_NETWORK_PUMP' }
function Compile-Native([string[]]$Arguments) {
    if ($Arguments -notcontains '/link') { $Arguments += '/link' }
    # Avoid Windows' filename-based installer detection for test executables.
    $Arguments += @('/MANIFEST:EMBED', "/MANIFESTUAC:level='asInvoker' uiAccess='false'")
    & cl.exe @common @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'Native build failed.' }
}
Push-Location $nativeOutput
try {
    Compile-Native @((Join-Path $nativeSource 'local_platform.cpp'), (Join-Path $nativeSource 'local_platform_tests.cpp'), '/Fe:local_platform_tests.exe')
    Compile-Native @('/LD', (Join-Path $nativeSource 'network_guard.cpp'), (Join-Path $nativeSource 'network_guard_test_exports.cpp'), '/Fe:network_guard_test.dll', '/link','ws2_32.lib','winhttp.lib','shell32.lib')
    Compile-Native @((Join-Path $nativeSource 'network_guard_tests.cpp'), '/Fe:network_guard_tests.exe', '/link','network_guard_test.lib','ws2_32.lib','winhttp.lib','shell32.lib')
    Compile-Native @((Join-Path $nativeSource 'adapter_rejection_test.cpp'), '/Fe:adapter_rejection_test.exe', '/link','ws2_32.lib')
    Compile-Native @((Join-Path $nativeSource 'local_connect_tests.cpp'), '/Fe:local_connect_tests.exe')
    Compile-Native @((Join-Path $nativeSource 'cpu_affinity.cpp'), (Join-Path $nativeSource 'cpu_affinity_tests.cpp'), '/Fe:cpu_affinity_tests.exe')
    Compile-Native @((Join-Path $nativeSource 'bootstrap_patch_tests.cpp'), (Join-Path $nativeSource 'cpu_affinity.cpp'), '/Fe:bootstrap_patch_tests.exe')
    Compile-Native @('/LD', (Join-Path $nativeSource 'local_platform.cpp'), (Join-Path $nativeSource 'network_guard.cpp'),
        (Join-Path $nativeSource 'offline_bootstrap.cpp'), (Join-Path $nativeSource 'runtime_config.cpp'), (Join-Path $nativeSource 'cpu_affinity.cpp'), '/Fe:uplay_r1_loader.dll',
        '/link', "/DEF:$(Join-Path $nativeSource 'local_platform.def')", 'ws2_32.lib','winhttp.lib','shell32.lib','bcrypt.lib','crypt32.lib',
        '/DYNAMICBASE','/NXCOMPAT')
} finally { Pop-Location }
Write-Output 'Built experimental x86 adapter and synthetic tests. No game was launched or installed.'
