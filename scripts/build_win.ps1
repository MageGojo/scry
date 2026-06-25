<#
  零环境出包(Windows):把 scry_app 打成自带运行时的 Scry-win\ —— 目标机双击即用,
  不用装 VC++ 可再发行组件 / Rust / SDK。

  必须在 Windows 上运行(macOS 无法交叉编译:gpui_windows 的 release 着色器要 Windows 专有
  fxc.exe,且其 build.rs 按宿主 cfg 求值,在非 Windows 上整段被跳过 → include! 生成的
  shaders_bytes.rs 失败)。aws-lc-rs(经 drission→reqwest)要 NASM,pcap 要 Npcap SDK。

  用法(PowerShell):
    pwsh -File scripts\build_win.ps1
    $env:SCRY_BUNDLE_CHROMIUM=1; pwsh -File scripts\build_win.ps1   # 额外打包 Chrome for Testing

  产物:dist\Scry-win\(scry_app.exe + 运行时 DLL + 资源) 与 dist\Scry-win.zip
#>
$ErrorActionPreference = "Stop"

$Root    = (Resolve-Path "$PSScriptRoot\..").Path
$BinName = "scry_app"
$AppName = "Scry"
$Dist    = Join-Path $Root "dist"
$OutDir  = Join-Path $Dist "$AppName-win"
$IconsSrc = Join-Path $Root "..\mage-ui\crates\mage_ui\assets\icons"

Write-Host "==> [1/5] 编译 release(opt-level=z + lto,首次很慢)"
Push-Location $Root
cargo build --release -p $BinName
Pop-Location
$Bin = Join-Path $Root "target\release\$BinName.exe"
if (-not (Test-Path $Bin)) { throw "找不到二进制:$Bin" }

Write-Host "==> [2/5] 组装 $OutDir"
if (Test-Path $OutDir) { Remove-Item -Recurse -Force $OutDir }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Copy-Item $Bin (Join-Path $OutDir "$BinName.exe")

# 界面 SVG 图标(运行时 mage_ui 优先读 resources\icons)
$ResIcons = Join-Path $OutDir "resources\icons"
New-Item -ItemType Directory -Force -Path $ResIcons | Out-Null
if (Test-Path $IconsSrc) {
    Copy-Item (Join-Path $IconsSrc "*.svg") $ResIcons -ErrorAction SilentlyContinue
    Write-Host "    UI icons: $((Get-ChildItem $ResIcons).Count) 个"
} else {
    Write-Host "    警告:未找到图标源 $IconsSrc(界面图标可能缺失)"
}

Write-Host "==> [3/5] 自带 VC++ 运行时 DLL(零环境关键)"
# 这些是 MSVC 编译的 Rust 产物 + gpui 动态依赖的 VC++ 2015-2022 运行时;
# 干净机器没装 VC++ Redistributable 就会缺 DLL 闪退。优先从 VS 官方可再分发副本拷,
# 兜底从 System32 拷(它们本身就是可再分发的微软运行时)。
$crtDlls = @(
    "msvcp140.dll","msvcp140_1.dll","msvcp140_2.dll",
    "vcruntime140.dll","vcruntime140_1.dll",
    "concrt140.dll","vccorlib140.dll"
)
$copied = @{}
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -products * -property installationPath 2>$null
    if ($vsPath) {
        $redistRoot = Join-Path $vsPath "VC\Redist\MSVC"
        if (Test-Path $redistRoot) {
            $ver = Get-ChildItem $redistRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1
            $crtDir = Get-ChildItem (Join-Path $ver.FullName "x64") -Directory -Filter "Microsoft.VC*.CRT" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($crtDir) {
                Get-ChildItem (Join-Path $crtDir.FullName "*.dll") | ForEach-Object {
                    Copy-Item $_.FullName $OutDir -Force; $copied[$_.Name] = $true
                }
                Write-Host "    从 VS Redist 拷入:$($copied.Count) 个 DLL"
            }
        }
    }
}
# 兜底:VS 没拷全的,从 System32 补
foreach ($d in $crtDlls) {
    if (-not $copied.ContainsKey($d)) {
        $sys = Join-Path $env:WINDIR "System32\$d"
        if (Test-Path $sys) { Copy-Item $sys $OutDir -Force; $copied[$d] = $true }
    }
}
Write-Host "    运行时 DLL 合计:$($copied.Count) 个"

Write-Host "==> [4/5] 内置 Chrome for Testing(可选;SCRY_BUNDLE_CHROMIUM=1 启用)"
if ($env:SCRY_BUNDLE_CHROMIUM -eq "1") {
    $chromeDir = Join-Path $OutDir "chrome"
    New-Item -ItemType Directory -Force -Path $chromeDir | Out-Null
    try {
        $json = Invoke-RestMethod "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"
        $url = ($json.channels.Stable.downloads.chrome | Where-Object { $_.platform -eq "win64" }).url
        $zip = Join-Path $chromeDir "chrome.zip"
        Invoke-WebRequest $url -OutFile $zip
        Expand-Archive $zip -DestinationPath $chromeDir -Force
        Remove-Item $zip
        Write-Host "    ✓ Chrome for Testing 已打包(win64)"
    } catch {
        Write-Host "    警告:Chrome 下载失败,跳过(运行时仍可 App 内下载)"
    }
} else {
    Write-Host "    跳过(默认);真离线零环境交付:`$env:SCRY_BUNDLE_CHROMIUM=1 后再跑"
}

Write-Host "==> [5/5] 打包 zip"
$zipOut = Join-Path $Dist "$AppName-win.zip"
if (Test-Path $zipOut) { Remove-Item $zipOut -Force }
Compress-Archive -Path "$OutDir\*" -DestinationPath $zipOut

Write-Host ""
Write-Host "✅ 完成:"
Write-Host "   目录: $OutDir"
Write-Host "   Zip : $zipOut"
Write-Host "   注意:被动嗅探(scry_sniff)在目标机需装 Npcap 运行时(https://npcap.com);"
Write-Host "         MITM 代理 / 扫描 / 重放等核心功能不依赖 Npcap。"
Write-Host "   验证零环境:dumpbin /dependents $OutDir\$BinName.exe  逐项确认非系统 DLL 已内置。"
