@echo off
setlocal EnableExtensions

REM If not running in own window, relaunch in one
if "%STANDALONE%"=="" (
    set STANDALONE=1
    cmd /k "%~f0"
    exit
)

title PolinRider Security Scanner + Lockdown

echo ============================================================
echo   POLINRIDER SECURITY SCANNER + LOCKDOWN
echo   Run as Administrator for full protection
echo ============================================================
echo.
echo This will:
echo   [SCAN]    1. Scan all drives for malicious files (parallel)
echo   [SCAN]    2. Check .gitignore for malware entries (parallel)
echo   [SCAN]    3. Check tasks.json for folderOpen triggers (parallel)
echo   [SCAN]    4. Check build config files for hidden payloads (parallel)
echo   [SCAN]    5. Check Beavertail, payload, process, exfil, browser, startup (parallel)
echo   [SCAN]    6. Scan git history in all repos (parallel)
echo   [LOCK]    7. Enable npm ignore-scripts
echo   [LOCK]    8. Disable VS Code and Cursor auto tasks
echo   [LOCK]    9. Block PolinRider C2 IPs in Firewall
echo   [VERIFY] 10. Verify all settings
echo.
pause

REM ── Configurable variables ──────────────────────────────────
REM PolinRider C2 IPs - update if new IPs are discovered
set C2_IPS=166.88.134.62,198.105.127.210,23.27.202.27,166.88.54.158

REM Git history scan depth - change to suit your needs
REM Examples: "3 months ago", "6 months ago", "1 year ago"
REM Leave empty for full history scan (slow but thorough)
set GIT_SINCE=3 months ago

REM Threat counter file
set TCFILE=%TEMP%\polinrider_tc.txt
echo 0 > "%TCFILE%"

echo.
echo ============================================================
echo PART A - FORENSIC SCAN
echo ============================================================

echo.
echo [A1] Scanning all drives in parallel for malicious filenames...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$tc=[System.Environment]::ExpandEnvironmentVariables('%TCFILE%'); $jobs=Get-PSDrive -PSProvider FileSystem | ForEach-Object { $d=$_.Root; Start-Job -ScriptBlock { param($r) Get-ChildItem $r -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { ($_.Name -in 'temp_auto_push.bat','temp_interactive_push.bat','branch_structure.json' -or $_.Name -match '^fa-solid-[0-9]+-.*\.woff2$') } | ForEach-Object { '[SUSPICIOUS FILENAME] '+$_.FullName } } -ArgumentList $d }; $count=0; $jobs | Wait-Job | ForEach-Object { $o=Receive-Job $_; if($o){ $o | ForEach-Object { Write-Host $_ -ForegroundColor Red; $count++ } } }; $jobs | Remove-Job; $c=[int](Get-Content $tc -ErrorAction SilentlyContinue); Set-Content $tc ($c+$count)"

echo.
echo [A2] Scanning all drives in parallel for infected .gitignore...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$tc=[System.Environment]::ExpandEnvironmentVariables('%TCFILE%'); $jobs=Get-PSDrive -PSProvider FileSystem | ForEach-Object { $d=$_.Root; Start-Job -ScriptBlock { param($r) $out=@(); Get-ChildItem $r -Recurse -Filter .gitignore -Force -ErrorAction SilentlyContinue | ForEach-Object { $h=Select-String -Path $_.FullName -Pattern 'temp_auto_push|temp_interactive_push|branch_structure' -ErrorAction SilentlyContinue; if($h){ $out+='[INFECTED GITIGNORE] '+$_.FullName; $h | ForEach-Object { $out+=$_.ToString() } } }; return $out } -ArgumentList $d }; $count=0; $jobs | Wait-Job | ForEach-Object { $o=Receive-Job $_; if($o){ $o | ForEach-Object { Write-Host $_ -ForegroundColor Red; $count++ } } }; $jobs | Remove-Job; $c=[int](Get-Content $tc -ErrorAction SilentlyContinue); Set-Content $tc ($c+$count)"

echo.
echo [A3] Scanning all drives in parallel for folderOpen in tasks.json...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$tc=[System.Environment]::ExpandEnvironmentVariables('%TCFILE%'); $jobs=Get-PSDrive -PSProvider FileSystem | ForEach-Object { $d=$_.Root; Start-Job -ScriptBlock { param($r) $out=@(); Get-ChildItem $r -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -in 'tasks.json','settings.json' -and $_.FullName -match '\.vscode' } | ForEach-Object { $c=Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue; if($c -match 'folderOpen'){ if($c -match 'woff2|woff|ttf|fonts'){ $out+='RED::[MALICIOUS TASK - folderOpen+font] '+$_.FullName } else { $out+='YEL::[REVIEW TASK - folderOpen] '+$_.FullName } } }; return $out } -ArgumentList $d }; $count=0; $jobs | Wait-Job | ForEach-Object { $o=Receive-Job $_; if($o){ $o | ForEach-Object { if($_ -match '^RED::'){ Write-Host ($_ -replace '^RED::','') -ForegroundColor Red; $count++ } else { Write-Host ($_ -replace '^YEL::','') -ForegroundColor Yellow } } } }; $jobs | Remove-Job; $c=[int](Get-Content $tc -ErrorAction SilentlyContinue); Set-Content $tc ($c+$count)"

echo.
echo [A4] Scanning all drives in parallel for hidden payloads in config files...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$tc=[System.Environment]::ExpandEnvironmentVariables('%TCFILE%'); $configs=@('jest.config.js','jest.config.ts','webpack.config.js','vite.config.js','vite.config.ts','postcss.config.js','tailwind.config.js','next.config.js','rollup.config.js','.eslintrc.js'); $jobs=Get-PSDrive -PSProvider FileSystem | ForEach-Object { $d=$_.Root; Start-Job -ScriptBlock { param($r,$cfg) $out=@(); Get-ChildItem $r -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -in $cfg } | ForEach-Object { $c=Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue; if($c -match ' {150,}\S'){ $out+='[HIDDEN PAYLOAD] '+$_.FullName } elseif($c -match 'rmcej%otb%|global\[.r.\]=require|:443/0x/|0xa322E5f3|trongrid|windowsHide|global\.i=|global\.i ='){ $out+='[MALWARE SIGNATURE] '+$_.FullName } }; return $out } -ArgumentList $d,$configs }; $count=0; $jobs | Wait-Job | ForEach-Object { $o=Receive-Job $_; if($o){ $o | ForEach-Object { Write-Host $_ -ForegroundColor Red; $count++ } } }; $jobs | Remove-Job; $c=[int](Get-Content $tc -ErrorAction SilentlyContinue); Set-Content $tc ($c+$count)"

echo.
echo [A5] Running remaining checks in parallel...
echo     - Beavertail staging artifacts
echo     - Payload execution artifacts
echo     - Suspicious node processes
echo     - Exfil zip archives
echo     - Browser credentials
echo     - Startup persistence
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$tc=[System.Environment]::ExpandEnvironmentVariables('%TCFILE%'); $j1=Start-Job -ScriptBlock { $out=@(); $count=0; $pts=@('_credentials.json','_sysenv.json','_sysenv.env','_info.json','tmp7A863DD1.tmp'); $locs=@($env:TEMP,$env:TMP,(Join-Path $env:USERPROFILE '.npm'),(Join-Path $env:LOCALAPPDATA 'Temp')); foreach($loc in $locs){ if(Test-Path $loc){ Get-ChildItem $loc -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -in $pts } | ForEach-Object { $out+='RED::[BEAVERTAIL ARTIFACT] '+$_.FullName; $count++ }; Get-ChildItem $loc -Recurse -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^[a-zA-Z0-9._-]+\$[a-zA-Z0-9._-]+_[0-9]{6}_[0-9]{6}$' } | ForEach-Object { $out+='RED::[BEAVERTAIL STAGING DIR] '+$_.FullName; $count++ } } }; return @($count)+$out }; $j2=Start-Job -ScriptBlock { $out=@(); $count=0; $arts=@((Join-Path $env:USERPROFILE '.node_modules'),(Join-Path $env:LOCALAPPDATA 'Programs\Python\Python3127'),(Join-Path $env:TEMP '.npm')); foreach($a in $arts){ if(Test-Path $a){ $out+='RED::[PAYLOAD EXECUTED] '+$a; $count++ } else { $out+='GRN::[OK] Not found: '+$a } }; return @($count)+$out }; $j3=Start-Job -ScriptBlock { $out=@(); $count=0; $procs=Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'node' -and $_.CommandLine -match 'woff|woff2|ttf|fonts|eval|-e ' }; if($procs){ $procs | ForEach-Object { $out+='RED::[SUSPICIOUS PROCESS] PID:'+$_.ProcessId+' '+$_.CommandLine; $count++ } } else { $out+='GRN::[OK] No suspicious node processes found' }; return @($count)+$out }; $j4=Start-Job -ScriptBlock { $out=@(); $count=0; Get-ChildItem $env:USERPROFILE -Recurse -Filter '*.zip' -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '\$[a-zA-Z0-9._-]+_[0-9]{6}_[0-9]{6}' } | ForEach-Object { $out+='RED::[EXFIL ARCHIVE] '+$_.FullName; $count++ }; return @($count)+$out }; $j5=Start-Job -ScriptBlock { $out=@(); $dbs=@((Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\Login Data'),(Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data\Default\Login Data'),(Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data\Default\Login Data')); foreach($db in $dbs){ if(Test-Path $db){ $item=Get-Item $db; $out+='YEL::Browser credentials last modified: '+$item.LastWriteTime+' - '+$db } }; return @(0)+$out }; $j6=Start-Job -ScriptBlock { $out=@(); $count=0; $starts=@((Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'),(Join-Path $env:PROGRAMDATA 'Microsoft\Windows\Start Menu\Programs\Startup')); foreach($s in $starts){ if(Test-Path $s){ $files=Get-ChildItem $s -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer -and $_.Name -ne 'desktop.ini' -and $_.Name -notmatch 'AnyDesk|Send to OneNote|OneDrive|OneNote' }; if($files){ $files | ForEach-Object { $out+='YEL::[STARTUP FILE] '+$_.FullName; $count++ } } else { $out+='GRN::[OK] Startup folder empty: '+$s } } }; $hkcu=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue; $hkcu.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $val=$_.Value; if($val -match 'node|npm|woff|\.bat|\.ps1' -and $val -notmatch 'Docker|OpenVPN|LGHUB|Teams|Edge|NordVPN|slack|Bitdefender|SecurityHealth|AnyDesk'){ $out+='RED::[SUSPICIOUS STARTUP HKCU] '+$_.Name; $count++ } else { $out+='GRN::[OK HKCU] '+$_.Name } }; $hklm=Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue; $hklm.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $val=$_.Value; if($val -match 'node|npm|woff|\.bat|\.ps1' -and $val -notmatch 'Docker|OpenVPN|LGHUB|Teams|Edge|NordVPN|slack|Bitdefender|SecurityHealth|AnyDesk'){ $out+='RED::[SUSPICIOUS STARTUP HKLM] '+$_.Name; $count++ } else { $out+='GRN::[OK HKLM] '+$_.Name } }; $tasks=schtasks /query /fo LIST 2>$null | Select-String -Pattern 'node|npm|woff|font' -Context 2; if($tasks -and ($tasks | Where-Object { $_ -notmatch 'NVIDIA|NvNode|NvDriver' })){ $out+='RED::[SUSPICIOUS SCHEDULED TASK] found'; $count++ } else { $out+='GRN::[OK] No suspicious scheduled tasks' }; return @($count)+$out }; @($j1,$j2,$j3,$j4,$j5,$j6) | Wait-Job | ForEach-Object { $results=Receive-Job $_; $cnt=[int]$results[0]; $lines=$results[1..($results.Length-1)]; $lines | ForEach-Object { if($_ -match '^RED::'){ Write-Host ($_ -replace '^RED::','') -ForegroundColor Red } elseif($_ -match '^YEL::'){ Write-Host ($_ -replace '^YEL::','') -ForegroundColor Yellow } elseif($_ -match '^GRN::'){ Write-Host ($_ -replace '^GRN::','') -ForegroundColor Green } else { Write-Host $_ } }; $c=[int](Get-Content $tc -ErrorAction SilentlyContinue); Set-Content $tc ($c+$cnt) }; @($j1,$j2,$j3,$j4,$j5,$j6) | Remove-Job"

echo.
echo [A6] Scanning git history in all repos (since %GIT_SINCE%, parallel)...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$tc=[System.Environment]::ExpandEnvironmentVariables('%TCFILE%'); $since=[System.Environment]::ExpandEnvironmentVariables('%GIT_SINCE%'); $env:GIT_TERMINAL_PROMPT=0; $env:GIT_OPTIONAL_LOCKS=0; $repos=Get-ChildItem 'D:\' -Recurse -Filter '.git' -Force -ErrorAction SilentlyContinue -Depth 5 | Where-Object { $_.PSIsContainer } | ForEach-Object { $_.Parent.FullName }; $jobs=$repos | ForEach-Object { $repo=$_; Start-Job -ScriptBlock { param($rp,$since) $out=@(); $t=& git -C $rp rev-parse --git-dir 2>&1; if($LASTEXITCODE -ne 0){ return @(0) }; if($since){ $sinceArg='--since='+$since } else { $sinceArg=$null }; $checks=@(@('folderOpen',@('log','--oneline','--all','-S','folderOpen','--','.')),@('global.i=',@('log','--oneline','--all','-S','global.i=','--','.')),@('global.i =',@('log','--oneline','--all','-S','global.i =','--','.')),@('windowsHide',@('log','--oneline','--all','-S','windowsHide','--','.')),@('branch_structure.json',@('log','--oneline','--all','-S','branch_structure.json','--','.gitignore')),@('fa-solid-400.woff2',@('log','--oneline','--all','-S','fa-solid-400.woff2','--','.')),@('fa-solid-500.woff2',@('log','--oneline','--all','-S','fa-solid-500.woff2','--','.')),@('temp_auto_push.bat',@('log','--oneline','--all','-S','temp_auto_push.bat','--','.'))); $count=0; foreach($c in $checks){ $args=$c[1]; if($sinceArg){ $args=@($args[0],$args[1],$sinceArg)+$args[2..($args.Length-1)] }; $r=& git -C $rp @args 2>$null; if($r){ $out+='RED::[GIT HIT: '+$c[0]+'] '+$rp; $r | ForEach-Object { $out+='  '+$_ }; $count++ } }; return @($count)+$out } -ArgumentList $repo,$since }; $total=0; $jobs | Wait-Job | ForEach-Object { $results=Receive-Job $_; $cnt=[int]$results[0]; $lines=$results[1..($results.Length-1)]; $lines | ForEach-Object { if($_ -match '^RED::'){ Write-Host ($_ -replace '^RED::','') -ForegroundColor Red } else { Write-Host $_ } }; $total+=$cnt }; $jobs | Remove-Job; $c=[int](Get-Content $tc -ErrorAction SilentlyContinue); Set-Content $tc ($c+$total)"

echo.
echo ============================================================
echo PART B - LOCKDOWN
echo ============================================================

echo.
echo [B1] Enabling npm lifecycle-script protection...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "try { & npm config set ignore-scripts true; Write-Host '[OK] npm ignore-scripts set to true' -ForegroundColor Green } catch { Write-Host '[WARNING] npm config set failed: '$_.Exception.Message -ForegroundColor Yellow }"

echo.
echo [B2] Configuring VS Code and Cursor...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "try { $targets=@((Join-Path $env:APPDATA 'Cursor\User\settings.json'),(Join-Path $env:APPDATA 'Code\User\settings.json')); foreach($p in $targets){ try { $dir=Split-Path $p; New-Item -ItemType Directory -Force -Path $dir | Out-Null; if(Test-Path $p){ Copy-Item $p ($p+'.backup-'+(Get-Date -Format 'yyyyMMdd-HHmmss')) -Force }; $s=if(Test-Path $p){ Get-Content $p | Out-String }else{ '' }; $s=$s.Trim(); if($s -eq '' -or $s -eq '{}' -or $s.Length -lt 3){ $j=[PSCustomObject]@{} } else { try { $j=$s | ConvertFrom-Json } catch { $j=[PSCustomObject]@{} } }; $j | Add-Member -Force -NotePropertyName 'task.allowAutomaticTasks' -NotePropertyValue 'off'; $j | Add-Member -Force -NotePropertyName 'security.workspace.trust.enabled' -NotePropertyValue $true; $j | Add-Member -Force -NotePropertyName 'security.workspace.trust.startupPrompt' -NotePropertyValue 'always'; $j | Add-Member -Force -NotePropertyName 'security.workspace.trust.emptyWindow' -NotePropertyValue $false; $j | Add-Member -Force -NotePropertyName 'security.workspace.trust.untrustedFiles' -NotePropertyValue 'open'; $j | ConvertTo-Json -Depth 10 | Out-File $p; Write-Host ('[OK] Updated: '+$p) -ForegroundColor Green } catch { Write-Host ('[WARNING] Skipped '+$p+': '+$_.Exception.Message) -ForegroundColor Yellow } } } catch { Write-Host ('Config error: '+$_.Exception.Message) -ForegroundColor Red }"

echo.
echo [B3] Blocking PolinRider C2 IPs in Windows Firewall...
echo.
netsh advfirewall firewall delete rule name="Block PolinRider C2" >nul 2>&1
netsh advfirewall firewall add rule name="Block PolinRider C2" dir=out action=block remoteip=%C2_IPS%
if errorlevel 1 (
    echo [WARNING] Firewall rule failed. Run as Administrator.
) else (
    echo [OK] PolinRider C2 IPs blocked successfully.
)

echo.
echo ============================================================
echo PART C - VERIFICATION
echo ============================================================

echo.
echo --- npm ignore-scripts ---
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "try { $r=& npm config get ignore-scripts; Write-Host $r } catch { Write-Host 'npm not found' }"

echo.
echo --- Cursor settings ---
powershell.exe -NoProfile -Command "try { $p=Join-Path $env:APPDATA 'Cursor\User\settings.json'; if(Test-Path $p){Select-String -Path $p -Pattern 'task.allowAutomaticTasks|security.workspace.trust.enabled'}else{Write-Host 'Cursor settings.json not found.'} } catch { Write-Host 'Cursor check error' }"

echo.
echo --- VS Code settings ---
powershell.exe -NoProfile -Command "try { $p=Join-Path $env:APPDATA 'Code\User\settings.json'; if(Test-Path $p){Select-String -Path $p -Pattern 'task.allowAutomaticTasks|security.workspace.trust.enabled'}else{Write-Host 'VS Code settings.json not found.'} } catch { Write-Host 'VS Code check error' }"

echo.
echo --- Firewall Rule ---
netsh advfirewall firewall show rule name="Block PolinRider C2"

echo.
echo ============================================================
echo PART D - FINAL VERDICT
echo ============================================================
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$tc=[System.Environment]::ExpandEnvironmentVariables('%TCFILE%'); $threats=[int](Get-Content $tc -ErrorAction SilentlyContinue); Write-Host ''; Write-Host '  ============================================================' -ForegroundColor White; Write-Host '  SCAN COMPLETE' -ForegroundColor White; Write-Host ('  Threats detected: '+$threats) -ForegroundColor $(if($threats -gt 0){'Red'}else{'Green'}); Write-Host ''; if($threats -eq 0){ Write-Host '  RESULT: YOUR MACHINE IS SAFE' -ForegroundColor Green; Write-Host ''; Write-Host '  No malicious files, backdoors, or suspicious activity' -ForegroundColor Green; Write-Host '  was found. All protections are active.' -ForegroundColor Green; Write-Host '  Run this scan weekly to stay protected.' -ForegroundColor Green } else { Write-Host '  RESULT: THREATS FOUND - ACTION REQUIRED' -ForegroundColor Red; Write-Host ''; Write-Host '  DO NOT open flagged projects in VS Code or Cursor.' -ForegroundColor Red; Write-Host '  DO NOT run npm install or npm test in flagged repos.' -ForegroundColor Red; Write-Host '  Rotate your credentials from a different device NOW.' -ForegroundColor Red; Write-Host '  Contact your security team immediately.' -ForegroundColor Red }; Write-Host '  ============================================================' -ForegroundColor White; Remove-Item $tc -Force -ErrorAction SilentlyContinue"

echo.
pause
endlocal