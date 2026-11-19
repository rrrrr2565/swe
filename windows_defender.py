"""Safe adapter to the Microsoft Defender CLI; no custom kernel driver is installed."""
import os
import shutil
import subprocess
from pathlib import Path

def find_mpcmdrun():
    roots=[]
    pf=os.environ.get("ProgramFiles",r"C:\Program Files")
    pd=os.environ.get("ProgramData",r"C:\ProgramData")
    roots.append(Path(pf)/"Windows Defender"/"MpCmdRun.exe")
    platform=Path(pd)/"Microsoft"/"Windows Defender"/"Platform"
    if platform.is_dir():
        for child in sorted(platform.iterdir(),reverse=True):
            roots.append(child/"MpCmdRun.exe")
    for candidate in roots:
        if candidate.is_file(): return candidate
    found=shutil.which("MpCmdRun.exe")
    return Path(found) if found else None

def defender_status():
    if os.name != "nt":
        raise RuntimeError("Microsoft Defender status integration is Windows-only")
    ps=shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not ps: raise RuntimeError("PowerShell was not found")
    cmd="Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated | ConvertTo-Json -Compress"
    result=subprocess.run([ps,"-NoProfile","-NonInteractive","-Command",cmd],capture_output=True,text=True,timeout=30)
    text=(result.stdout or result.stderr).strip()
    if result.returncode: raise RuntimeError(text or f"PowerShell exited {result.returncode}")
    print(text)

def defender_scan(target):
    if os.name != "nt":
        raise RuntimeError("Microsoft Defender scan integration is Windows-only")
    path=Path(target).expanduser().resolve()
    if not path.exists(): raise FileNotFoundError(path)
    exe=find_mpcmdrun()
    if not exe: raise RuntimeError("MpCmdRun.exe not found; check Microsoft Defender installation")
    print("Using Microsoft Defender:",exe)
    result=subprocess.run([str(exe),"-Scan","-ScanType","3","-File",str(path)],capture_output=True,text=True,timeout=7200)
    output=(result.stdout or "")+(("\n"+result.stderr) if result.stderr else "")
    if output.strip(): print(output.strip())
    print("Defender scan process exit code:",result.returncode)
    if result.returncode: raise RuntimeError("Microsoft Defender reported a non-zero exit code; inspect Windows Security and its event log")
