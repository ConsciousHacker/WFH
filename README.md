# Windows Feature Hunter (WFH)
Windows Feature Hunter (WFH) is a proof of concept python script that uses [Frida](https://frida.re/), a dynamic instrumentation toolkit, to assist in potentially identifying common “vulnerabilities” or “features” within Windows executables. WFH currently has the capability to automatically identify potential Dynamic Linked Library (DLL) sideloading and Component Object Model (COM) hijacking opportunities at scale. 

DLL sideloading utilizes the Windows side-by-side (WinSXS) assembly to load a malicious DLL from the side-by-side (SXS) listing. COM hijacking allows an adversary to insert malicious code that can be executed in place of legitimate software through hijacking the COM references and relationships. WFH will print the potential vulnerabilities and write a CSV file containing the potential vulnerabilities in the target Windows executables.
## Install
```
pip install -r requirements.txt
```
## Help
```
PS C:\Tools\WFH > python .\wfh.py -h
usage: wfh.py [-h] -t T [T ...] -m {dll,com} [-v] [-timeout TIMEOUT]

Windows Feature Hunter

optional arguments:
  -h, --help            show this help message and exit
  -t T [T ...], -targets T [T ...]
                        list of target windows executables
  -m {dll,com}, -mode {dll,com}
                        vulnerabilities to potentially identify
  -v, -verbose          verbose output from Frida instrumentation
  -timeout TIMEOUT      timeout value for Frida instrumentation

EXAMPLE USAGE
    NOTE: It is recommended to copy target binaries to the same directory as wfh for identifying DLL Sideloading

    DLL Sideloading Identification (Single):        python wfh.py -t .\mspaint.exe -m dll
    DLL Sideloading Identification (Verbose):       python wfh.py -t .\mspaint.exe -m dll -v
    DLL Sideloading Identification (Timeout 30s):   python wfh.py -t .\mspaint.exe -m dll -timeout 30
    DLL Sideloading Identification (Wildcard):      python wfh.py -t * -m dll
    DLL Sideloading Identification (List):          python wfh.py -t .\mspaint.exe .\charmap.exe -m dll

    COM Hijacking Identification (Single):          python wfh.py -t "C:\Program Files\Internet Explorer\iexplore.exe" -m com
    COM Hijacking Identification (Verbose):         python wfh.py -t "C:\Program Files\Internet Explorer\iexplore.exe" -m com -v
    COM Hijacking Identification (Timeout 60s):     python wfh.py -t "C:\Program Files\Internet Explorer\iexplore.exe" -m com -timeout 60
    COM Hijacking Identification (Wildcard):        python wfh.py -t * -m com -v
    COM Hijacking Identification (List):            python wfh.py -t "C:\Program Files\Internet Explorer\iexplore.exe" "C:\Windows\System32\notepad.exe" -m com -v
```
## Usage
### DLL Sideloading Identification
First you need to copy the binaries you want to analyze to the same directory as wfh
```
PS C:\Tools\WFH > copy C:\Windows\System32\mspaint.exe .
PS C:\Tools\WFH > copy C:\Windows\System32\charmap.exe .
PS C:\Tools\WFH > dir


    Directory: C:\Tools\WFH


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         5/14/2021   2:12 PM                .vscode
-a----          5/6/2021   2:39 PM           1928 .gitignore
-a----         12/7/2019   2:09 AM         198656 charmap.exe
-a----         5/18/2021   7:39 AM           6603 loadlibrary.js
-a----          4/7/2021  12:48 PM         988160 mspaint.exe
-a----         5/18/2021   7:53 AM           8705 README.md
-a----         5/17/2021  11:27 AM           5948 registry.js
-a----          5/6/2021   2:41 PM             11 requirements.txt
-a----         5/18/2021   8:35 AM          10623 wfh.py
```
Now you can run wfh against the binaries to identify dll sideloading opportunities
```
PS C:\Tools\WFH > python .\wfh.py -t * -m dll
==================================================
Running Frida against charmap.exe
--------------------------------------------------
        [+] Potential DllMain Sideloading: LoadLibraryW,LPCWSTR: MSFTEDIT.DLL
        [+] Potential DllMain Sideloading: LoadLibraryExW,LPCWSTR : MSFTEDIT.DLL, dwFlags : NONE

[*] Writing raw Frida instrumentation to charmap.exe-raw.log
[*] Writing Potential DLL Sideloading to charmap.exe-sideload.log
--------------------------------------------------
==================================================
Running Frida against mspaint.exe
--------------------------------------------------
        [+] Potential DllMain Sideloading: LoadLibraryExW,LPCWSTR : gdiplus.dll, dwFlags : NONE
        [-] Potential DllExport Sideloading: GetProcAddress,hModule : C:\WINDOWS\WinSxS\amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.19041.789_none_faf0a7e97612e7bb\gdiplus.dll, LPCSTR: GdiplusStartup
        [+] Potential DllMain Sideloading: LoadLibraryW,LPCWSTR: MSFTEDIT.DLL
        [+] Potential DllMain Sideloading: LoadLibraryExW,LPCWSTR : MSFTEDIT.DLL, dwFlags : NONE

[*] Writing raw Frida instrumentation to mspaint.exe-raw.log
[*] Writing Potential DLL Sideloading to mspaint.exe-sideload.log
--------------------------------------------------
==================================================
[*] Writing dll results to dll_results.csv

PS C:\Tools\WFH > type .\dll_results.csv
Executable,WinAPI,DLL,EntryPoint / WinAPI Args
charmap.exe,LoadLibraryW,LPCWSTR: MSFTEDIT.DLL
charmap.exe,LoadLibraryExW,LPCWSTR : MSFTEDIT.DLL, dwFlags : NONE
mspaint.exe,LoadLibraryExW,LPCWSTR : gdiplus.dll, dwFlags : NONE
mspaint.exe,GetProcAddress,hModule : C:\WINDOWS\WinSxS\amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.19041.789_none_faf0a7e97612e7bb\gdiplus.dll, LPCSTR: GdiplusStartup
mspaint.exe,LoadLibraryW,LPCWSTR: MSFTEDIT.DLL
mspaint.exe,LoadLibraryExW,LPCWSTR : MSFTEDIT.DLL, dwFlags : NONE
```
If you prefer more verbose output, you can use "-v" to see every message from Frida instrumenting the Windows API calls. You can also view this output in the raw log file.
```
PS C:\Tools\WFH > python .\wfh.py -t * -m dll -v
==================================================
Running Frida against charmap.exe
{'type': 'send', 'payload': 'LoadLibraryW,LPCWSTR: MSFTEDIT.DLL'}
{'type': 'send', 'payload': 'LoadLibraryExW,LPCWSTR : MSFTEDIT.DLL, dwFlags : NONE'}
--------------------------------------------------
        [+] Potential DllMain Sideloading: LoadLibraryW,LPCWSTR: MSFTEDIT.DLL
        [+] Potential DllMain Sideloading: LoadLibraryExW,LPCWSTR : MSFTEDIT.DLL, dwFlags : NONE

[*] Writing raw Frida instrumentation to charmap.exe-raw.log
[*] Writing Potential DLL Sideloading to charmap.exe-sideload.log
--------------------------------------------------
==================================================
Running Frida against mspaint.exe
{'type': 'send', 'payload': 'LoadLibraryExW,LPCWSTR : gdiplus.dll, dwFlags : NONE'}
{'type': 'send', 'payload': 'GetProcAddress,hModule : C:\\WINDOWS\\WinSxS\\amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.19041.789_none_faf0a7e97612e7bb\\gdiplus.dll, LPCSTR: GdiplusStartup'}
{'type': 'send', 'payload': 'LoadLibraryW,LPCWSTR: MSFTEDIT.DLL'}
{'type': 'send', 'payload': 'LoadLibraryExW,LPCWSTR : MSFTEDIT.DLL, dwFlags : NONE'}
--------------------------------------------------
        [+] Potential DllMain Sideloading: LoadLibraryExW,LPCWSTR : gdiplus.dll, dwFlags : NONE
        [-] Potential DllExport Sideloading: GetProcAddress,hModule : C:\WINDOWS\WinSxS\amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.19041.789_none_faf0a7e97612e7bb\gdiplus.dll, LPCSTR: GdiplusStartup
        [+] Potential DllMain Sideloading: LoadLibraryW,LPCWSTR: MSFTEDIT.DLL
        [+] Potential DllMain Sideloading: LoadLibraryExW,LPCWSTR : MSFTEDIT.DLL, dwFlags : NONE

[*] Writing raw Frida instrumentation to mspaint.exe-raw.log
[*] Writing Potential DLL Sideloading to mspaint.exe-sideload.log
--------------------------------------------------
==================================================
[*] Writing dll results to dll_results.csv
```
### COM Hijacking Identification
```
PS C:\Tools\WFH > python .\wfh.py -t "C:\Program Files\Internet Explorer\iexplore.exe" -m com
==================================================
Running Frida against C:\Program Files\Internet Explorer\iexplore.exe
--------------------------------------------------
        [+] Potential COM Hijack: Path : HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{0E5AAE11-A475-4C5B-AB00-C66DE400274E}\InProcServer32,lpValueName : null,Type : REG_EXPAND_SZ, Value : %SystemRoot%\system32\Windows.Storage.dll
        [+] Potential COM Hijack: Path : HKEY_CLASSES_ROOT\CLSID\{1FD49718-1D00-4B19-AF5F-070AF6D5D54C}\InProcServer32,lpValueName : null,Type : REG_SZ, Value : C:\Program Files (x86)\Microsoft\Edge\Application\90.0.818.62\BHO\ie_to_edge_bho_64.dll

[*] Writing raw Frida instrumentation to .\iexplore.exe-raw.log
[*] Writing Potential COM Hijack to .\iexplore.exe-comhijack.log
--------------------------------------------------
==================================================
[*] Writing dll results to comhijack_results.csv
```
## Use Cases
### Native Windows Signed Binaries
Copy all native Windows signed binaries to wfh directory
```
Get-ChildItem c:\ -File | ForEach-Object { if($_ -match '.+?exe$') {Get-AuthenticodeSignature $_.fullname} } | where {$_.IsOSBinary} | ForEach-Object {Copy-Item $_.path . }
```
Hunt for DLL sideloading opportunities
```
python wfh.py -t * -m dll
```
Hunt for COM hijacking opportunities
```
python wfh.py -t * -m com
```