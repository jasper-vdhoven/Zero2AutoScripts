# Zero2AutoScripts
Scripts / Tools written during Zero2Auto course.

# (Sort of) Index of Tools

## `ursnif.py`

Takes a lookup table string found in the macros for an ursnif maldoc and translates any obfuscated `Array()`s found within it (granted they follow the same obfuscation logic).

Example usage

```ps
PS C:\Macros > python .\ursnif.py -h
usage: ursnif.py [-h] -i ./ursnif-macro.vbs

options:
  -h, --help            show this help message and exit
  -i ./ursnif-macro.vbs, --infile ./ursnif-macro.vbs
                        A VBScript from the Ursnif malware containing character arrays

PS C:\Scripts> python ursnif.py -i C:\Samples\Zero2Automated\macros\ursnif-macro.vbs
[i] Ursnif macro deobfuscator script by: Jasper vd Hoven
[i] Attempting to open macro file: C:\Samples\Zero2Automated\macros\ursnif-macro.vbs
[i] Attempting to parse VBS file for target Array() objects
[i] Found 4 arrays
[i] Transforming input buffer into to source strings
[i] powershell.exe
[i] -nop -exec bypass -win hidden -noni -e 
[i] C:\Windows\System32
[i] new:{9BA05972-F6A8-11CF-A442-00A0C90A8F39}
[!] Current string matches as CLSID, attempting to lookup CLSID on pirate server
[i]     CLSID: 9BA05972-F6A8-11CF-A442-00A0C90A8F39 == CLSID ShellWindows
```
