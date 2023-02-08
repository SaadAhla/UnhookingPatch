# UnhookingPatch
Bypass EDR Hooks by patching NT API stub, and resolving SSNs and syscall instructions at runtime

![image](https://raw.githubusercontent.com/illegal-instruction-co/UnhookingPatch/main/assets/view.jpg)

## Building
Run build.bat if you are building it first time, then you can build it after changes from **VS** command prompt.

## How do i convert binary to MAC ?

Requirements: 
1. macaddress

```
pip install macaddress
./tools/bin2mac.py shellcode_file.exe
```
Then check
./tools/shellcode_file.exe.c
