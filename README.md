# BreadManModuleStomping

This project was created to show off a technique I created called BreadManModuleStomping. It performs module stomping with a unique twist. Instead of loading a module into memory and then overwriting the contents of the .text section with a malicious payload. It does the following:

1) Searches for a code cave in previously loaded module (i.e. kernel32) that has the capacity to fit our shellcode
2) Changes memory permissions from execute & read to read & write
3) writes payload to code cave
4) Executes payload to code cave.

This has a few benefits from an offensive security perspective:

1) Does not require interaction with the file system or windows loader. - Less possibilty to trigger events.
2) Code execution appears to come from legitimately loaded module in the call stack. - Less possibility for call stack detection.
