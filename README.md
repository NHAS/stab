# Stab
Stab is a fully golang Manual Mapper that can inject x86 and x64 bit DLLs into local and remote processes. 
Local meaning our current process, and remote meaning another process on the same machine that is owned by the same user.


This project provides the `MemoryLoadLibrary(...)` function which can load a DLL from bytes. Which is handy for fileless exploitation. 

## Run me
This project also contains a little main function as an example of how to use the methods. 

```
#Build
GOOS=windows go build

 #Inject into the local process
./stab.exe .\Path\to\dll

 #Inject into a remote process
./stab.exe .\Path\to\dll 2910

#Build with embedded DLL (put DLL in pkg/embed/preload)
GOOS=windows go build -tags=embed
./stab.exe <pid>
```
