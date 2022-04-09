package manualmap

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32DLL            = windows.NewLazySystemDLL("kernel32.dll")
	VirtualAllocExProc     = kernel32DLL.NewProc("VirtualAllocEx")
	writeProcessMemoryProc = kernel32DLL.NewProc("WriteProcessMemory")
	procGetProcAddress     = kernel32DLL.NewProc("GetProcAddress")
	CreateRemoteThreadProc = kernel32DLL.NewProc("CreateRemoteThread")
)

func CreateRemoteThread(process syscall.Handle, sa *syscall.SecurityAttributes, stackSize uint32, startAddress,
	parameter uintptr, creationFlags uint32) (syscall.Handle, uint32, error) {
	var threadId uint32
	r1, _, e1 := CreateRemoteThreadProc.Call(
		uintptr(process),
		uintptr(unsafe.Pointer(sa)),
		uintptr(stackSize),
		startAddress,
		parameter,
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(&threadId)))
	runtime.KeepAlive(sa)
	if int(r1) == 0 {
		return syscall.InvalidHandle, 0, os.NewSyscallError("CreateRemoteThread", e1)
	}
	return syscall.Handle(r1), threadId, nil
}

// GetProcAddressByOrdinal retrieves the address of the exported
// function from module by ordinal.
func GetProcAddressByOrdinal(module syscall.Handle, ordinal uintptr) (uintptr, error) {
	r0, _, _ := syscall.Syscall(procGetProcAddress.Addr(), 2, uintptr(module), ordinal, 0)
	proc := uintptr(r0)
	if proc == 0 {
		return 0, syscall.EINVAL
	}
	return proc, nil
}

func VirtualAllocEx(h windows.Handle, lpAddress uintptr, dwSize uintptr,
	flAllocationType uint32, flProtect uint32) (uintptr, error) {
	r1, _, lastErr := VirtualAllocExProc.Call(uintptr(h),
		uintptr(lpAddress),
		uintptr(dwSize),
		uintptr(flAllocationType),
		uintptr(flProtect))
	if r1 == 0 {
		return 0, lastErr
	}
	return r1, nil
}

func WriteProcessMemory(hProcess windows.Handle, lpBaseAddress uintptr, lpBuffer []byte) (int, error) {
	const bufSize = 4096
	var tmpBuf [bufSize]byte
	var lpNumberOfBytesWritten int
	written := 0
	for written < len(lpBuffer) {
		var src []byte
		// Maybe need <=
		if written+bufSize < len(lpBuffer) {
			src = lpBuffer[written : written+bufSize]
		} else {
			src = lpBuffer[written:]
		}
		nSize := copy(tmpBuf[:], src)
		r1, _, lastErr := writeProcessMemoryProc.Call(
			uintptr(hProcess),
			uintptr(lpBaseAddress+uintptr(written)),
			uintptr(unsafe.Pointer(&tmpBuf)),
			uintptr(nSize),
			uintptr(unsafe.Pointer(&lpNumberOfBytesWritten)))
		if r1 == 0 {
			return written + int(lpNumberOfBytesWritten), lastErr
		}
		written += int(lpNumberOfBytesWritten)
	}
	return written, nil
}
