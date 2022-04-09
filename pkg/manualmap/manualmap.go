package manualmap

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func MemoryLoadLibrary(PE []byte, pid int) error {
	if PE == nil {
		return errors.New("Error null")
	}

	peInfo, err := GetPEBasicInfo(PE)
	if err != nil {
		return err
	}

	remoteProcess, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(pid))
	if err != nil || remoteProcess == 0 {
		return err
	}

	peInfo.WriteHandle, err = VirtualAllocEx(remoteProcess, 0, uintptr(peInfo.SizeOfImage), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return err
	}

	fullData, err := CopySections(peInfo, PE)
	if err != nil {
		return err
	}

	RebaseImage(fullData, peInfo)

	err = FixImports(peInfo.PEFile, fullData)
	if err != nil {
		return err
	}

	_, err = WriteProcessMemory(remoteProcess, peInfo.WriteHandle, fullData)
	if err != nil {
		return err
	}

	entry := peInfo.WriteHandle + uintptr(peInfo.AddressOfEntryPoint)

	err = CallDLLMain(peInfo.WriteHandle, entry, uintptr(remoteProcess))
	if err != nil {
		return err
	}

	return windows.CloseHandle(remoteProcess)

}

func RebaseImage(local_image []byte, peInfo PEInfo) error {

	var relocsSection *pe.Section
	for i := range peInfo.Sections {
		if peInfo.Sections[i].Name == ".reloc" {
			relocsSection = peInfo.Sections[i]
			break
		}
	}

	delta := peInfo.WriteHandle - uintptr(peInfo.OriginalImageBase)

	sectionReader := relocsSection.Open()

	for {
		var reloc BaseReloc
		err := binary.Read(sectionReader, binary.LittleEndian, &reloc)
		if err != nil || reloc.VirtualAddress == 0 || reloc.SizeOfBlock == 0 || reloc.VirtualAddress > peInfo.BaseRelocationTable.Size+peInfo.BaseRelocationTable.VirtualAddress {
			break
		}

		count := (reloc.SizeOfBlock - 8) / 2

		for i := uint32(0); i < count; i++ {

			var r Reloc
			err = binary.Read(sectionReader, binary.LittleEndian, &r)
			if err != nil {
				break
			}

			t := uint8(r >> 12)
			offset := r & Reloc(0x0FFF)

			switch t {
			case IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW:
				orgAddress, _ := Read(local_image[reloc.VirtualAddress+uint32(offset):])
				Write(orgAddress+delta, local_image[reloc.VirtualAddress+uint32(offset):])

			default:

			}

		}

	}

	return nil
}

func CallDLLMain(remoteAddr uintptr, entry uintptr, processHandle uintptr) error {

	shellcode := code.Resolve(remoteAddr, entry)

	shellCodeWriteHandle, err := VirtualAllocEx(
		windows.Handle(processHandle),
		0,
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)

	if err != nil {
		return err
	}

	_, err = WriteProcessMemory(windows.Handle(processHandle), shellCodeWriteHandle, shellcode)

	if err != nil {
		return err
	}

	threadHandle, _, err := CreateRemoteThread(syscall.Handle(processHandle), nil, 0, shellCodeWriteHandle, 0, 0)
	if err != nil {
		return err
	}

	windows.CloseHandle(windows.Handle(threadHandle))

	return nil
}

func CopySections(peInfo PEInfo, PEBytes []byte) ([]byte, error) {

	fullData := make([]byte, peInfo.SizeOfImage)

	fmt.Println("Total Size:   ", len(fullData))

	for _, section := range peInfo.Sections {

		destAddr := section.VirtualAddress
		sectionData, err := section.Data()
		if len(sectionData) == 0 || err != nil {
			sectionData = nil
		}

		if section.Size > section.VirtualSize {
			sectionData = sectionData[:section.VirtualSize]
		}

		if sectionData != nil {
			n := copy(fullData[destAddr:], sectionData)
			if n != len(sectionData) {
				return nil, errors.New("Unable to write data")
			}
		}
	}

	return fullData, nil
}

func GetPEBasicInfo(PE []byte) (PEInfo, error) {
	f, err := pe.NewFile(bytes.NewReader(PE))
	if err != nil {
		return PEInfo{}, err
	}

	if f.OptionalHeader == nil {
		return PEInfo{}, errors.New("Optional header is empty")
	}

	var p PEInfo
	p.PE64Bit = f.Machine == pe.IMAGE_FILE_MACHINE_AMD64 || f.Machine == pe.IMAGE_FILE_MACHINE_ARM64

	if p.PE64Bit {
		p.OriginalImageBase = uintptr(f.OptionalHeader.(*pe.OptionalHeader64).ImageBase)
	} else {
		p.OriginalImageBase = uintptr(f.OptionalHeader.(*pe.OptionalHeader32).ImageBase)
	}

	if p.PE64Bit {
		p.SizeOfImage = f.OptionalHeader.(*pe.OptionalHeader64).SizeOfImage
	} else {
		p.SizeOfImage = f.OptionalHeader.(*pe.OptionalHeader32).SizeOfImage
	}

	if p.PE64Bit {
		p.SizeOfHeaders = f.OptionalHeader.(*pe.OptionalHeader64).SizeOfHeaders
	} else {
		p.SizeOfHeaders = f.OptionalHeader.(*pe.OptionalHeader32).SizeOfHeaders
	}

	if p.PE64Bit {
		p.DllCharacteristics = f.OptionalHeader.(*pe.OptionalHeader64).DllCharacteristics
	} else {
		p.DllCharacteristics = f.OptionalHeader.(*pe.OptionalHeader32).DllCharacteristics
	}

	if p.PE64Bit {
		p.BaseRelocationTable = f.OptionalHeader.(*pe.OptionalHeader64).DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
	} else {
		p.BaseRelocationTable = f.OptionalHeader.(*pe.OptionalHeader32).DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
	}

	if p.PE64Bit {
		p.AddressOfEntryPoint = f.OptionalHeader.(*pe.OptionalHeader64).AddressOfEntryPoint
	} else {
		p.AddressOfEntryPoint = f.OptionalHeader.(*pe.OptionalHeader32).AddressOfEntryPoint
	}

	p.Sections = f.Sections
	p.PEFile = f

	return p, nil
}

func FixImports(f *pe.File, local_image []byte) error {
	if f.OptionalHeader == nil {
		return nil
	}

	pe64 := f.Machine == pe.IMAGE_FILE_MACHINE_AMD64 || f.Machine == pe.IMAGE_FILE_MACHINE_ARM64

	// grab the number of data directory entries
	var dd_length uint32
	if pe64 {
		dd_length = f.OptionalHeader.(*pe.OptionalHeader64).NumberOfRvaAndSizes
	} else {
		dd_length = f.OptionalHeader.(*pe.OptionalHeader32).NumberOfRvaAndSizes
	}

	// check that the length of data directory entries is large
	// enough to include the imports directory.
	if dd_length < pe.IMAGE_DIRECTORY_ENTRY_IMPORT+1 {
		return nil
	}

	// grab the import data directory entry
	var idd pe.DataDirectory
	if pe64 {
		idd = f.OptionalHeader.(*pe.OptionalHeader64).DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
	} else {
		idd = f.OptionalHeader.(*pe.OptionalHeader32).DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
	}

	// figure out which section contains the import directory table
	var ds *pe.Section
	ds = nil
	for _, s := range f.Sections {
		if s.VirtualAddress <= idd.VirtualAddress && idd.VirtualAddress < s.VirtualAddress+s.VirtualSize {
			ds = s
			break
		}
	}

	// didn't find a section, so no import libraries were found
	if ds == nil {
		return nil
	}

	d, err := ds.Data()
	if err != nil {
		return err
	}

	// seek to the virtual address specified in the import data directory
	d = d[idd.VirtualAddress-ds.VirtualAddress:]

	// start decoding the import directory
	var ida []ImportDirectory
	for len(d) >= 20 {
		var dt ImportDirectory
		dt.OriginalFirstThunk = binary.LittleEndian.Uint32(d[0:4])
		dt.TimeDateStamp = binary.LittleEndian.Uint32(d[4:8])
		dt.ForwarderChain = binary.LittleEndian.Uint32(d[8:12])
		dt.Name = binary.LittleEndian.Uint32(d[12:16])
		dt.FirstThunk = binary.LittleEndian.Uint32(d[16:20])
		d = d[20:]
		if dt.OriginalFirstThunk == 0 {
			break
		}
		ida = append(ida, dt)
	}

	names, _ := ds.Data()
	for _, dt := range ida {
		dt.DllName, _ = getString(names, int(dt.Name-ds.VirtualAddress))
		libHandle, err := windows.LoadLibrary(dt.DllName)
		if err != nil {
			return err
		}

		// seek to OriginalFirstThunk
		OrgFirstThunkIndex := dt.OriginalFirstThunk
		if OrgFirstThunkIndex == 0 {
			OrgFirstThunkIndex = dt.FirstThunk
		}

		// WE read from the original first thunk array, and write to the FirstThunk array
		originalFirstThunk := local_image[OrgFirstThunkIndex:]
		thunk := local_image[dt.FirstThunk:]

		ptrSize := unsafe.Sizeof(uintptr(0))

		for {
			//Begin parsing IMAGE_THUNK_DATA

			//Effectively advancing originalFirstThunk = originalFirstThunk[ptrSize:]
			var va uintptr
			va, originalFirstThunk = Read(originalFirstThunk)
			if va == 0 {
				break
			}

			var proc uintptr

			if va&uintptr(IMAGE_ORDINAL) > 0 {
				proc, err = GetProcAddressByOrdinal(syscall.Handle(libHandle), uintptr(va&0xffff))
				if err != nil {
					return err
				}
			} else {
				fn, _ := getString(names, int(uint32(va)-ds.VirtualAddress+2))
				proc, err = windows.GetProcAddress(libHandle, fn)
				if err != nil {
					return err
				}
			}

			Write(proc, thunk)

			thunk = thunk[ptrSize:]
		}
	}

	return nil
}

func Write(proc uintptr, location []byte) {

	ptrSize := unsafe.Sizeof(proc)
	for i := uintptr(0); i < ptrSize; i += 2 {

		nProc := proc >> (i * ptrSize)

		binary.LittleEndian.PutUint16(location, uint16(nProc))
		location = location[2:]
	}
}

func Read(location []byte) (data uintptr, finishedLoc []byte) {

	finishedLoc = location
	ptrSize := unsafe.Sizeof(uintptr(0))
	i := uintptr(0)
	for ; i < ptrSize; i += 2 {

		val := uintptr(binary.LittleEndian.Uint16(finishedLoc))
		data |= val << (i * ptrSize)
		finishedLoc = finishedLoc[2:]
	}

	return
}

// getString extracts a string from symbol string table.
func getString(section []byte, start int) (string, bool) {
	if start < 0 || start >= len(section) {
		return "", false
	}

	for end := start; end < len(section); end++ {
		if section[end] == 0 {
			return string(section[start:end]), true
		}
	}
	return "", false
}
