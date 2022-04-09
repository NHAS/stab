package manualmap

import "debug/pe"

type PEInfo struct {
	WriteHandle uintptr

	PE64Bit             bool
	OriginalImageBase   uintptr
	SizeOfImage         uint32
	SizeOfHeaders       uint32
	AddressOfEntryPoint uint32
	DllCharacteristics  uint16
	BaseRelocationTable pe.DataDirectory
	Sections            []*pe.Section
	PEFile              *pe.File
}

type ImportDirectory struct {
	pe.ImportDirectory
	DllName string
}

type BaseReloc struct {
	VirtualAddress uint32
	SizeOfBlock    uint32
}

type Reloc uint16
