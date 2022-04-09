package manualmap

type Shellcode struct {
	Instruct         []byte
	EntryPointOffset uintptr
	HandleOffset     uintptr
}

func (s *Shellcode) Resolve(Handle, EntryPoint uintptr) []byte {
	Write(Handle, s.Instruct[code.HandleOffset:])
	Write(EntryPoint, s.Instruct[code.EntryPointOffset:])

	return s.Instruct
}
