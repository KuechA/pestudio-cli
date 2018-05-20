# See https://msdn.microsoft.com/en-us/library/windows/desktop/ms680547(v=vs.85).aspx

MACHINE_TYPE = {
	0x0: "unknown",
	0x1d3: "Matsushita AM33",
	0x8664: "x64",
	0x1c0: "ARM little endian",
	0xaa64: "ARM64 little endian",
	0x1c4: "ARM Thumb-2 little endian",
	0xebc: "EFI byte code",
	0x14c: "Intel 386 or later and compatible",
	0x200: "Intel Itanium",
	0x9041: "Mitsubishi M32R little endian",
	0x266: "MIPS16",
	0x366: "MIPS with FPU",
	0x466: "MIPS16 with FPU",
	0x1f0: "Power PC little endian",
	0x1f1: "Power PC with floating point support",
	0x166: "MIPS little endian",
	0x5032: "RISC-V 32-bit",
	0x5064: "RISC-V 64-bit",
	0x5128: "RISC-V 128-bit",
	0x1a2: "Hitachi SH3",
	0x1a3: "Hitachi SH3 DSP",
	0x1a6: "Hitachi SH4",
	0x1a8: "Hitachi SH5",
	0x1c2: "Thumb",
	0x169: "MIPS little-endian WCE v2"
}


RED   = "\033[1;31m"  
BLUE  = "\033[1;34m"
CYAN  = "\033[1;36m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"