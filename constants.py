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


__RESOURCE_TYPE = {
	'0': "Manifest",
	'1': "Cursor",
	'2': "Bitmap",
	'3': "Icon",
	'4': "Menu",
	'5': "Dialog",
	'6': "String-table",
	'7': "Message-table",
	'8': "Font-directory",
	'9': "Font",
	'10': "Accelerator",
	'11': "Rcdata",
	'12': "Cursor-group",
	'13': "Icon-group",
	'14': "Version",
	'15': "DlgInclude",
	'16': "Plug-and-play",
	'17': "Vxd",
	'18': "Animated-cursor",
	'19': "Animated-icon",
	'20': "HTML",
	'21': "MUI",
	'22': "Icons",
	'23': "Custom",
	'24': "Executable",
	'25': "Compiled-HTML",
	'26': "Riff",
	'27': "GIF",
	'28': "PNG",
	'29': "BMP",
	'30': "Typelib",
	'31': "Registry",
	'32': "Driver-Installation-File",
	'33': "PDF",
	'34': "CAB",
	'35': "PKZIP",
	'36': "PKlite",
	'37': "PKSfx",
	'38': "JAR",
	'39': "Delphi-Form",
	'40': "7zSFX",
	'41': "Stylesheet-XML",
	'42': "MOF",
	'43': "XML Event Log",
	'44': "Rich-Text",
	'45': "Nullsoft",
	'46': "AutoIt",
	'47': "Nb10",
	'48': "Spoon",
	'49': "RAR",
	'50': "Smart-installer",
	'51': "InnoSetup",
	'52': "Flash",
	'53': "Flash",
	'54': "Debugger",
	'55': "FPO-debug",
	'56': "Text",
	'57': "JPEG",
	'58': "Registry-file",
	'59': "aPLib-compressed",
	'60': "Python",
	'61': "Python-script",
	'62': "SFX",
	'63': "XML",
	'64': "Delphi-Config",
	'65': "Microsoft-Word",
	'66': "any"
}

def RES_TO_STR(x):
	return __RESOURCE_TYPE.get(str(x), "Unknown")

RED   = "\033[1;31m"  
BLUE  = "\033[1;34m"
CYAN  = "\033[1;36m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
