Set-StrictMode -Version Latest

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

function Put-U16LE {
    param([byte[]]$Bytes, [UInt32]$Offset, [UInt16]$Value)
    $Bytes[$Offset + 0] = [byte]($Value -band 0xff)
    $Bytes[$Offset + 1] = [byte](($Value -shr 8) -band 0xff)
}

function Put-U32LE {
    param([byte[]]$Bytes, [UInt32]$Offset, [UInt32]$Value)
    for ($Index = [UInt32]0; $Index -lt 4; ++$Index) {
        $Bytes[$Offset + $Index] = [byte](($Value -shr ([Int32](8 * $Index))) -band 0xff)
    }
}

function Put-U64LE {
    param([byte[]]$Bytes, [UInt32]$Offset, [UInt64]$Value)
    for ($Index = [UInt32]0; $Index -lt 8; ++$Index) {
        $Bytes[$Offset + $Index] = [byte](($Value -shr ([Int32](8 * $Index))) -band 0xff)
    }
}

function Put-U16BE {
    param([byte[]]$Bytes, [UInt32]$Offset, [UInt16]$Value)
    $Bytes[$Offset + 0] = [byte](($Value -shr 8) -band 0xff)
    $Bytes[$Offset + 1] = [byte]($Value -band 0xff)
}

function Put-U32BE {
    param([byte[]]$Bytes, [UInt32]$Offset, [UInt32]$Value)
    for ($Index = [UInt32]0; $Index -lt 4; ++$Index) {
        $Shift = [Int32](8 * (3 - $Index))
        $Bytes[$Offset + $Index] = [byte](($Value -shr $Shift) -band 0xff)
    }
}

function Put-U64BE {
    param([byte[]]$Bytes, [UInt32]$Offset, [UInt64]$Value)
    for ($Index = [UInt32]0; $Index -lt 8; ++$Index) {
        $Shift = [Int32](8 * (7 - $Index))
        $Bytes[$Offset + $Index] = [byte](($Value -shr $Shift) -band 0xff)
    }
}

function Put-U16 {
    param([byte[]]$Bytes, [UInt32]$Offset, [UInt16]$Value, [bool]$BigEndian)
    if ($BigEndian) {
        Put-U16BE $Bytes $Offset $Value
    } else {
        Put-U16LE $Bytes $Offset $Value
    }
}

function Put-U32 {
    param([byte[]]$Bytes, [UInt32]$Offset, [UInt32]$Value, [bool]$BigEndian)
    if ($BigEndian) {
        Put-U32BE $Bytes $Offset $Value
    } else {
        Put-U32LE $Bytes $Offset $Value
    }
}

function Put-U64 {
    param([byte[]]$Bytes, [UInt32]$Offset, [UInt64]$Value, [bool]$BigEndian)
    if ($BigEndian) {
        Put-U64BE $Bytes $Offset $Value
    } else {
        Put-U64LE $Bytes $Offset $Value
    }
}

function Put-Ascii {
    param([byte[]]$Bytes, [UInt32]$Offset, [string]$Text)
    $Data = [Text.Encoding]::ASCII.GetBytes($Text)
    for ($Index = [UInt32]0; $Index -lt $Data.Length; ++$Index) {
        $Bytes[$Offset + $Index] = $Data[$Index]
    }
}

function Put-Note {
    param([byte[]]$Bytes, [UInt32]$Offset, [bool]$BigEndian)
    Put-U32 $Bytes ($Offset + 0x00) 6 $BigEndian
    Put-U32 $Bytes ($Offset + 0x04) 4 $BigEndian
    Put-U32 $Bytes ($Offset + 0x08) 1 $BigEndian
    Put-Ascii $Bytes ($Offset + 0x0C) "PEELF"
    $Bytes[$Offset + 0x14] = 0x11
    $Bytes[$Offset + 0x15] = 0x22
    $Bytes[$Offset + 0x16] = 0x33
    $Bytes[$Offset + 0x17] = 0x44
}

function Put-SysvHash {
    param([byte[]]$Bytes, [UInt32]$Offset, [bool]$BigEndian)
    Put-U32 $Bytes ($Offset + 0x00) 1 $BigEndian
    Put-U32 $Bytes ($Offset + 0x04) 2 $BigEndian
    Put-U32 $Bytes ($Offset + 0x08) 1 $BigEndian
    Put-U32 $Bytes ($Offset + 0x0C) 0 $BigEndian
    Put-U32 $Bytes ($Offset + 0x10) 0 $BigEndian
}

function Put-GnuHash {
    param([byte[]]$Bytes, [UInt32]$Offset, [bool]$BigEndian, [bool]$Elf64)
    Put-U32 $Bytes ($Offset + 0x00) 1 $BigEndian
    Put-U32 $Bytes ($Offset + 0x04) 1 $BigEndian
    Put-U32 $Bytes ($Offset + 0x08) 1 $BigEndian
    Put-U32 $Bytes ($Offset + 0x0C) 5 $BigEndian
    if ($Elf64) {
        Put-U64 $Bytes ($Offset + 0x10) 1 $BigEndian
        Put-U32 $Bytes ($Offset + 0x18) 1 $BigEndian
        Put-U32 $Bytes ($Offset + 0x1C) 1 $BigEndian
    } else {
        Put-U32 $Bytes ($Offset + 0x10) 1 $BigEndian
        Put-U32 $Bytes ($Offset + 0x14) 1 $BigEndian
        Put-U32 $Bytes ($Offset + 0x18) 1 $BigEndian
    }
}

function Put-CodeViewRsds {
    param([byte[]]$Bytes, [UInt32]$Offset, [UInt32]$Age, [string]$PdbPath, [byte]$GuidBase)
    Put-Ascii $Bytes $Offset "RSDS"
    for ($Index = [UInt32]0; $Index -lt 16; ++$Index) {
        $Bytes[$Offset + 0x04 + $Index] = [byte]($GuidBase + $Index)
    }
    Put-U32LE $Bytes ($Offset + 0x14) $Age
    Put-Ascii $Bytes ($Offset + 0x18) $PdbPath
}

function New-Elf64Fixture {
    param([string]$Name, [UInt16]$Machine)

    $Bytes = [byte[]]::new(0x680)
    $Bytes[0] = 0x7f
    $Bytes[1] = [byte][char]'E'
    $Bytes[2] = [byte][char]'L'
    $Bytes[3] = [byte][char]'F'
    $Bytes[4] = 2       # ELFCLASS64
    $Bytes[5] = 1       # ELFDATA2LSB
    $Bytes[6] = 1       # EV_CURRENT

    Put-U16LE $Bytes 0x10 2          # ET_EXEC
    Put-U16LE $Bytes 0x12 $Machine
    Put-U32LE $Bytes 0x14 1
    Put-U64LE $Bytes 0x18 0x400080
    Put-U64LE $Bytes 0x20 0x480      # e_phoff
    Put-U64LE $Bytes 0x28 0x180      # e_shoff
    Put-U16LE $Bytes 0x34 0x40       # e_ehsize
    Put-U16LE $Bytes 0x36 0x38       # e_phentsize
    Put-U16LE $Bytes 0x38 3          # e_phnum
    Put-U16LE $Bytes 0x3a 0x40       # e_shentsize
    Put-U16LE $Bytes 0x3c 11         # e_shnum
    Put-U16LE $Bytes 0x3e 2          # e_shstrndx

    Put-U32LE $Bytes 0x480 1          # PT_LOAD
    Put-U32LE $Bytes 0x484 5          # PF_R | PF_X
    Put-U64LE $Bytes 0x488 0x80       # p_offset
    Put-U64LE $Bytes 0x490 0x400080   # p_vaddr
    Put-U64LE $Bytes 0x498 0x400080   # p_paddr
    Put-U64LE $Bytes 0x4A0 0x10       # p_filesz
    Put-U64LE $Bytes 0x4A8 0x10       # p_memsz
    Put-U64LE $Bytes 0x4B0 0x1000     # p_align

    Put-U32LE $Bytes 0x4B8 3          # PT_INTERP
    Put-U32LE $Bytes 0x4BC 4          # PF_R
    Put-U64LE $Bytes 0x4C0 0x540      # p_offset
    Put-U64LE $Bytes 0x4C8 0x400540   # p_vaddr
    Put-U64LE $Bytes 0x4D0 0x400540   # p_paddr
    Put-U64LE $Bytes 0x4D8 0x11       # p_filesz
    Put-U64LE $Bytes 0x4E0 0x11       # p_memsz
    Put-U64LE $Bytes 0x4E8 1          # p_align

    Put-U32LE $Bytes 0x4F0 4          # PT_NOTE
    Put-U32LE $Bytes 0x4F4 4          # PF_R
    Put-U64LE $Bytes 0x4F8 0x560      # p_offset
    Put-U64LE $Bytes 0x500 0x400560   # p_vaddr
    Put-U64LE $Bytes 0x508 0x400560   # p_paddr
    Put-U64LE $Bytes 0x510 0x18       # p_filesz
    Put-U64LE $Bytes 0x518 0x18       # p_memsz
    Put-U64LE $Bytes 0x520 4          # p_align

    for ($Index = [UInt32]0; $Index -lt 16; ++$Index) {
        $Bytes[0x80 + $Index] = [byte](0x90 + ($Index % 16))
    }

    $Names = [Text.Encoding]::ASCII.GetBytes("`0.text`0.shstrtab`0.strtab`0.symtab`0.dynstr`0.dynamic`0.rela.dyn`0.note.peelf`0.hash`0.gnu.hash`0")
    for ($Index = [UInt32]0; $Index -lt $Names.Length; ++$Index) {
        $Bytes[0x90 + $Index] = $Names[$Index]
    }

    $SymNames = [byte[]](0, 95, 115, 116, 97, 114, 116, 0)
    for ($Index = [UInt32]0; $Index -lt $SymNames.Length; ++$Index) {
        $Bytes[0xF0 + $Index] = $SymNames[$Index]
    }

    $StartSym = [UInt32](0x100 + 0x18)
    Put-U32LE $Bytes ($StartSym + 0x00) 1        # st_name = "_start"
    $Bytes[$StartSym + 0x04] = 0x12              # STB_GLOBAL | STT_FUNC
    $Bytes[$StartSym + 0x05] = 0                 # st_other
    Put-U16LE $Bytes ($StartSym + 0x06) 1        # .text
    Put-U64LE $Bytes ($StartSym + 0x08) 0x400080
    Put-U64LE $Bytes ($StartSym + 0x10) 0x10

    $DynNames = [byte[]](0, 108, 105, 98, 99, 46, 115, 111, 46, 54, 0)
    for ($Index = [UInt32]0; $Index -lt $DynNames.Length; ++$Index) {
        $Bytes[0x138 + $Index] = $DynNames[$Index]
    }

    Put-U64LE $Bytes 0x148 1      # DT_NEEDED
    Put-U64LE $Bytes 0x150 1      # "libc.so.6"
    Put-U64LE $Bytes 0x158 0      # DT_NULL
    Put-U64LE $Bytes 0x160 0

    Put-U64LE $Bytes 0x168 0x400088
    Put-U64LE $Bytes 0x170 0x100000008
    Put-U64LE $Bytes 0x178 4
    Put-Ascii $Bytes 0x540 "/lib/ld-peelf.so"
    Put-Note $Bytes 0x560 $false
    Put-SysvHash $Bytes 0x580 $false
    Put-GnuHash $Bytes 0x5A0 $false $true

    $Text = 0x180 + 0x40
    Put-U32LE $Bytes ($Text + 0x00) 1      # ".text"
    Put-U32LE $Bytes ($Text + 0x04) 1      # SHT_PROGBITS
    Put-U64LE $Bytes ($Text + 0x08) 6      # SHF_ALLOC | SHF_EXECINSTR
    Put-U64LE $Bytes ($Text + 0x10) 0x400080
    Put-U64LE $Bytes ($Text + 0x18) 0x80
    Put-U64LE $Bytes ($Text + 0x20) 0x10
    Put-U64LE $Bytes ($Text + 0x30) 0x10

    $Strtab = 0x180 + 0x80
    Put-U32LE $Bytes ($Strtab + 0x00) 7    # ".shstrtab"
    Put-U32LE $Bytes ($Strtab + 0x04) 3    # SHT_STRTAB
    Put-U64LE $Bytes ($Strtab + 0x18) 0x90
    Put-U64LE $Bytes ($Strtab + 0x20) ([UInt64]$Names.Length)
    Put-U64LE $Bytes ($Strtab + 0x30) 1

    $StringTable = 0x180 + 0xC0
    Put-U32LE $Bytes ($StringTable + 0x00) 17   # ".strtab"
    Put-U32LE $Bytes ($StringTable + 0x04) 3    # SHT_STRTAB
    Put-U64LE $Bytes ($StringTable + 0x18) 0xF0
    Put-U64LE $Bytes ($StringTable + 0x20) ([UInt64]$SymNames.Length)
    Put-U64LE $Bytes ($StringTable + 0x30) 1

    $Symtab = 0x180 + 0x100
    Put-U32LE $Bytes ($Symtab + 0x00) 25        # ".symtab"
    Put-U32LE $Bytes ($Symtab + 0x04) 2         # SHT_SYMTAB
    Put-U64LE $Bytes ($Symtab + 0x18) 0x100
    Put-U64LE $Bytes ($Symtab + 0x20) 0x30
    Put-U32LE $Bytes ($Symtab + 0x28) 3         # link -> .strtab
    Put-U32LE $Bytes ($Symtab + 0x2C) 1         # one local symbol (null)
    Put-U64LE $Bytes ($Symtab + 0x30) 8
    Put-U64LE $Bytes ($Symtab + 0x38) 0x18

    $Dynstr = 0x180 + 0x140
    Put-U32LE $Bytes ($Dynstr + 0x00) 33        # ".dynstr"
    Put-U32LE $Bytes ($Dynstr + 0x04) 3         # SHT_STRTAB
    Put-U64LE $Bytes ($Dynstr + 0x18) 0x138
    Put-U64LE $Bytes ($Dynstr + 0x20) ([UInt64]$DynNames.Length)
    Put-U64LE $Bytes ($Dynstr + 0x30) 1

    $Dynamic = 0x180 + 0x180
    Put-U32LE $Bytes ($Dynamic + 0x00) 41       # ".dynamic"
    Put-U32LE $Bytes ($Dynamic + 0x04) 6        # SHT_DYNAMIC
    Put-U64LE $Bytes ($Dynamic + 0x08) 2        # SHF_ALLOC
    Put-U64LE $Bytes ($Dynamic + 0x18) 0x148
    Put-U64LE $Bytes ($Dynamic + 0x20) 0x20
    Put-U32LE $Bytes ($Dynamic + 0x28) 5        # link -> .dynstr
    Put-U64LE $Bytes ($Dynamic + 0x30) 8
    Put-U64LE $Bytes ($Dynamic + 0x38) 0x10

    $Rela = 0x180 + 0x1C0
    Put-U32LE $Bytes ($Rela + 0x00) 50          # ".rela.dyn"
    Put-U32LE $Bytes ($Rela + 0x04) 4           # SHT_RELA
    Put-U64LE $Bytes ($Rela + 0x18) 0x168
    Put-U64LE $Bytes ($Rela + 0x20) 0x18
    Put-U32LE $Bytes ($Rela + 0x28) 4           # link -> .symtab
    Put-U32LE $Bytes ($Rela + 0x2C) 1           # info -> .text
    Put-U64LE $Bytes ($Rela + 0x30) 8
    Put-U64LE $Bytes ($Rela + 0x38) 0x18

    $Note = 0x180 + 0x200
    Put-U32LE $Bytes ($Note + 0x00) 60          # ".note.peelf"
    Put-U32LE $Bytes ($Note + 0x04) 7           # SHT_NOTE
    Put-U64LE $Bytes ($Note + 0x18) 0x560
    Put-U64LE $Bytes ($Note + 0x20) 0x18
    Put-U64LE $Bytes ($Note + 0x30) 4

    $Hash = 0x180 + 0x240
    Put-U32LE $Bytes ($Hash + 0x00) 72          # ".hash"
    Put-U32LE $Bytes ($Hash + 0x04) 5           # SHT_HASH
    Put-U64LE $Bytes ($Hash + 0x18) 0x580
    Put-U64LE $Bytes ($Hash + 0x20) 0x14
    Put-U32LE $Bytes ($Hash + 0x28) 4           # link -> .symtab
    Put-U64LE $Bytes ($Hash + 0x30) 4
    Put-U64LE $Bytes ($Hash + 0x38) 4

    $GnuHash = 0x180 + 0x280
    Put-U32LE $Bytes ($GnuHash + 0x00) 78       # ".gnu.hash"
    Put-U32LE $Bytes ($GnuHash + 0x04) 0x6ffffff6
    Put-U64LE $Bytes ($GnuHash + 0x18) 0x5A0
    Put-U64LE $Bytes ($GnuHash + 0x20) 0x20
    Put-U32LE $Bytes ($GnuHash + 0x28) 4        # link -> .symtab
    Put-U64LE $Bytes ($GnuHash + 0x30) 8
    Put-U64LE $Bytes ($GnuHash + 0x38) 0

    [IO.File]::WriteAllBytes((Join-Path $Root $Name), $Bytes)
}

function New-Pe64Fixture {
    param([string]$Name)

    $Bytes = [byte[]]::new(0x700)
    $Bytes[0] = [byte][char]'M'
    $Bytes[1] = [byte][char]'Z'
    Put-U32LE $Bytes 0x3c 0x80

    Put-Ascii $Bytes 0x80 "PE"
    $Coff = [UInt32](0x80 + 4)
    Put-U16LE $Bytes ($Coff + 0) 0x8664
    Put-U16LE $Bytes ($Coff + 2) 4
    Put-U16LE $Bytes ($Coff + 16) 0x00c0
    Put-U16LE $Bytes ($Coff + 18) 0x0022

    $Opt = [UInt32]($Coff + 20)
    Put-U16LE $Bytes ($Opt + 0) 0x020b
    Put-U32LE $Bytes ($Opt + 16) 0x1000
    Put-U64LE $Bytes ($Opt + 24) 0x140000000
    Put-U32LE $Bytes ($Opt + 0x6C) 16
    Put-U32LE $Bytes ($Opt + 0x70) 0x1100
    Put-U32LE $Bytes ($Opt + 0x74) 0x80
    Put-U32LE $Bytes ($Opt + 0x78) 0x1180
    Put-U32LE $Bytes ($Opt + 0x7C) 0x40
    Put-U32LE $Bytes ($Opt + 0x98) 0x2000
    Put-U32LE $Bytes ($Opt + 0x9C) 0x0C
    Put-U32LE $Bytes ($Opt + 0xA0) 0x3000
    Put-U32LE $Bytes ($Opt + 0xA4) 0x1C
    Put-U32LE $Bytes ($Opt + 0xB8) 0x4000
    Put-U32LE $Bytes ($Opt + 0xBC) 0x28

    $Sect = [UInt32]($Opt + 0x00c0)
    Put-Ascii $Bytes $Sect ".text"
    Put-U32LE $Bytes ($Sect + 8) 0x200
    Put-U32LE $Bytes ($Sect + 12) 0x1000
    Put-U32LE $Bytes ($Sect + 16) 0x200
    Put-U32LE $Bytes ($Sect + 20) 0x200
    Put-U32LE $Bytes ($Sect + 36) 0x60000020

    $RelocSect = [UInt32]($Sect + 0x28)
    Put-Ascii $Bytes $RelocSect ".reloc"
    Put-U32LE $Bytes ($RelocSect + 8) 0x0C
    Put-U32LE $Bytes ($RelocSect + 12) 0x2000
    Put-U32LE $Bytes ($RelocSect + 16) 0x200
    Put-U32LE $Bytes ($RelocSect + 20) 0x400
    Put-U32LE $Bytes ($RelocSect + 36) 0x42000040

    $DebugSect = [UInt32]($RelocSect + 0x28)
    Put-Ascii $Bytes $DebugSect ".debug"
    Put-U32LE $Bytes ($DebugSect + 8) 0x80
    Put-U32LE $Bytes ($DebugSect + 12) 0x3000
    Put-U32LE $Bytes ($DebugSect + 16) 0x100
    Put-U32LE $Bytes ($DebugSect + 20) 0x500
    Put-U32LE $Bytes ($DebugSect + 36) 0x42000040

    $TlsSect = [UInt32]($DebugSect + 0x28)
    Put-Ascii $Bytes $TlsSect ".tls"
    Put-U32LE $Bytes ($TlsSect + 8) 0x80
    Put-U32LE $Bytes ($TlsSect + 12) 0x4000
    Put-U32LE $Bytes ($TlsSect + 16) 0x100
    Put-U32LE $Bytes ($TlsSect + 20) 0x600
    Put-U32LE $Bytes ($TlsSect + 36) 3254779968

    for ($Index = [UInt32]0; $Index -lt 0x20; ++$Index) {
        $Bytes[0x200 + $Index] = [byte](0xcc)
    }

    Put-U32LE $Bytes 0x400 0x1000  # Page RVA
    Put-U32LE $Bytes 0x404 0x0C    # Block size
    Put-U16LE $Bytes 0x408 0xA088  # IMAGE_REL_BASED_DIR64 at RVA 0x1088
    Put-U16LE $Bytes 0x40A 0       # IMAGE_REL_BASED_ABSOLUTE padding

    Put-U32LE $Bytes 0x500 0           # Characteristics
    Put-U32LE $Bytes 0x504 0x5E2A5A64  # TimeDateStamp
    Put-U16LE $Bytes 0x508 0           # MajorVersion
    Put-U16LE $Bytes 0x50A 0           # MinorVersion
    Put-U32LE $Bytes 0x50C 2           # IMAGE_DEBUG_TYPE_CODEVIEW
    Put-U32LE $Bytes 0x510 0x2A        # SizeOfData
    Put-U32LE $Bytes 0x514 0x301C      # AddressOfRawData
    Put-U32LE $Bytes 0x518 0x51C       # PointerToRawData
    Put-CodeViewRsds $Bytes 0x51C 2 "known-win-x64.pdb" 0x20

    Put-U64LE $Bytes 0x600 0x140004010 # StartAddressOfRawData
    Put-U64LE $Bytes 0x608 0x140004020 # EndAddressOfRawData
    Put-U64LE $Bytes 0x610 0x140004030 # AddressOfIndex
    Put-U64LE $Bytes 0x618 0x140004040 # AddressOfCallBacks
    Put-U32LE $Bytes 0x620 8           # SizeOfZeroFill
    Put-U32LE $Bytes 0x624 0x00400000  # Characteristics
    Put-U64LE $Bytes 0x640 0x140001088 # TLS callback VA
    Put-U64LE $Bytes 0x648 0

    Put-U32LE $Bytes 0x30C 0x1140  # Name RVA
    Put-U32LE $Bytes 0x310 1       # Base
    Put-U32LE $Bytes 0x314 1       # NumberOfFunctions
    Put-U32LE $Bytes 0x318 1       # NumberOfNames
    Put-U32LE $Bytes 0x31C 0x1150  # AddressOfFunctions
    Put-U32LE $Bytes 0x320 0x1154  # AddressOfNames
    Put-U32LE $Bytes 0x324 0x1158  # AddressOfNameOrdinals
    Put-Ascii $Bytes 0x340 "known-win-x64.exe"
    Put-U32LE $Bytes 0x350 0x1000  # exported function RVA
    Put-U32LE $Bytes 0x354 0x1160  # export name RVA
    Put-U16LE $Bytes 0x358 0       # ordinal index
    Put-Ascii $Bytes 0x360 "known_export"

    Put-U32LE $Bytes 0x380 0x11C0  # OriginalFirstThunk
    Put-U32LE $Bytes 0x38C 0x11A0  # Name
    Put-U32LE $Bytes 0x390 0x11D0  # FirstThunk
    Put-Ascii $Bytes 0x3A0 "KERNEL32.dll"
    Put-U16LE $Bytes 0x3B0 0       # import hint
    Put-Ascii $Bytes 0x3B2 "ExitProcess"
    Put-U64LE $Bytes 0x3C0 0x11B0  # INT
    Put-U64LE $Bytes 0x3C8 0
    Put-U64LE $Bytes 0x3D0 0x11B0  # IAT
    Put-U64LE $Bytes 0x3D8 0

    [IO.File]::WriteAllBytes((Join-Path $Root $Name), $Bytes)
}

function New-Elf32CompatibilityFixture {
    param([string]$Name, [UInt16]$Machine, [bool]$BigEndian)

    $Bytes = [byte[]]::new(0x680)
    $Bytes[0] = 0x7f
    $Bytes[1] = [byte][char]'E'
    $Bytes[2] = [byte][char]'L'
    $Bytes[3] = [byte][char]'F'
    $Bytes[4] = 1
    $Bytes[5] = if ($BigEndian) { 2 } else { 1 }
    $Bytes[6] = 1

    Put-U16 $Bytes 0x10 2 $BigEndian
    Put-U16 $Bytes 0x12 $Machine $BigEndian
    Put-U32 $Bytes 0x14 1 $BigEndian
    Put-U32 $Bytes 0x18 0x400080 $BigEndian
    Put-U32 $Bytes 0x1c 0x480 $BigEndian
    Put-U32 $Bytes 0x20 0x180 $BigEndian
    Put-U16 $Bytes 0x28 0x34 $BigEndian
    Put-U16 $Bytes 0x2a 0x20 $BigEndian
    Put-U16 $Bytes 0x2c 3 $BigEndian
    Put-U16 $Bytes 0x2e 0x28 $BigEndian
    Put-U16 $Bytes 0x30 11 $BigEndian
    Put-U16 $Bytes 0x32 2 $BigEndian

    Put-U32 $Bytes 0x480 1 $BigEndian
    Put-U32 $Bytes 0x484 0x80 $BigEndian
    Put-U32 $Bytes 0x488 0x400080 $BigEndian
    Put-U32 $Bytes 0x48C 0x400080 $BigEndian
    Put-U32 $Bytes 0x490 0x10 $BigEndian
    Put-U32 $Bytes 0x494 0x10 $BigEndian
    Put-U32 $Bytes 0x498 5 $BigEndian
    Put-U32 $Bytes 0x49C 0x1000 $BigEndian

    Put-U32 $Bytes 0x4A0 3 $BigEndian
    Put-U32 $Bytes 0x4A4 0x540 $BigEndian
    Put-U32 $Bytes 0x4A8 0x400540 $BigEndian
    Put-U32 $Bytes 0x4AC 0x400540 $BigEndian
    Put-U32 $Bytes 0x4B0 0x11 $BigEndian
    Put-U32 $Bytes 0x4B4 0x11 $BigEndian
    Put-U32 $Bytes 0x4B8 4 $BigEndian
    Put-U32 $Bytes 0x4BC 1 $BigEndian

    Put-U32 $Bytes 0x4C0 4 $BigEndian
    Put-U32 $Bytes 0x4C4 0x560 $BigEndian
    Put-U32 $Bytes 0x4C8 0x400560 $BigEndian
    Put-U32 $Bytes 0x4CC 0x400560 $BigEndian
    Put-U32 $Bytes 0x4D0 0x18 $BigEndian
    Put-U32 $Bytes 0x4D4 0x18 $BigEndian
    Put-U32 $Bytes 0x4D8 4 $BigEndian
    Put-U32 $Bytes 0x4DC 4 $BigEndian

    for ($Index = [UInt32]0; $Index -lt 16; ++$Index) {
        $Bytes[0x80 + $Index] = [byte](0x90 + ($Index % 16))
    }

    $Names = [Text.Encoding]::ASCII.GetBytes("`0.text`0.shstrtab`0.strtab`0.symtab`0.dynstr`0.dynamic`0.rel.dyn`0.note.peelf`0.hash`0.gnu.hash`0")
    for ($Index = [UInt32]0; $Index -lt $Names.Length; ++$Index) {
        $Bytes[0x90 + $Index] = $Names[$Index]
    }

    $SymNames = [byte[]](0, 95, 115, 116, 97, 114, 116, 0)
    for ($Index = [UInt32]0; $Index -lt $SymNames.Length; ++$Index) {
        $Bytes[0xF0 + $Index] = $SymNames[$Index]
    }

    $DynNames = [byte[]](0, 108, 105, 98, 99, 46, 115, 111, 46, 54, 0)
    for ($Index = [UInt32]0; $Index -lt $DynNames.Length; ++$Index) {
        $Bytes[0x138 + $Index] = $DynNames[$Index]
    }

    Put-U32 $Bytes 0x148 1 $BigEndian
    Put-U32 $Bytes 0x14C 1 $BigEndian
    Put-U32 $Bytes 0x150 0 $BigEndian
    Put-U32 $Bytes 0x154 0 $BigEndian
    Put-U32 $Bytes 0x158 0x400084 $BigEndian
    Put-U32 $Bytes 0x15C 0x101 $BigEndian
    Put-Ascii $Bytes 0x540 "/lib/ld-peelf.so"
    Put-Note $Bytes 0x560 $BigEndian
    Put-SysvHash $Bytes 0x580 $BigEndian
    Put-GnuHash $Bytes 0x5A0 $BigEndian $false

    $StartSym = [UInt32](0x100 + 0x10)
    Put-U32 $Bytes ($StartSym + 0x00) 1 $BigEndian
    Put-U32 $Bytes ($StartSym + 0x04) 0x400080 $BigEndian
    Put-U32 $Bytes ($StartSym + 0x08) 0x10 $BigEndian
    $Bytes[$StartSym + 0x0C] = 0x12
    $Bytes[$StartSym + 0x0D] = 0
    Put-U16 $Bytes ($StartSym + 0x0E) 1 $BigEndian

    $Text = 0x180 + 0x28
    Put-U32 $Bytes ($Text + 0x00) 1 $BigEndian
    Put-U32 $Bytes ($Text + 0x04) 1 $BigEndian
    Put-U32 $Bytes ($Text + 0x08) 6 $BigEndian
    Put-U32 $Bytes ($Text + 0x0c) 0x400080 $BigEndian
    Put-U32 $Bytes ($Text + 0x10) 0x80 $BigEndian
    Put-U32 $Bytes ($Text + 0x14) 0x10 $BigEndian
    Put-U32 $Bytes ($Text + 0x20) 0x10 $BigEndian

    $Shstr = 0x180 + 0x50
    Put-U32 $Bytes ($Shstr + 0x00) 7 $BigEndian
    Put-U32 $Bytes ($Shstr + 0x04) 3 $BigEndian
    Put-U32 $Bytes ($Shstr + 0x10) 0x90 $BigEndian
    Put-U32 $Bytes ($Shstr + 0x14) ([UInt32]$Names.Length) $BigEndian
    Put-U32 $Bytes ($Shstr + 0x20) 1 $BigEndian

    $StringTable = 0x180 + 0x78
    Put-U32 $Bytes ($StringTable + 0x00) 17 $BigEndian
    Put-U32 $Bytes ($StringTable + 0x04) 3 $BigEndian
    Put-U32 $Bytes ($StringTable + 0x10) 0xF0 $BigEndian
    Put-U32 $Bytes ($StringTable + 0x14) ([UInt32]$SymNames.Length) $BigEndian
    Put-U32 $Bytes ($StringTable + 0x20) 1 $BigEndian

    $Symtab = 0x180 + 0xA0
    Put-U32 $Bytes ($Symtab + 0x00) 25 $BigEndian
    Put-U32 $Bytes ($Symtab + 0x04) 2 $BigEndian
    Put-U32 $Bytes ($Symtab + 0x10) 0x100 $BigEndian
    Put-U32 $Bytes ($Symtab + 0x14) 0x20 $BigEndian
    Put-U32 $Bytes ($Symtab + 0x18) 3 $BigEndian
    Put-U32 $Bytes ($Symtab + 0x1C) 1 $BigEndian
    Put-U32 $Bytes ($Symtab + 0x20) 4 $BigEndian
    Put-U32 $Bytes ($Symtab + 0x24) 0x10 $BigEndian

    $Dynstr = 0x180 + 0xC8
    Put-U32 $Bytes ($Dynstr + 0x00) 33 $BigEndian
    Put-U32 $Bytes ($Dynstr + 0x04) 3 $BigEndian
    Put-U32 $Bytes ($Dynstr + 0x10) 0x138 $BigEndian
    Put-U32 $Bytes ($Dynstr + 0x14) ([UInt32]$DynNames.Length) $BigEndian
    Put-U32 $Bytes ($Dynstr + 0x20) 1 $BigEndian

    $Dynamic = 0x180 + 0xF0
    Put-U32 $Bytes ($Dynamic + 0x00) 41 $BigEndian
    Put-U32 $Bytes ($Dynamic + 0x04) 6 $BigEndian
    Put-U32 $Bytes ($Dynamic + 0x08) 2 $BigEndian
    Put-U32 $Bytes ($Dynamic + 0x10) 0x148 $BigEndian
    Put-U32 $Bytes ($Dynamic + 0x14) 0x10 $BigEndian
    Put-U32 $Bytes ($Dynamic + 0x18) 5 $BigEndian
    Put-U32 $Bytes ($Dynamic + 0x20) 4 $BigEndian
    Put-U32 $Bytes ($Dynamic + 0x24) 0x08 $BigEndian

    $Rel = 0x180 + 0x118
    Put-U32 $Bytes ($Rel + 0x00) 50 $BigEndian
    Put-U32 $Bytes ($Rel + 0x04) 9 $BigEndian
    Put-U32 $Bytes ($Rel + 0x10) 0x158 $BigEndian
    Put-U32 $Bytes ($Rel + 0x14) 0x08 $BigEndian
    Put-U32 $Bytes ($Rel + 0x18) 4 $BigEndian
    Put-U32 $Bytes ($Rel + 0x1C) 1 $BigEndian
    Put-U32 $Bytes ($Rel + 0x20) 4 $BigEndian
    Put-U32 $Bytes ($Rel + 0x24) 0x08 $BigEndian

    $Note = 0x180 + 0x140
    Put-U32 $Bytes ($Note + 0x00) 59 $BigEndian
    Put-U32 $Bytes ($Note + 0x04) 7 $BigEndian
    Put-U32 $Bytes ($Note + 0x10) 0x560 $BigEndian
    Put-U32 $Bytes ($Note + 0x14) 0x18 $BigEndian
    Put-U32 $Bytes ($Note + 0x20) 4 $BigEndian

    $Hash = 0x180 + 0x168
    Put-U32 $Bytes ($Hash + 0x00) 71 $BigEndian
    Put-U32 $Bytes ($Hash + 0x04) 5 $BigEndian
    Put-U32 $Bytes ($Hash + 0x10) 0x580 $BigEndian
    Put-U32 $Bytes ($Hash + 0x14) 0x14 $BigEndian
    Put-U32 $Bytes ($Hash + 0x18) 4 $BigEndian
    Put-U32 $Bytes ($Hash + 0x20) 4 $BigEndian
    Put-U32 $Bytes ($Hash + 0x24) 4 $BigEndian

    $GnuHash = 0x180 + 0x190
    Put-U32 $Bytes ($GnuHash + 0x00) 77 $BigEndian
    Put-U32 $Bytes ($GnuHash + 0x04) 0x6ffffff6 $BigEndian
    Put-U32 $Bytes ($GnuHash + 0x10) 0x5A0 $BigEndian
    Put-U32 $Bytes ($GnuHash + 0x14) 0x1C $BigEndian
    Put-U32 $Bytes ($GnuHash + 0x18) 4 $BigEndian
    Put-U32 $Bytes ($GnuHash + 0x20) 4 $BigEndian
    Put-U32 $Bytes ($GnuHash + 0x24) 0 $BigEndian

    [IO.File]::WriteAllBytes((Join-Path $Root $Name), $Bytes)
}

function New-Elf64CompatibilityFixture {
    param([string]$Name, [UInt16]$Machine, [bool]$BigEndian)

    $Bytes = [byte[]]::new(0x680)
    $Bytes[0] = 0x7f
    $Bytes[1] = [byte][char]'E'
    $Bytes[2] = [byte][char]'L'
    $Bytes[3] = [byte][char]'F'
    $Bytes[4] = 2
    $Bytes[5] = if ($BigEndian) { 2 } else { 1 }
    $Bytes[6] = 1

    Put-U16 $Bytes 0x10 2 $BigEndian
    Put-U16 $Bytes 0x12 $Machine $BigEndian
    Put-U32 $Bytes 0x14 1 $BigEndian
    Put-U64 $Bytes 0x18 0x400080 $BigEndian
    Put-U64 $Bytes 0x20 0x480 $BigEndian
    Put-U64 $Bytes 0x28 0x180 $BigEndian
    Put-U16 $Bytes 0x34 0x40 $BigEndian
    Put-U16 $Bytes 0x36 0x38 $BigEndian
    Put-U16 $Bytes 0x38 3 $BigEndian
    Put-U16 $Bytes 0x3a 0x40 $BigEndian
    Put-U16 $Bytes 0x3c 11 $BigEndian
    Put-U16 $Bytes 0x3e 2 $BigEndian

    Put-U32 $Bytes 0x480 1 $BigEndian
    Put-U32 $Bytes 0x484 5 $BigEndian
    Put-U64 $Bytes 0x488 0x80 $BigEndian
    Put-U64 $Bytes 0x490 0x400080 $BigEndian
    Put-U64 $Bytes 0x498 0x400080 $BigEndian
    Put-U64 $Bytes 0x4A0 0x10 $BigEndian
    Put-U64 $Bytes 0x4A8 0x10 $BigEndian
    Put-U64 $Bytes 0x4B0 0x1000 $BigEndian

    Put-U32 $Bytes 0x4B8 3 $BigEndian
    Put-U32 $Bytes 0x4BC 4 $BigEndian
    Put-U64 $Bytes 0x4C0 0x540 $BigEndian
    Put-U64 $Bytes 0x4C8 0x400540 $BigEndian
    Put-U64 $Bytes 0x4D0 0x400540 $BigEndian
    Put-U64 $Bytes 0x4D8 0x11 $BigEndian
    Put-U64 $Bytes 0x4E0 0x11 $BigEndian
    Put-U64 $Bytes 0x4E8 1 $BigEndian

    Put-U32 $Bytes 0x4F0 4 $BigEndian
    Put-U32 $Bytes 0x4F4 4 $BigEndian
    Put-U64 $Bytes 0x4F8 0x560 $BigEndian
    Put-U64 $Bytes 0x500 0x400560 $BigEndian
    Put-U64 $Bytes 0x508 0x400560 $BigEndian
    Put-U64 $Bytes 0x510 0x18 $BigEndian
    Put-U64 $Bytes 0x518 0x18 $BigEndian
    Put-U64 $Bytes 0x520 4 $BigEndian

    for ($Index = [UInt32]0; $Index -lt 16; ++$Index) {
        $Bytes[0x80 + $Index] = [byte](0x90 + ($Index % 16))
    }

    $Names = [Text.Encoding]::ASCII.GetBytes("`0.text`0.shstrtab`0.strtab`0.symtab`0.dynstr`0.dynamic`0.rela.dyn`0.note.peelf`0.hash`0.gnu.hash`0")
    for ($Index = [UInt32]0; $Index -lt $Names.Length; ++$Index) {
        $Bytes[0x90 + $Index] = $Names[$Index]
    }

    $SymNames = [byte[]](0, 95, 115, 116, 97, 114, 116, 0)
    for ($Index = [UInt32]0; $Index -lt $SymNames.Length; ++$Index) {
        $Bytes[0xF0 + $Index] = $SymNames[$Index]
    }

    $DynNames = [byte[]](0, 108, 105, 98, 99, 46, 115, 111, 46, 54, 0)
    for ($Index = [UInt32]0; $Index -lt $DynNames.Length; ++$Index) {
        $Bytes[0x138 + $Index] = $DynNames[$Index]
    }

    Put-U64 $Bytes 0x148 1 $BigEndian
    Put-U64 $Bytes 0x150 1 $BigEndian
    Put-U64 $Bytes 0x158 0 $BigEndian
    Put-U64 $Bytes 0x160 0 $BigEndian
    Put-U64 $Bytes 0x168 0x400088 $BigEndian
    Put-U64 $Bytes 0x170 0x100000008 $BigEndian
    Put-U64 $Bytes 0x178 4 $BigEndian
    Put-Ascii $Bytes 0x540 "/lib/ld-peelf.so"
    Put-Note $Bytes 0x560 $BigEndian
    Put-SysvHash $Bytes 0x580 $BigEndian
    Put-GnuHash $Bytes 0x5A0 $BigEndian $true

    $StartSym = [UInt32](0x100 + 0x18)
    Put-U32 $Bytes ($StartSym + 0x00) 1 $BigEndian
    $Bytes[$StartSym + 0x04] = 0x12
    $Bytes[$StartSym + 0x05] = 0
    Put-U16 $Bytes ($StartSym + 0x06) 1 $BigEndian
    Put-U64 $Bytes ($StartSym + 0x08) 0x400080 $BigEndian
    Put-U64 $Bytes ($StartSym + 0x10) 0x10 $BigEndian

    $Text = 0x180 + 0x40
    Put-U32 $Bytes ($Text + 0x00) 1 $BigEndian
    Put-U32 $Bytes ($Text + 0x04) 1 $BigEndian
    Put-U64 $Bytes ($Text + 0x08) 6 $BigEndian
    Put-U64 $Bytes ($Text + 0x10) 0x400080 $BigEndian
    Put-U64 $Bytes ($Text + 0x18) 0x80 $BigEndian
    Put-U64 $Bytes ($Text + 0x20) 0x10 $BigEndian
    Put-U64 $Bytes ($Text + 0x30) 0x10 $BigEndian

    $Shstr = 0x180 + 0x80
    Put-U32 $Bytes ($Shstr + 0x00) 7 $BigEndian
    Put-U32 $Bytes ($Shstr + 0x04) 3 $BigEndian
    Put-U64 $Bytes ($Shstr + 0x18) 0x90 $BigEndian
    Put-U64 $Bytes ($Shstr + 0x20) ([UInt64]$Names.Length) $BigEndian
    Put-U64 $Bytes ($Shstr + 0x30) 1 $BigEndian

    $StringTable = 0x180 + 0xC0
    Put-U32 $Bytes ($StringTable + 0x00) 17 $BigEndian
    Put-U32 $Bytes ($StringTable + 0x04) 3 $BigEndian
    Put-U64 $Bytes ($StringTable + 0x18) 0xF0 $BigEndian
    Put-U64 $Bytes ($StringTable + 0x20) ([UInt64]$SymNames.Length) $BigEndian
    Put-U64 $Bytes ($StringTable + 0x30) 1 $BigEndian

    $Symtab = 0x180 + 0x100
    Put-U32 $Bytes ($Symtab + 0x00) 25 $BigEndian
    Put-U32 $Bytes ($Symtab + 0x04) 2 $BigEndian
    Put-U64 $Bytes ($Symtab + 0x18) 0x100 $BigEndian
    Put-U64 $Bytes ($Symtab + 0x20) 0x30 $BigEndian
    Put-U32 $Bytes ($Symtab + 0x28) 3 $BigEndian
    Put-U32 $Bytes ($Symtab + 0x2C) 1 $BigEndian
    Put-U64 $Bytes ($Symtab + 0x30) 8 $BigEndian
    Put-U64 $Bytes ($Symtab + 0x38) 0x18 $BigEndian

    $Dynstr = 0x180 + 0x140
    Put-U32 $Bytes ($Dynstr + 0x00) 33 $BigEndian
    Put-U32 $Bytes ($Dynstr + 0x04) 3 $BigEndian
    Put-U64 $Bytes ($Dynstr + 0x18) 0x138 $BigEndian
    Put-U64 $Bytes ($Dynstr + 0x20) ([UInt64]$DynNames.Length) $BigEndian
    Put-U64 $Bytes ($Dynstr + 0x30) 1 $BigEndian

    $Dynamic = 0x180 + 0x180
    Put-U32 $Bytes ($Dynamic + 0x00) 41 $BigEndian
    Put-U32 $Bytes ($Dynamic + 0x04) 6 $BigEndian
    Put-U64 $Bytes ($Dynamic + 0x08) 2 $BigEndian
    Put-U64 $Bytes ($Dynamic + 0x18) 0x148 $BigEndian
    Put-U64 $Bytes ($Dynamic + 0x20) 0x20 $BigEndian
    Put-U32 $Bytes ($Dynamic + 0x28) 5 $BigEndian
    Put-U64 $Bytes ($Dynamic + 0x30) 8 $BigEndian
    Put-U64 $Bytes ($Dynamic + 0x38) 0x10 $BigEndian

    $Rela = 0x180 + 0x1C0
    Put-U32 $Bytes ($Rela + 0x00) 50 $BigEndian
    Put-U32 $Bytes ($Rela + 0x04) 4 $BigEndian
    Put-U64 $Bytes ($Rela + 0x18) 0x168 $BigEndian
    Put-U64 $Bytes ($Rela + 0x20) 0x18 $BigEndian
    Put-U32 $Bytes ($Rela + 0x28) 4 $BigEndian
    Put-U32 $Bytes ($Rela + 0x2C) 1 $BigEndian
    Put-U64 $Bytes ($Rela + 0x30) 8 $BigEndian
    Put-U64 $Bytes ($Rela + 0x38) 0x18 $BigEndian

    $Note = 0x180 + 0x200
    Put-U32 $Bytes ($Note + 0x00) 60 $BigEndian
    Put-U32 $Bytes ($Note + 0x04) 7 $BigEndian
    Put-U64 $Bytes ($Note + 0x18) 0x560 $BigEndian
    Put-U64 $Bytes ($Note + 0x20) 0x18 $BigEndian
    Put-U64 $Bytes ($Note + 0x30) 4 $BigEndian

    $Hash = 0x180 + 0x240
    Put-U32 $Bytes ($Hash + 0x00) 72 $BigEndian
    Put-U32 $Bytes ($Hash + 0x04) 5 $BigEndian
    Put-U64 $Bytes ($Hash + 0x18) 0x580 $BigEndian
    Put-U64 $Bytes ($Hash + 0x20) 0x14 $BigEndian
    Put-U32 $Bytes ($Hash + 0x28) 4 $BigEndian
    Put-U64 $Bytes ($Hash + 0x30) 4 $BigEndian
    Put-U64 $Bytes ($Hash + 0x38) 4 $BigEndian

    $GnuHash = 0x180 + 0x280
    Put-U32 $Bytes ($GnuHash + 0x00) 78 $BigEndian
    Put-U32 $Bytes ($GnuHash + 0x04) 0x6ffffff6 $BigEndian
    Put-U64 $Bytes ($GnuHash + 0x18) 0x5A0 $BigEndian
    Put-U64 $Bytes ($GnuHash + 0x20) 0x20 $BigEndian
    Put-U32 $Bytes ($GnuHash + 0x28) 4 $BigEndian
    Put-U64 $Bytes ($GnuHash + 0x30) 8 $BigEndian
    Put-U64 $Bytes ($GnuHash + 0x38) 0 $BigEndian

    [IO.File]::WriteAllBytes((Join-Path $Root $Name), $Bytes)
}

function New-Pe32Fixture {
    param([string]$Name)

    $Bytes = [byte[]]::new(0x600)
    $Bytes[0] = [byte][char]'M'
    $Bytes[1] = [byte][char]'Z'
    Put-U32LE $Bytes 0x3c 0x80

    Put-Ascii $Bytes 0x80 "PE"
    $Coff = [UInt32](0x80 + 4)
    Put-U16LE $Bytes ($Coff + 0) 0x014c
    Put-U16LE $Bytes ($Coff + 2) 4
    Put-U16LE $Bytes ($Coff + 16) 0x00b0
    Put-U16LE $Bytes ($Coff + 18) 0x0102

    $Opt = [UInt32]($Coff + 20)
    Put-U16LE $Bytes ($Opt + 0) 0x010b
    Put-U32LE $Bytes ($Opt + 16) 0x1000
    Put-U32LE $Bytes ($Opt + 28) 0x00400000
    Put-U32LE $Bytes ($Opt + 0x5C) 16
    Put-U32LE $Bytes ($Opt + 0x88) 0x2000
    Put-U32LE $Bytes ($Opt + 0x8C) 0x0C
    Put-U32LE $Bytes ($Opt + 0x90) 0x3000
    Put-U32LE $Bytes ($Opt + 0x94) 0x1C
    Put-U32LE $Bytes ($Opt + 0xA8) 0x4000
    Put-U32LE $Bytes ($Opt + 0xAC) 0x18

    $Sect = [UInt32]($Opt + 0x00b0)
    Put-Ascii $Bytes $Sect ".text"
    Put-U32LE $Bytes ($Sect + 8) 0x100
    Put-U32LE $Bytes ($Sect + 12) 0x1000
    Put-U32LE $Bytes ($Sect + 16) 0x100
    Put-U32LE $Bytes ($Sect + 20) 0x200
    Put-U32LE $Bytes ($Sect + 36) 0x60000020

    $RelocSect = [UInt32]($Sect + 0x28)
    Put-Ascii $Bytes $RelocSect ".reloc"
    Put-U32LE $Bytes ($RelocSect + 8) 0x0C
    Put-U32LE $Bytes ($RelocSect + 12) 0x2000
    Put-U32LE $Bytes ($RelocSect + 16) 0x100
    Put-U32LE $Bytes ($RelocSect + 20) 0x300
    Put-U32LE $Bytes ($RelocSect + 36) 0x42000040

    $DebugSect = [UInt32]($RelocSect + 0x28)
    Put-Ascii $Bytes $DebugSect ".debug"
    Put-U32LE $Bytes ($DebugSect + 8) 0x80
    Put-U32LE $Bytes ($DebugSect + 12) 0x3000
    Put-U32LE $Bytes ($DebugSect + 16) 0x100
    Put-U32LE $Bytes ($DebugSect + 20) 0x400
    Put-U32LE $Bytes ($DebugSect + 36) 0x42000040

    $TlsSect = [UInt32]($DebugSect + 0x28)
    Put-Ascii $Bytes $TlsSect ".tls"
    Put-U32LE $Bytes ($TlsSect + 8) 0x80
    Put-U32LE $Bytes ($TlsSect + 12) 0x4000
    Put-U32LE $Bytes ($TlsSect + 16) 0x100
    Put-U32LE $Bytes ($TlsSect + 20) 0x500
    Put-U32LE $Bytes ($TlsSect + 36) 3254779968

    for ($Index = [UInt32]0; $Index -lt 0x20; ++$Index) {
        $Bytes[0x200 + $Index] = [byte](0xcc)
    }

    Put-U32LE $Bytes 0x300 0x1000  # Page RVA
    Put-U32LE $Bytes 0x304 0x0C    # Block size
    Put-U16LE $Bytes 0x308 0x3010  # IMAGE_REL_BASED_HIGHLOW at RVA 0x1010
    Put-U16LE $Bytes 0x30A 0       # IMAGE_REL_BASED_ABSOLUTE padding

    Put-U32LE $Bytes 0x400 0           # Characteristics
    Put-U32LE $Bytes 0x404 0x5E2A5A32  # TimeDateStamp
    Put-U16LE $Bytes 0x408 0           # MajorVersion
    Put-U16LE $Bytes 0x40A 0           # MinorVersion
    Put-U32LE $Bytes 0x40C 2           # IMAGE_DEBUG_TYPE_CODEVIEW
    Put-U32LE $Bytes 0x410 0x2A        # SizeOfData
    Put-U32LE $Bytes 0x414 0x301C      # AddressOfRawData
    Put-U32LE $Bytes 0x418 0x41C       # PointerToRawData
    Put-CodeViewRsds $Bytes 0x41C 1 "known-win-x86.pdb" 0x10

    Put-U32LE $Bytes 0x500 0x404010 # StartAddressOfRawData
    Put-U32LE $Bytes 0x504 0x404018 # EndAddressOfRawData
    Put-U32LE $Bytes 0x508 0x404020 # AddressOfIndex
    Put-U32LE $Bytes 0x50C 0x404030 # AddressOfCallBacks
    Put-U32LE $Bytes 0x510 4        # SizeOfZeroFill
    Put-U32LE $Bytes 0x514 0x00300000
    Put-U32LE $Bytes 0x530 0x401010 # TLS callback VA
    Put-U32LE $Bytes 0x534 0

    [IO.File]::WriteAllBytes((Join-Path $Root $Name), $Bytes)
}

New-Elf64Fixture "known-linux-x64.elf" 62
New-Elf64Fixture "known-linux-arm64.elf" 183
New-Elf64Fixture "known-linux-riscv64.elf" 243
New-Elf32CompatibilityFixture "known-linux-x86-elf32-le.elf" 3 $false
New-Elf32CompatibilityFixture "known-linux-mips-elf32-be.elf" 8 $true
New-Elf64CompatibilityFixture "known-linux-mips64-elf64-be.elf" 8 $true
New-Elf32CompatibilityFixture "known-linux-arm-elf32-le.elf" 40 $false
New-Elf32CompatibilityFixture "known-linux-arm-elf32-be.elf" 40 $true
New-Elf64CompatibilityFixture "known-linux-arm64-elf64-be.elf" 183 $true
New-Elf32CompatibilityFixture "known-linux-riscv32-elf32-le.elf" 243 $false
New-Elf32CompatibilityFixture "known-linux-riscv32-elf32-be.elf" 243 $true
New-Elf64CompatibilityFixture "known-linux-riscv64-elf64-be.elf" 243 $true
New-Elf32CompatibilityFixture "known-linux-ppc-elf32-be.elf" 20 $true
New-Elf64CompatibilityFixture "known-linux-ppc64-elf64-be.elf" 21 $true
New-Pe32Fixture "known-win-x86.exe"
New-Pe64Fixture "known-win-x64.exe"
