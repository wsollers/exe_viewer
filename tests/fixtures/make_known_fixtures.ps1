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

function Put-Ascii {
    param([byte[]]$Bytes, [UInt32]$Offset, [string]$Text)
    $Data = [Text.Encoding]::ASCII.GetBytes($Text)
    for ($Index = [UInt32]0; $Index -lt $Data.Length; ++$Index) {
        $Bytes[$Offset + $Index] = $Data[$Index]
    }
}

function New-Elf64Fixture {
    param([string]$Name, [UInt16]$Machine)

    $Bytes = [byte[]]::new(0x220)
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
    Put-U64LE $Bytes 0x28 0x100      # e_shoff
    Put-U16LE $Bytes 0x34 0x40       # e_ehsize
    Put-U16LE $Bytes 0x3a 0x40       # e_shentsize
    Put-U16LE $Bytes 0x3c 3          # e_shnum
    Put-U16LE $Bytes 0x3e 2          # e_shstrndx

    for ($Index = [UInt32]0; $Index -lt 16; ++$Index) {
        $Bytes[0x80 + $Index] = [byte](0x90 + ($Index % 16))
    }

    $Names = [byte[]](0, 46, 116, 101, 120, 116, 0, 46, 115, 104, 115, 116, 114, 116, 97, 98, 0)
    for ($Index = [UInt32]0; $Index -lt $Names.Length; ++$Index) {
        $Bytes[0x90 + $Index] = $Names[$Index]
    }

    $Text = 0x100 + 0x40
    Put-U32LE $Bytes ($Text + 0x00) 1      # ".text"
    Put-U32LE $Bytes ($Text + 0x04) 1      # SHT_PROGBITS
    Put-U64LE $Bytes ($Text + 0x08) 6      # SHF_ALLOC | SHF_EXECINSTR
    Put-U64LE $Bytes ($Text + 0x10) 0x400080
    Put-U64LE $Bytes ($Text + 0x18) 0x80
    Put-U64LE $Bytes ($Text + 0x20) 0x10
    Put-U64LE $Bytes ($Text + 0x30) 0x10

    $Strtab = 0x100 + 0x80
    Put-U32LE $Bytes ($Strtab + 0x00) 7    # ".shstrtab"
    Put-U32LE $Bytes ($Strtab + 0x04) 3    # SHT_STRTAB
    Put-U64LE $Bytes ($Strtab + 0x18) 0x90
    Put-U64LE $Bytes ($Strtab + 0x20) ([UInt64]$Names.Length)
    Put-U64LE $Bytes ($Strtab + 0x30) 1

    [IO.File]::WriteAllBytes((Join-Path $Root $Name), $Bytes)
}

function New-Pe64Fixture {
    param([string]$Name)

    $Bytes = [byte[]]::new(0x420)
    $Bytes[0] = [byte][char]'M'
    $Bytes[1] = [byte][char]'Z'
    Put-U32LE $Bytes 0x3c 0x80

    Put-Ascii $Bytes 0x80 "PE"
    $Coff = [UInt32](0x80 + 4)
    Put-U16LE $Bytes ($Coff + 0) 0x8664
    Put-U16LE $Bytes ($Coff + 2) 1
    Put-U16LE $Bytes ($Coff + 16) 0x00f0
    Put-U16LE $Bytes ($Coff + 18) 0x0022

    $Opt = [UInt32]($Coff + 20)
    Put-U16LE $Bytes ($Opt + 0) 0x020b
    Put-U32LE $Bytes ($Opt + 16) 0x1000
    Put-U64LE $Bytes ($Opt + 24) 0x140000000

    $Sect = [UInt32]($Opt + 0x00f0)
    Put-Ascii $Bytes $Sect ".text"
    Put-U32LE $Bytes ($Sect + 8) 0x100
    Put-U32LE $Bytes ($Sect + 12) 0x1000
    Put-U32LE $Bytes ($Sect + 16) 0x20
    Put-U32LE $Bytes ($Sect + 20) 0x200
    Put-U32LE $Bytes ($Sect + 36) 0x60000020
    for ($Index = [UInt32]0; $Index -lt 0x20; ++$Index) {
        $Bytes[0x200 + $Index] = [byte](0xcc)
    }

    [IO.File]::WriteAllBytes((Join-Path $Root $Name), $Bytes)
}

New-Elf64Fixture "known-linux-x64.elf" 62
New-Elf64Fixture "known-linux-arm64.elf" 183
New-Elf64Fixture "known-linux-riscv64.elf" 243
New-Pe64Fixture "known-win-x64.exe"
