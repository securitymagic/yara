rule DragonsGate_SharedConstant_LFSR_Hunt_20261104
{
    meta:
        description = "Suspicious gated Downloader, shared 32-byte constant plus LFSR seed"
        author = "Luke Acha: https://github.com/securitymagic/remnux/tree/main/DragonsGateLoader"
        date = "2026-11-04"
    strings:
        $constant = { 0F E7 E7 1C A4 52 75 33 49 8D A9 D3 D9 9D 0E 43 7C 7D 25 79 74 20 E0 7D FB F5 06 AA 53 CF C3 6D }
        $lfsr_seed = { 00 00 00 95 }
    condition:
        uint16(0) == 0x5A4D and filesize < 20MB and
        $constant and $lfsr_seed
}
