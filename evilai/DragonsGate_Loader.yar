rule DragonsGate_SharedConstant_LFSR_Hunt_20261104
{
    meta:
        description = "Suspicious gated Downloader, shared 32-byte constant plus LFSR seed: Updated 2026-11-21"
        author = "Luke Acha: https://github.com/securitymagic/remnux/tree/main/DragonsGateLoader"
        date = "2026-11-20"

    strings:
        $constant_old = {
            0F E7 E7 1C A4 52 75 33
            49 8D A9 D3 D9 9D 0E 43
            7C 7D 25 79 74 20 E0 7D
            FB F5 06 AA 53 CF C3 6D
        }

        $constant_new = {
            36 BF 90 8A 11 86 86 21
            78 DD C6 5D 74 51 E5 49
            55 35 42 FF D1 E4 03 7F
            DA B5 59 D4 CE 73 18 97
        }

        $lfsr_seed = { 00 00 00 95 }

    condition:
        uint16(0) == 0x5A4D and
        $lfsr_seed and
        ($constant_old or $constant_new)
}
