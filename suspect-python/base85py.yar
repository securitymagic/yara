rule Suspicious_PYC_Base85
{
    meta:
        description = "Detects suspicious Python bytecode containing marshal/zlib/base64 artifacts and a characteristic encoded data marker"
        author = "Luke Acha (@luke92881)"
        date = "2026-06-16"
        version = "1.0"
        reference = "Custom detection based on PureRAT Python bytecode samples"
        tlp = "CLEAR"

    strings:
        // Characteristic encoded blob marker observed near the beginning
        $b85_marker = { 63 24 7C 63 7? 2A 52 75 30 55 }

        // marshal -> zlib -> base64 sequence observed in samples
        $libs = { 6D 61 72 73 68 61 6C DA 04 7A 6C 69 62 DA 06 62 61 73 65 36 34 }

condition:
    filesize < 5MB and
    $b85_marker in (0..256) and
    $libs  in (0..256)
}
