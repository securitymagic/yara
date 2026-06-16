rule Suspicious_PYC_Base85_v2
{
    meta:
        description = "Detects suspicious Python bytecode containing marshal/zlib/base64 artifacts and a characteristic encoded data marker"
        author = "Luke Acha (@luke92881)"
        date = "2026-06-16"
        version = "1.0"
        reference = "Custom detection based on PureRAT Python bytecode samples"
        tlp = "CLEAR"

  strings:
    $a = "marshal" ascii
    $b = "base64" ascii
    $c = "decompress" ascii
    $d = "b85decode" ascii
    $e = "<module>" ascii
    $f = "__import__" ascii

  condition:
    uint16(2) == 0x0a0d and
    all of them
}
