rule DotNet_BabelVM_Encoded_Indicator
{
    meta:
        description = "Detects a BabelVM-related Base64 string in .NET samples"
        confidence = "medium"
        classification = "protector indicator, not malware family"

    strings:
        $babel_b64 = "YmFiZWx2bQ==" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        $babel_b64
}
