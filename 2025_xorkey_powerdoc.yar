rule 2025_xorkey_powerdoc
{
    meta:
        author = "Luke"
        description = "Detects presence of hardcoded XOR key in EvilAI PowerDoc applications. 06ffbbf87d7feb88bfa548800abacd2b"

    strings:
        $s = "CSIRELSCSIRELS" wide

    condition:
        $s
}
