rule xorkey_powerdoc_2025
{
    meta:
        author = "Luke Acha"
        description = "Detects presence of hardcoded XOR key in EvilAI PowerDoc applications. 06ffbbf87d7feb88bfa548800abacd2b"

    strings:
        $s = "CSIRELSCSIRELS" wide
        $s2 = "ZX8qNsT7bW4vK1pD-y5823401974" wide
    condition:
        any of them
}
