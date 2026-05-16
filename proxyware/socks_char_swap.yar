import "pe"

rule suspect_sxcks_request
{
  meta:
    author = "Luke Acha (blog.lukeacha.com)"
    description = "Detects PE files containing char-swapped sxcks.Request style strings observed in proxyware (GhostSocks) style campaigns"
    target_entity = "file"

  strings:
    // Examples:
    // sxcks.Request
    // s0cks.Request
    // sAcks.Request
    // But NOT legitimate socks.Request
    $a = /s[^oO]cks\.Request/ ascii

  condition:
    uint16(0) == 0x5A4D and
    pe.is_pe and
    $a
}
