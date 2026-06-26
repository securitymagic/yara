import "pe"

rule Proxyware_Go_Backconnect_Family
{
    meta:
        description = "Detects old and possible new generations of the backconnect/proxyware DLL family"
        author = "Luke Acha"
        date = "2026-06-26"

    strings:
        // Old campaign
        $old1 = "server/src/cmd/backconnect_dll" ascii

        // New campaign
        $new1 = "*httpproxy.config" ascii
        $new2 = "*http.socksAddr" ascii
        $new3 = "github.com/gogo/protobuf" ascii
        $new4 = "github.com/google/uuid" ascii
        $new5 = "Go buildinf:" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & pe.DLL) and
        (
            $old1 or
            5 of ($new*)
        )
}
