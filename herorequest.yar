import "pe"

rule hero-request
{
  meta:
    author = "Luke Acha"
    description = "Detects strings related to hero/uphero found in trojanized 7zip installer 63396fa92aa010e543e21cd8cb1bcccc"
    target_entity = "file"

  strings:
    $a = "C:\\job\\jump\\passcommon" ascii
    $b = "isharkVPNGuid" wide
    $c = "Services\\UniqueHeroValue" wide
    $d = "Services\\isharkVPNValue" wide
    $e = "youqu_job\\SuperBrowser" ascii nocase

  condition:
    pe.is_pe and
    any of them
}
