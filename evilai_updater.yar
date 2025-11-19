rule possible_evilai_updater
{
  meta:
    author = "Luke"
    description = "Detects updater binaries referenced in evilai tasks: ConvertMate: https://blog.lukeacha.com/2025/11/suspicious-converter-obfuscated-strings.html"
    target_entity = "file"

  strings:
    $wide1 = "&user_id=" wide
    $wide2 = ".txt" wide
    $reg   = /17\d{14}/ wide
    $base  = "ZXZlbnRfbmFtZQ==" wide   // literal Base64, wide

  condition:
    $reg and
    filesize < 60KB and
    ( ( $wide1 and $wide2 ) or $base )
}
