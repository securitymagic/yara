rule possible_evilai_updater
{
  meta:
    author = "Luke"
    description = "Detects updater binaries referenced in evilai tasks: ConvertMate"
    target_entity = "file"

  strings:
    $a = "&user_id=" wide
    $b = ".txt" wide
    $c = /\d{16}/ wide

  condition:
    all of them and
    filesize < 60KB
}
