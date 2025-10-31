rule systemshock_loader
{
  meta:
    author = "Luke Acha"
    description = "54d1cde4842fdccc63b9beece056a9b617cbbe106d1cb47dd8d248971bf82bc2"
    target_entity = "file"

  strings:
    $a = /\{[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}/ wide
    $b = "Powered by SmartAssembly" ascii
    $c = "Windows7.0" ascii

  condition:
    filesize >= 30KB and filesize <= 70KB and all of them
}
