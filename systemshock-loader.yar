rule systemshock_loader
{
  meta:
    author = "Luke Acha"
    description = "https://blog.lukeacha.com/2025/10/systemshock-loader-look-at-malware.html"
    target_entity = "file"

  strings:
    $a = /\{[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}/ wide
    $b = "Powered by SmartAssembly" ascii
    $c = "Windows7.0" ascii

  condition:
    filesize >= 30KB and filesize <= 70KB and all of them
}
