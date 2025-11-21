rule suspected_fake_converter_apps
{
  meta:
    author = "Luke Acha"
    description = "https://blog.lukeacha.com/2025/11/suspicious-converter-obfuscated-strings.html"
    target_entity = "file"
  strings:
    $a = "-ep RemoteSigned -File \"" wide
    $b = "c2ltdWxhdGlvbl9zdGF0dXM=" wide
  condition:
    any of them
}
