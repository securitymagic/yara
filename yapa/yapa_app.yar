rule possible_yapa_app
{
  meta:
    author = "Luke Acha"
    description = "Detects ConvertMate, PDFSkills, PDFusion, and other similar applications. https://blog.lukeacha.com/2025/11/suspicious-converter-obfuscated-strings.html"
    target_entity = "file"
  strings:
    $a = "=c2bs9lbvlGdhxGbhR3cul2X05WZpx2Y" wide
    $b = "==gclN3dvJnYfRWYvxmb39GZ" wide
    $c = "=42bpRXds92clJ3XuVWZyN2c" wide
  condition:
    all of them
}
