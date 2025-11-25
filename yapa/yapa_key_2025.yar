rule yapa_key_2025
{
  meta:
    author = "Luke Acha"
    description = "Looks at wide string pattern for 2025 observed YAPA .NET loader: https://blog.lukeacha.com/2025/11/primepdfconvert-yapa-yet-another-pdf.html"
    target_entity = "file"
  strings:
    $a = /\wzU.\dwMDA./ wide

  condition:
    all of them
}
