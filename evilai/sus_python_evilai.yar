rule sus_python_evilai
{
  meta:
    author = "Luke Acha"
    description = "Suspected fake conversion and productivity apps (EvilAI) as Python compiled executables"
    target_entity = "file"
  strings:
    $a = /[a-zA-Z]{15}\sto\screate\schild\sprocess!/ wide
  condition:
    all of them
}
