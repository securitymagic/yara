rule Suspected_Fake_RustBased_App
{
  meta:
    author = "Luke Acha"
    description = "Suspected fake application, rust binary, similar to CLOUDHAZE/Zenith Backdoor 7f1db334fd3302cf98dd4afddf6f90e98e2a496fe7e86bf1832b89d02f3d73c3"
    target_entity = "file"
  strings:
    $a = "[%s] release item (%d)" wide
	  $b = "%p, size=%zu)" wide
  condition:
    any of them
}
