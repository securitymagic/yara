import "pe"

rule Redline_Detection
{
   meta:
      author = "Lucas Acha (http://www.lukeacha.com)"
      description = "Observed with Redline Stealer injected DLL"
  strings:
      $htt1 = "System.Reflection.ReflectionContext" wide
      $htt7 = "System.Runtime.Remoting" ascii
      $htt8 = "AesCryptoServiceProvider" ascii
      $htt9 = "DownloadString" ascii
      $htt10 = "CheckRemoteDebuggerPresent" ascii
      $htt6 = "System.IO.Compression" ascii
      $mzh = "This program cannot be run in DOS mode"
      $neg = "rsEngine.Utilities.dll" wide
  condition:
      (pe.imphash() == "dae02f32a21e03ce65412f6e56942daa") and all of ($htt*) and $mzh and filesize > 500KB and not $neg
}
