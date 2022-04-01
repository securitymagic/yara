/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
import "pe"
rule suspicious_obfuscated_script_detection
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "Observed strings with suspicious AutoIT scripts"
  strings:
      $a = "NoTrayIcon" ascii
      $b = "Global" ascii
      $c = "StringTrimLeft" ascii
      $d = "StringTrimRight" ascii
      $e = "StringReverse" ascii
  condition:
      all of them and filesize < 3MB
}
