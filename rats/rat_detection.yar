/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
import "pe"

rule Multifamily_RAT_Detection
{
   meta:
        author = "Lucas Acha (https://www.lukeacha.com)"
        description = "Generic detection for multiple RAT families, PUPs, packers and suspicious executables. NOTE: This rule may produce false positives. Updated May 2026 to reduce False Positives."

   strings:
      $htt1  = "WScript.Shell" wide
      $htt2  = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
      $htt3  = "\\nuR\\noisreVtnerruC\\swodniW" wide
      $htt4  = "SecurityCenter2" wide
      $htt5  = ":ptth" wide
      $htt6  = ":sptth" wide
      $htt7  = "System.Reflection" ascii
      $htt8  = "ConfuserEx" ascii
      $htt9  = ".NET Framework 4 Client Profile" ascii
      $htt10 = "CreateEncryptor" ascii
      $mzh   = "This program cannot be run in DOS mode"

      // False-positive exclusion strings
      $fp1 = "Microsoft Teams" wide
      $fp2 = "[KeePass]" wide

   condition:
      not any of ($fp*) and
      (
         pe.imphash() == "b8bb385806b89680e13fc0cf24f4431e" or
         pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744"
      ) and
      4 of ($htt*) and
      $mzh
}
