/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
import "pe"
rule Possible_Emotet_DLL
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed indicators Emotet DLL loaded into memory March 2022"
  strings:
      $htt1 = "MS Shell Dlg" wide
      $mzh = "This program cannot be run in DOS mode"
  condition:
      pe.imphash() == "066d4e2c6288c042d958ddc93cfa07f1" and $htt1 and $mzh
}
