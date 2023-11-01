
/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
rule HydraSeven_loader
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "New custom loader observed since September 2023"
        reference = "https://security5magics.blogspot.com/2023/10/interesting-customloader-observed-in.html" 
  strings:
      $mz = "MZ"
      $astring1 = "app.dll" ascii
      $wstring1 = "webView2" wide
      $wstring2 = /https?:\/\/.{1,25}\/main/ wide
  condition:
    $astring1 and $wstring1 and $wstring2 and $mz at 0 and filesize<1MB
}
