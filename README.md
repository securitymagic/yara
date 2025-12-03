# securitymagic / yara

YARA rules for live and retro hunts, focused on:

- Infostealers (e.g., Jupyter / SolarMarker)
- Malicious document loaders and droppers
- Suspicious PowerShell and script-based threats
- DLL hijacking and custom loaders
- VBS downloaders and other commodity malware
- Fake PDF/File converters
  
These rules are created and maintained by **Luke Acha**.

---

##  Blog write-ups and analysis

Most of these rules are backed by full malware analysis posts on my blog:

 **Malware analysis & YARA write-ups:**  
https://blog.lukeacha.com  

You’ll find posts that walk through:

- How each sample was discovered
- Behavioral analysis (network, persistence, LOLBins, etc.)
- String and pattern selection for the YARA rule
- Hunting tips and example usage

Highlighted Pages:

https://blog.lukeacha.com/2025/11/fake-pdf-converter-hides-dark-secret.html

https://blog.lukeacha.com/2025/10/systemshock-loader-look-at-malware.html

https://blog.lukeacha.com/2025/06/suspicious-recipe-app.html

https://blog.lukeacha.com/2023/10/interesting-customloader-observed-in.html

https://blog.lukeacha.com/2020/12/tracking-jupyter-malware.html

Older posts and legacy content are also mirrored here:

- https://security5magics.blogspot.com

---

##  Repository structure

Each folder groups rules by family or theme:

- `Jupyter Malware/` – Jupyter / SolarMarker–related rules
- `hydraseven/` – HydraSeven loader and related artifacts
- `maldocs/` – Malicious Office docs, loaders, and droppers
- `pws/` – Suspicious PowerShell patterns
- `rats/` – Remote access trojan detections
- `vbs/` – VBS downloaders and script-based threats
- `obfuscation/` – Generic obfuscation / packing indicators
- Standalone `.yar` files – One-off rules for specific campaigns or loaders


