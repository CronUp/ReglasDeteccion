rule MSI_Powershell_BatLoader
{
    meta:
        description = "Regla Yara para detectar los archivos MSI con Powershell (BatLoader)"
        author = "German Fernandez | CronUp - Cyber Threat Intelligence"
        reference = "https://twitter.com/1ZRR4H/status/1575364101148114944"
        date = "2022-10-13"
        hash = "08cd62a04c3ed5245f022424e9843d6e420ce6e2431c0fecd7c90a63b2a81c45"

    strings:
        $magic = {D0 CF 11 E0 A1 B1 1A E1} // .MSI
        $s1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65} // powershell.exe
        $s2 = {70 77 73 68 2e 65 78 65} // pwsh.exe
        $s3 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73} // Start-Process
        $m1 = {49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74} // Invoke-WebRequest
        $m2 = {49 6e 76 6f 6b 65 2d 52 65 73 74 4d 65 74 68 6f 64} // Invoke-RestMethod

    condition:
        ($magic at 0) and all of ($s*) and 1 of ($m*)
}
