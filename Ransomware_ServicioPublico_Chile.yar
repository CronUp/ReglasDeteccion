rule Ransomware_ServicioPublico_Chile {

   meta:
      description = "Regla Yara para detectar ARCrypt Ransomware (también conocido como Chile Locker)"
      author = "German Fernandez | CronUp - Cyber Threat Intelligence"
      reference = "https://twitter.com/SERNAC/status/1562872175068975105"
      date = "2022-08-26"
      hash = "39b74b2fb057e8c78a2ba6639cf3d58ae91685e6ac13b57b70d2afb158cf742d"

   strings:
      $s1 = "TASKLIST |>NUL FINDSTR /B /L /I /C"
      $s2 = ".\\readme_for_unlock.txt"
      $s3 = "vssadmin delete shadows /All /quiet"
      $s4 = "reg add \"hklm\\SYSTEM\\ControlSet001\\Control\\CommonGlobUserSettings\\Control Panel\\International\""
      $s5 = "/v sShortDate /t REG_SZ /d \"ALL YOUR FILES HAS BEEN ENCRYPTED\""
      $s6 = "\\_ARC\\_WorkSolution\\cryptopp860\\sse_simd.cpp"
      $s7 = "\\_ARC\\Encrypter 2.0.pdb"

   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and 6 of ($s*)

}
