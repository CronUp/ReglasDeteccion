rule MAL_Warsaw_EDR_killer
{
    meta:
        description = "Detecta binarios que habilitan SeDebugPrivilege, cargan driver dump_diskdumps, manipulan Warsaw_PM y terminan procesos EDR/AV"
        author = "German Fernandez | CronUp - Cyber Threat Intelligence"
        date = "2026-01-01"
        severity = "high"
        reference = "DEVMAN Ransomware en Sector Salud de Chile."

    strings:
        $s1 = "SeDebugPrivilege successfully enabled" ascii
        $s2 = "You Got SeDebugPriv" ascii
        $s3 = "dump_diskdumps.sys" ascii
        $s4 = "Driver Loaded as dump_diskdumps" ascii
        $s5 = "\\\\.\\Warsaw_PM" ascii
        $s6 = "Finished TKO" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            2 of ($s1,$s2,$s3,$s4) and
            $s5 and
            $s6
        )
}
