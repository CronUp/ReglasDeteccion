rule Ransomware_DEVMAN_WindowsLocker
{
    meta:
        description = "DEVMAN ransomware (Windows Locker)"
        author = "German Fernandez | CronUp - Cyber Threat Intelligence"
        date = "2026-01-01"
        malware_family = "DEVMAN"
        severity = "critical"
        reference = "DEVMAN Ransomware en Sector Salud de Chile.

    strings:
        $ext = /\.devman[0-9]{2}/ ascii
        $id_1 = "DEVMAN File Encryption Utility" ascii
        $id_2 = "devman_wallpaper.png" ascii
        $id_3 = "DECRYPT_ME.txt" ascii
        $enc_1 = "Found files to encrypt on drive" ascii
        $enc_2 = "Encryption complete. Files encrypted:" ascii
        $enc_3 = "Successfully encrypted drive:" ascii
        $note_1 = "Set wallpaper with ransom note" ascii
        $note_2 = "Dropped ransom note at:" ascii
        $rust_1 = "src/crypto.rs" ascii
        $anti_1 = "Debugging detected" ascii

    condition:
        uint16(0) == 0x5A4D and
        $ext and
        1 of ($id_*) and
        2 of ($enc_*) and
        1 of ($note_*) and
        (
            1 of ($rust_*) or
            1 of ($anti_*)
        )
}
