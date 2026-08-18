# SafeBase v5.6.5 – Sicherheitsmodell

## Lokaler App-Tresor: 6-stellige Master-PIN
Seit SafeBase v5.3 ersetzt die App das Master-Passwort des lokalen Passwort-/Notiztresors durch eine **genau 6-stellige numerische PIN**.

1. SafeBase erzeugt einen zufälligen 32-Byte-Datenschlüssel.
2. Aus PIN + zufälligem 32-Byte-Salt wird mit PBKDF2-HMAC-SHA-256 (650.000 Iterationen) ein AES-256-Schlüssel abgeleitet.
3. Dieser Schlüssel verpackt den zufälligen Datenschlüssel mit AES-256-GCM.
4. Der Datenschlüssel verschlüsselt den lokalen Tresor mit AES-256-GCM.
5. Die PIN wird nicht gespeichert.
6. Nach fünf falschen Eingaben blockiert die UI weitere PIN-Versuche für 30 Sekunden.

**Grenze:** 6 Ziffern haben maximal 1.000.000 Kombinationen. Die UI-Sperre verhindert keinen Offline-Brute-Force-Angriff auf eine kopierte Browser-Datenbank. Eine zufällige PIN und aktiviertes TOTP-2FA erhöhen den praktischen Schutz, ersetzen aber nicht die Entropie eines starken Master-Passworts.

## Einmalige Migration von v5.2
Vorhandene lokale v5.2-Metadaten ohne `authMode: pin6` werden nicht direkt mit dem neuen PIN-Login geöffnet. SafeBase verlangt einmalig das bisherige Master-Passwort und zwei Eingaben der neuen PIN. Nach erfolgreicher Entschlüsselung wird nur das Key-Wrapping neu mit der PIN erzeugt; die Tresordaten bleiben AES-256-GCM-verschlüsselt.

## Externe `.safebase`-Tresordatei v3
Neue Tresordateien bleiben **Passkey-only**. Es gibt kein separates Tresordatei-Passwort.

1. SafeBase erzeugt einen zufälligen 32-Byte-PRF-Salt und registriert einen WebAuthn-Credential.
2. Der Authenticator liefert über WebAuthn PRF einen 32-Byte-Geheimwert.
3. Aus PRF-Geheimwert + zufälligem 32-Byte-HKDF-Salt wird per HKDF-SHA-256 ein AES-256-GCM-Schlüssel abgeleitet.
4. Manifest und Nutzdateien werden mit AES-256-GCM und jeweils eigenem 12-Byte-IV authentifiziert verschlüsselt.
5. PRF-Geheimwert und AES-Schlüssel werden nicht in der Tresordatei gespeichert.

## Passkey-only Backup `.safebasebackup`
Neue Backups verwenden dasselbe kryptografische Grundprinzip wie die externe `.safebase`-Datei:

1. SafeBase erzeugt einen zufälligen 32-Byte-PRF-Salt und registriert einen WebAuthn-Credential.
2. WebAuthn PRF liefert einen 32-Byte-Geheimwert, der an genau diesen Credential gebunden ist.
3. PRF-Geheimwert + zufälliger 32-Byte-HKDF-Salt werden mit HKDF-SHA-256 in einen AES-256-GCM-Schlüssel überführt.
4. Der komplette lokale Passwort-/Notiztresor wird mit einem zufälligen 12-Byte-IV und authentifizierten Zusatzdaten verschlüsselt.
5. Weder PRF-Geheimwert noch AES-Schlüssel werden in der Backup-Datei gespeichert.
6. Nach erfolgreicher Passkey-Entschlüsselung wird der importierte Tresor mit einer neu festgelegten 6-stelligen lokalen Master-PIN und einem neuen zufälligen Datenschlüssel im Browser gespeichert.

Alte `.json`-Backups bleiben aus Kompatibilitätsgründen importierbar. Neue Exporte verwenden ausschließlich `.safebasebackup`.

## Sicherheitsgrenzen
- Verlust des einzigen passenden Passkeys/Sicherheitsschlüssels kann bei einer v3 `.safebase`-Datei Datenverlust bedeuten.
- Änderung der Website-Domain/RP-ID kann vorhandene WebAuthn-Credentials unbrauchbar machen.
- Kompromittierter JavaScript-Code kann Daten während einer entsperrten Sitzung lesen.
- Eine 6-stellige PIN ist gegen Offline-Angriffe schwächer als ein langes zufälliges Master-Passwort.
