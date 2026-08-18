# SafeBase v5.6.5 – Security Audit / Änderungsliste

- Anmeldung des lokalen SafeBase-App-Tresors von Master-Passwort auf **genau 6 Ziffern** umgestellt.
- iPhone-Zifferntastatur über `inputmode="numeric"` und 6-Ziffern-Validierung aktiviert.
- PIN wird nicht gespeichert; bestehendes PBKDF2/AES-256-GCM-Key-Wrapping wird weiterverwendet.
- UI-Rate-Limit: nach fünf fehlgeschlagenen PIN-Versuchen 30 Sekunden Sperre.
- Einstellungen und 2FA-Verwaltung verlangen jetzt die Master-PIN statt des Master-Passworts.
- Bestehende v5.2-Installationen erhalten eine einmalige, explizite Migration: altes Master-Passwort → neue 6-stellige PIN.
- Backup-Import erkennt PIN-basierte v5.3-Backups und ältere passwortbasierte Backups.
- `.safebase`-Dateiformat v3 und Passkey-only-Mechanismus bleiben unverändert.
- Service-Worker-Cache auf `v5.3.0-pin6-passkey-only` erhöht.

## Sicherheitsnotiz
Die 6-stellige PIN hat wesentlich weniger Entropie als das vorherige Master-Passwort. Das UI-Rate-Limit hilft nur gegen interaktive Versuche und ist kein vollständiger Schutz gegen Offline-Brute-Force auf kopierte Browserdaten.


## v5.4 UI-Änderung
Das Speicher-Menü wurde neu strukturiert. Die Kryptografie, das `.safebase`-Dateiformat v3, WebAuthn-PRF/HKDF und AES-256-GCM wurden dabei nicht geändert.


## v5.6.5 Stabilitäts- und Sicherheitsfixes

- Neue Backups sind Passkey-only (`.safebasebackup`) mit AES-256-GCM + WebAuthn-PRF + HKDF-SHA-256.
- Neue Backup-Dateien enthalten keine PIN- oder Passwort-abhängige Schlüsselableitung.
- Beim Passkey-Backup-Import wird eine neue lokale 6-stellige Master-PIN gesetzt und der lokale Tresor mit einem neuen zufälligen Datenschlüssel aufgebaut.
- Legacy-`.json`-Backups bleiben importierbar.
- Dialog-Abbrechen unabhängig von HTML-Pflichtfeldvalidierung.
- Backup-Zugangsdaten nur noch über ein eigenes Passwort/PIN-Dialogfeld.
- PIN-Fehlversuchsstatus bleibt bei normalem Reload erhalten.
- File-Picker-Cancel-Recovery für iOS/Safari, damit Auto-Lock wieder aktiv wird.
- Verschlüsselter lokaler Wiederherstellungsentwurf für ungespeicherte `.safebase`-Änderungen.
- Network-first Navigation im Service Worker; Offline-HTML-Fallback nur für Navigation.
- Konsistente Versionskennung v5.6.5.
