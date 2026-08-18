# SafeBase v5.6.5 – Sicherheit und Stabilität

SafeBase verwendet für die **Anmeldung am lokalen App-Tresor eine 6-stellige Zahlen-PIN**. Neue externe `.safebase`-Tresordateien bleiben **Passkey-only** und benötigen weiterhin kein eigenes Dateipasswort.



## Neu in v5.6.5 – Handy, PC und Mac

- Backup-Ablauf jetzt als klarer 2-Schritt-Prozess: **Passkey erstellen → verschlüsselte Datei speichern**.
- Nach der Passkey-Erstellung öffnet automatisch ein eigenes Speicherfenster.
- **iPhone/iPad/Android:** bevorzugt das native Teilen-Menü zum Sichern in Dateien/Downloads/Cloud-Speicher.
- **Windows/macOS/Linux:** nutzt, wenn vorhanden, „Speichern unter“; sonst einen normalen Browser-Download.
- Zusätzlicher **Direkter Download** als plattformübergreifender Fallback.
- Die verschlüsselte Datei kann erneut gespeichert werden, ohne einen zweiten Passkey zu erzeugen, solange SafeBase entsperrt bleibt.

## Bereits enthalten aus v5.6.4

- **macOS/Safari Backup-Fix:** Nach der Passkey-Erstellung wird die verschlüsselte `.safebasebackup`-Datei nicht mehr automatisch gestartet. Stattdessen erscheint ein eigener „Verschlüsselte Datei jetzt speichern“-Button. Dadurch bleibt der Speichervorgang an einen direkten Benutzer-Klick gebunden und Safari blockiert den Download nicht.
- **Zwei klar getrennte Schritte:** 1) Passkey erstellen, 2) verschlüsselte Datei speichern. Die Datei kann danach erneut gespeichert werden, ohne einen neuen Passkey zu erzeugen.


- **Backup-Paar:** Jedes neue Backup erzeugt einen neuen Passkey und eine dazugehörige AES-256-GCM-verschlüsselte `.safebasebackup`-Datei mit identischem Namen.
- **Abbruchsicherung:** Wird das Speichern der Datei abgebrochen, kann dieselbe bereits verschlüsselte Datei erneut gespeichert werden, ohne einen weiteren Passkey zu erzeugen.
- **Klare Trennung:** Der Passkey-Privatschlüssel wird nie exportiert oder in die Backup-Datei geschrieben.
- **Passkey-only Backup:** Neue Backups werden als `.safebasebackup` mit AES-256-GCM verschlüsselt. Der Schlüssel wird wie beim Datei-/Foto-Tresor aus WebAuthn-PRF + HKDF-SHA-256 abgeleitet; es gibt kein Backup-Passwort und keine Backup-PIN mehr.
- **Backup-Passkey-Name:** Vor dem Export erhält der Passkey denselben Namen wie die Backup-Datei, damit die Zuordnung eindeutig bleibt.
- **Passkey-Wiederherstellung:** Beim Import eines neuen Backups wird zuerst der passende Passkey/Sicherheitsschlüssel bestätigt. Danach wird eine neue 6-stellige lokale Master-PIN für den wiederhergestellten Browser-Tresor festgelegt.
- **Legacy-Kompatibilität:** Ältere `.json`-Backups können weiterhin mit ihrer bisherigen PIN bzw. ihrem bisherigen Master-Passwort importiert werden.
- **Abbrechen-Buttons:** Dialoge schließen zuverlässig, auch wenn Pflichtfelder leer sind.
- **Versionsanzeige:** Oberfläche, PWA-Manifest und Cache verwenden konsistent v5.6.5.
- **Service Worker:** Seitennavigation ist network-first; der Offline-Fallback wird nur für HTML-Navigation verwendet. Dadurch werden GitHub-Updates schneller sichtbar und JS/CSS erhalten nie versehentlich HTML als Fallback.
- **Dateiauswahl:** Abgebrochene iPhone-Dateiauswahlen setzen den Picker-Status wieder korrekt zurück, damit die Auto-Sperre nicht hängen bleibt.
- **Wiederherstellungsentwurf:** Ungespeicherte Änderungen an einer `.safebase`-Datei werden zusätzlich als verschlüsselter lokaler Entwurf in IndexedDB gesichert. Nach erneutem Entsperren kann der Entwurf wieder geöffnet oder verworfen werden.
- **PIN-Sperre:** Fehlversuche und die 30-Sekunden-Sperre bleiben über ein normales Neuladen der WebApp erhalten.
- **iPhone-Share:** Nach dem Teilen einer Tresordatei bleibt der Status vorsichtshalber „ungespeichert“, weil die WebApp nicht prüfen kann, ob tatsächlich „In Dateien sichern“ gewählt wurde.

## Neu in v5.6
- Der bisherige technische Hinweis im Speicher-Menü wurde durch einen klaren gelben Sicherheitsbereich ersetzt.
- **Wichtiger Sicherheitshinweis:** Der Nutzer wird deutlich darauf hingewiesen, den Passkey/Sicherheitsschlüssel sicher aufzubewahren.
- **Regelmäßig sichern:** SafeBase erinnert direkt an eine zusätzliche Sicherung der `.safebase`-Datei, z. B. auf USB-Stick oder externer Festplatte.
- Die gelben Hinweise erscheinen im **Speicher-Menü**, im Bereich **Sicherheit** und beim **Backup**.
- Kryptografie, Passkey-only-Tresorformat und bestehende v5.5-Funktionen bleiben unverändert.

## Neu in v5.5
- Vor jeder neuen Tresorgenerierung vergibst du einen gemeinsamen Namen für **Passkey und Tresordatei**.
- Beispiel: Passkey `SafeBase-Privat` → Datei `SafeBase-Privat.safebase`.
- SafeBase setzt bei WebAuthn sowohl `user.name` als auch `user.displayName` auf diesen Namen.
- Der Name wird zusätzlich als nicht-geheimes Label im `.safebase`-Header gespeichert und im Speicher-Menü angezeigt.
- Ungültige Dateinamenzeichen werden automatisch ersetzt.

## Bereits enthalten aus v5.4
- Neu gestaltetes, kompaktes **Speicher-Menü** für `.safebase`-Tresordateien.
- Saubere Dateiliste mit gekürzten langen Namen, Typ, Größe und Datum.
- Suche, Filter **Alle / Fotos / Dokumente** und Sortierung nach **Neueste / Name / Größe**.
- Drei-Punkte-Menü pro Datei: Öffnen/Vorschau, entschlüsselt exportieren, umbenennen, Informationen und löschen.
- Sicherheits- und Verschlüsselungslogik des Passkey-only Tresors bleibt unverändert.

## Anmeldung
- Beim ersten Einrichten wählst du genau **6 Ziffern**.
- Beim späteren Öffnen erscheint nur das PIN-Feld mit der Zifferntastatur.
- Nach 5 falschen Versuchen sperrt die Oberfläche weitere PIN-Versuche für 30 Sekunden.
- Die PIN kann unter **Einstellungen → Sicherheit → Master-PIN ändern** geändert werden.
- Optional kann danach weiterhin ein zusätzlicher 6-stelliger TOTP-Code aus einer Authenticator-App verlangt werden.

## Upgrade von SafeBase v5.2
Wenn im Browser bereits ein v5.2-Tresor mit Master-Passwort vorhanden ist, erscheint **einmalig** die Seite „Auf 6-stellige PIN umstellen“:
1. bisheriges Master-Passwort eingeben,
2. neue 6-stellige PIN eingeben,
3. PIN bestätigen.

Danach wird der lokale Tresorschlüssel mit der neuen PIN neu verpackt. Bei künftigen Anmeldungen wird das alte Master-Passwort nicht mehr abgefragt.

## iPhone-Ablauf für `.safebase`
1. SafeBase über HTTPS öffnen und mit der 6-stelligen PIN entsperren.
2. **Dateien → Neue Tresordatei**.
3. Einen Namen eingeben, z. B. `SafeBase-Privat`. Dieser wird zugleich Passkey-Name und Dateiname `SafeBase-Privat.safebase`.
4. Den iPhone-Dialog für den Passkey/Sicherheitsschlüssel bestätigen. Bei einem NFC-Sicherheitsschlüssel den Schlüssel nach Aufforderung ans iPhone halten.
5. **+ Fotos / Dateien** wählen.
6. **In Dateien sichern** und z. B. **Auf meinem iPhone → SafeBase** auswählen.
7. Später: `.safebase` auswählen → denselben Passkey/Sicherheitsschlüssel bestätigen → Tresor öffnet sich. Ein Tresordatei-Passwort wird nicht abgefragt.

## Kryptografie des lokalen App-Tresors
- Zufälliger 256-Bit-Datenschlüssel für den lokalen Passwort-/Notiztresor.
- AES-256-GCM für die verschlüsselten Tresordaten.
- Der Datenschlüssel wird mit einem aus der 6-stelligen PIN über PBKDF2-HMAC-SHA-256 abgeleiteten Schlüssel geschützt.
- PBKDF2: 650.000 Iterationen und zufälliger 256-Bit-Salt.
- Die PIN selbst wird nicht gespeichert.

### Wichtige Sicherheitsgrenze der 6-stelligen PIN
Eine sechsstellige PIN besitzt nur **1.000.000 mögliche Kombinationen** und ist deshalb kryptografisch deutlich schwächer als ein langes zufälliges Master-Passwort. Die 30-Sekunden-Sperre schützt gegen normales Ausprobieren in der Oberfläche, kann aber einen Angreifer mit einer kopierten Browser-Datenbank nicht zuverlässig an Offline-Versuchen hindern. Für besonders sensible gespeicherte Passwörter ist **PIN + TOTP-2FA** sinnvoll; noch stärker wäre eine Passkey-gebundene Anmeldung.

## Kryptografie der externen `.safebase`-Datei v3
- AES-256-GCM für Manifest und jede enthaltene Datei.
- WebAuthn `prf` liefert einen credential-gebundenen geheimen Wert.
- PRF → HKDF-SHA-256 → AES-256-Schlüssel.
- Eigener zufälliger IV je verschlüsseltem Objekt.
- Die PRF-Ausgabe und der AES-Schlüssel werden nicht dauerhaft in der Tresordatei gespeichert.

## Alte `.safebase`-Dateien
Die Dateiformat-Kompatibilität aus v5.2 bleibt erhalten:
- v1: altes Tresordatei-Passwort einmalig eingeben und auf Passkey-only migrieren.
- v2: altes Tresordatei-Passwort + bisherigen Passkey einmalig bestätigen und auf v3 Passkey-only migrieren.
- v3: direkt mit Passkey/Sicherheitsschlüssel öffnen.

## Voraussetzungen
- HTTPS-Verbindung, z. B. GitHub Pages oder eigene HTTPS-Domain.
- Browser mit WebAuthn-PRF-Unterstützung für Passkey-only `.safebase`-Dateien.
- Für vorhandene passkey-geschützte Dateien dieselbe SafeBase-Domain/RP-ID weiterverwenden.

## Backup
Neue Backups sind **Passkey-only** und werden als `.safebasebackup` gespeichert:
1. WebAuthn registriert einen Passkey/Sicherheitsschlüssel und erzeugt über die `prf`-Erweiterung einen credential-gebundenen 32-Byte-Geheimwert.
2. Aus PRF-Geheimwert + zufälligem 32-Byte-HKDF-Salt wird mit HKDF-SHA-256 ein AES-256-GCM-Schlüssel abgeleitet.
3. Der vollständige Passwort-/Notiztresor inklusive Einstellungen und 2FA-Konfiguration wird als authentifizierter AES-256-GCM-Payload verschlüsselt.
4. Beim Import genügt der passende Passkey/Sicherheitsschlüssel zum Entschlüsseln des Backups. Anschließend wird eine **neue lokale 6-stellige Master-PIN** festgelegt, mit der der wiederhergestellte Browser-Tresor neu verschlüsselt wird.
5. Alte `.json`-Backups bleiben importierbar und verwenden weiterhin die damals zugehörige PIN bzw. das damalige Master-Passwort.

Die `.safebase`-Dateien aus dem Bereich **Dateien** sind weiterhin separate passkey-geschützte Tresordateien und müssen zusätzlich gesichert werden. Sowohl `.safebase` als auch `.safebasebackup` sind an die SafeBase-Domain/RP-ID gebunden.

## UI-Fix: Abbrechen-Buttons
Die Abbrechen-Buttons in Dialogen schließen das Fenster jetzt explizit und werden nicht mehr von der HTML-Pflichtfeldvalidierung blockiert. Der Service-Worker-Cache wurde für die korrigierte Oberfläche aktualisiert.

