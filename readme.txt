14:30 02.10.2026	
Dirk Hanisch

V1.1.0.0

Icons from https://www.flaticon.com
Many thanks!

Das Tool "CEN_BackRes.exe" erlaubt das Sichern und WIederherstellen der Datenbank mit Hilfe des Tools GBAK


Für das Tool ist keine Installation nötig, aber folgende DLL-Dateien müssen sich im Arbeitsverzeichnis unter /Firebird befinden:

- ipworks20.dll
- ipworksencrypt20.dll 
- fbclient.dll 

Die Pfade zur Datenbank und der Cenadco.ini können frei gewählt werden. 

Die Settings werden in der Datei CEN_BackRes.ini gemerkt und können angepasst werden (z.B. um den Pfad zum Firebird anzupassen)

Folgende Werte sind einstellbar
--------------------------------

[Main]
dbConfigFile= <Pfad zur Cenadco.ini zum Ermitteln des DB Passwort>
default: c:\Program Files (x86)\Cenadco\Cenadco.ini

dbConfigString=zuletzt bekannter Konfig-String, falls keine cenadco.ini zu finden ist
default: 

path_firebird= <Pfad zum FIrebird, standardmäßig wird unter dem Arbeitsverzeichnis das Verzeichnis "/firebird" durchsucht, wo die wichtigsten binaries als portable version liegen
default: firebird

[Restore]
source_backup = Quellpfad zur Backupdatei (*.fbk)
destination_database = Zielpfad zur Datenbank (*.fdb)

[Backup]
source_database=Quellpfad zur Quelldatenbank oder der DB Alias (*.fdb)
destination_backup=Zielfad zur BAckupdatei, die geschrieben wird (*.fbk)

local= Lokale Datenbank oder Remote per Hostname/Port (0/1)
Port=Port bei Remote (default 3051)
HostName= Host bei Remote (default 127.0.0.1)

-------------------------------------------------------

Updates:
