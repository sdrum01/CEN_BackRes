unit Ini;

{$mode objfpc}{$H+}

interface


uses
  Classes, SysUtils, IniFiles;

type
    TIniSettings = record
      dbFile : string;
      dbConfigFile : string;
      port : integer;
      hostname: string;
      debug : integer;
      sc_version : integer;
      tables : TStringList;
      show_password : integer;
      show_sql : integer;
      show_alltables : integer;
      show_tools : integer;
      show_sctools : integer;
    end;

function ReadSettings:TIniSettings;
procedure WriteSettings(mySettings : TIniSettings);
function ReadCenadcoConfig(configFile:string):string;

implementation

const
  IniFile = 'CEN_SCConfig.ini';

  TABLES: array[0..5] of string = (
  'CEN_DEVICES',
  'CEN_ANLAGE',
  'CEN_SC',
  'CEN_COMPONENTS',
  'CEN_SDL_BOX',
  'CEN_SDL_BOXSIZES'
  );

function ReadSettings:TIniSettings;
var
  Sett : TIniFile;
  mySettings : TIniSettings;
  keyListTables : TStringList;
  i : integer;
begin
  Sett := TIniFile.Create(IniFile);
  keyListTables := TStringList.Create;



  try
    mySettings.dbFile := Sett.ReadString('Main', 'dbFile', 'c:\Program Files (x86)\Cenadco\data\CENADCO.FDB');
    mySettings.dbConfigFile := Sett.ReadString('Main', 'dbConfigFile', 'c:\Program Files (x86)\Cenadco\Cenadco.ini');
    mySettings.port := Sett.ReadInteger('Main', 'Port', 3051);
    mySettings.hostname := Sett.ReadString('Main', 'HostName', 'localhost');

    mySettings.tables := TStringList.Create;

    {
    Sett.ReadSection('tables', keyListTables); // Alle Schlüssel aus der Sektion 'Tabellen' lesen
    if(keyListTables.Count > 0)then begin
      for i := 0 to keyListTables.Count - 1 do
      mySettings.tables.Add( Sett.ReadString('tables', keyListTables[i], '') );
    end else begin
      for i := Low(TABLES) to High(TABLES) do
      mySettings.tables.Add(TABLES[i]); // Eintrag hinzufügen
    end;
    }

    mySettings.show_password := Sett.ReadInteger('extra', 'show_password', 0);
    mySettings.show_sql := Sett.ReadInteger('extra', 'show_sql', 0);
    mySettings.show_alltables := Sett.ReadInteger('extra', 'show_alltables', 0);
    mySettings.show_tools := Sett.ReadInteger('extra', 'show_tools', 0);
    mySettings.show_sctools := Sett.ReadInteger('extra', 'show_sctools', 1);

  finally
    keyListTables.Free;
    Sett.Free;
  end;


  Result := mySettings;
end;

procedure WriteSettings(mySettings : TIniSettings);
var
  Sett : TIniFile;
  i : integer;
  keyListTables : TStringList;
begin
  keyListTables := TStringList.Create;
  Sett := TIniFile.Create(IniFile);

  try

    Sett.WriteString('Main', 'dbFile', mySettings.dbFile);
    Sett.WriteString('Main', 'dbConfigFile', mySettings.dbConfigFile);
    Sett.WriteInteger('Main', 'Port', mySettings.port);
    Sett.WriteString('Main', 'HostName', mySettings.hostname);

    // kontrollieren, ob Tabellen definiert sind
    Sett.ReadSection('tables', keyListTables);
    if(keyListTables.Count = 0)then
    begin
      Sett.EraseSection('Tables');
      for i := 0 to mySettings.tables.Count - 1 do
        Sett.WriteString('Tables', 'table'+IntToStr(i+1), mySettings.tables[i]);
    end;

  finally
    Sett.Free;
    keyListTables.Free;
  end;



end;

function ReadCenadcoConfig(configFile:string):string;
var
  CenConfig : TIniFile;
  dbConfig : string;

begin
  CenConfig := TIniFile.Create(configFile);
  try
    dbConfig := CenConfig.ReadString('Database', 'DBCONFIG', '');
  except on E: Exception do
  begin

  end;


  end;
  CenConfig.Free;
  Result := dbConfig;
end;

end.

