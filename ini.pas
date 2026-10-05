unit Ini;

{$mode objfpc}{$H+}

interface


uses
  Classes, SysUtils, Forms, IniFiles;

type
    TIniSettings = record
      restoreSrcFbkFile : string;
      restoreDstFdbFile : string;
      backupSrcFdbFile : string;
      backupDstFbkFile : string;
      dbConfigFile : string;
      dbConfigString : string;
      fbPath : string;
      backupSrcLocal : boolean;
      backupSrcPort : integer;
      backupSrcHostname: string;
    end;

function ReadSettings:TIniSettings;
procedure WriteSettings(mySettings : TIniSettings);
function ReadCenadcoConfig(configFile:string):string;

implementation

const
  IniFile = 'CEN_BackRes.ini';

function ReadSettings:TIniSettings;
var
  Sett : TIniFile;
  mySettings : TIniSettings;
  i : integer;
  workingDir : string;
begin
  Sett := TIniFile.Create(IniFile);
    workingDir := IncludeTrailingPathDelimiter(ExtractFilePath(Application.ExeName)) ;

  try

    mySettings.dbConfigFile := Sett.ReadString('Main', 'dbConfigFile', 'c:\Program Files (x86)\Cenadco\Cenadco.ini');
    mySettings.dbConfigString := Sett.ReadString('Main', 'dbConfigString', '');
    mySettings.fbPath := Sett.ReadString('Main', 'path_firebird', workingDir +'firebird');

    if not(DirectoryExists(mySettings.fbPath)) then
      mySettings.fbPath := workingDir +'firebird';

    mySettings.restoreSrcFbkFile := Sett.ReadString('Restore', 'source_backup', 'c:\Program Files (x86)\Cenadco\backup\cenadco.fbk');
    mySettings.restoreDstFdbFile := Sett.ReadString('Restore', 'destination_database', workingDir + 'output' +'\cenadco.fdb');
    mySettings.backupSrcFdbFile := Sett.ReadString('Backup', 'source_database', 'c:\Program Files (x86)\Cenadco\data\CENADCO.FDB');
    mySettings.backupDstFbkFile := Sett.ReadString('Backup', 'destination_backup', workingDir + 'output' +'\cenadco_manualbackup.fbk');

    mySettings.backupSrcLocal := Sett.ReadBool('Backup', 'local', true);
    mySettings.backupSrcPort := Sett.ReadInteger('Backup', 'Port', 3051);
    mySettings.backupSrcHostname := Sett.ReadString('Backup', 'HostName', '127.0.0.1');

  finally
    Sett.Free;
  end;
  Result := mySettings;
end;

procedure WriteSettings(mySettings : TIniSettings);
var
  Sett : TIniFile;
  i : integer;
begin

  Sett := TIniFile.Create(IniFile);

  try

    Sett.WriteString('Main', 'dbConfigFile', mySettings.dbConfigFile);
    Sett.WriteString('Main', 'dbConfigString', mySettings.dbConfigString);
    Sett.WriteString('Main', 'path_firebird', mySettings.fbPath);

    Sett.WriteString('Restore', 'source_backup', mySettings.restoreSrcFbkFile);
    Sett.WriteString('Restore', 'destination_database', mySettings.restoreDstFdbFile);

    Sett.WriteString('Backup', 'source_database', mySettings.backupSrcFdbFile);
    Sett.WriteString('Backup', 'destination_backup', mySettings.backupDstFbkFile);

    Sett.WriteBool('Backup', 'local', mySettings.backupSrcLocal);
    Sett.WriteInteger('Backup', 'Port', mySettings.backupSrcPort);
    Sett.WriteString('Backup', 'HostName', mySettings.backupSrcHostname);

  finally
    Sett.Free;
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

