// Icons provided by https://www.flaticon.com

unit mainUnit;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, ExtCtrls, StdCtrls,
  Buttons, Process, ipcezcrypt, ipctypes;

type

  { TmainForm }

  TmainForm = class(TForm)
    b_chooseDbConfig: TButton;
    b_chooseBackupDst: TButton;
    b_chooseBackupSrc: TButton;
    b_chooseFbPath: TButton;
    b_restore: TButton;
    b_chooseRestoreSrc: TButton;
    b_chooseRestoreDst: TButton;
    b_backup: TButton;
    cbLocalDb: TCheckBox;
    e_DbConfig: TLabeledEdit;
    gb_restore: TGroupBox;
    gb_backup: TGroupBox;
    Label1: TLabel;
    le_fbPath: TLabeledEdit;
    le_hostname: TLabeledEdit;
    le_pathBackupDst: TLabeledEdit;
    le_pathBackupSrc: TLabeledEdit;
    le_port: TLabeledEdit;
    le_pathRestoreSrc: TLabeledEdit;
    le_pathRestoreDst: TLabeledEdit;
    MemoLog: TMemo;
    OpenDialog1: TOpenDialog;
    SelectDirectoryDialog1: TSelectDirectoryDialog;
    TimerProcess: TTimer;

    procedure b_backupClick(Sender: TObject);
    procedure b_chooseBackupDstClick(Sender: TObject);
    procedure b_chooseDbConfigClick(Sender: TObject);
    procedure b_chooseFbPathClick(Sender: TObject);
    procedure b_chooseRestoreDstClick(Sender: TObject);
    procedure b_chooseBackupSrcClick(Sender: TObject);
    procedure b_chooseRestoreSrcClick(Sender: TObject);
    procedure b_restoreClick(Sender: TObject);
    procedure cbLocalDbChange(Sender: TObject);
    procedure e_DbConfigChange(Sender: TObject);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormCreate(Sender: TObject);
    procedure le_fbPathChange(Sender: TObject);
    procedure le_hostnameChange(Sender: TObject);
    procedure le_pathBackupDstChange(Sender: TObject);
    procedure le_pathBackupSrcChange(Sender: TObject);
    procedure le_pathRestoreDstChange(Sender: TObject);
    procedure le_pathRestoreSrcChange(Sender: TObject);
    procedure le_portChange(Sender: TObject);
    procedure TimerProcessTimer(Sender: TObject);

  private
    GbakProcess: TProcess;

    procedure StartRestore;
    procedure StartBackup;
    procedure ReadProcessOutput;
    Procedure WriteLog(s : String);
    procedure grabPw;

    var dbConfig, dbConfigFile : string;



  public
    restoreDstFileName, backupDstFileName: string;
    LogFile, BackupOrRestore: String;


  end;

var
  mainForm: TmainForm;

implementation

{$R *.lfm}

uses Ini;

var iniSettings : TIniSettings;

{ TmainForm }

// Login holen
function HexToByte(aHEXValue: string): Byte;
begin
  Result := 0;

  aHEXValue := Trim(aHEXValue);
  if Length(aHEXValue) > 2 then
    aHEXValue := Copy(aHEXValue, 1, 2);

  case Length(aHEXValue) of
    1:
      begin
        case aHEXValue[1] of
          '0'..'9':
            Result := StrToInt(aHEXValue[1]);
          'A':
            Result := 10;
          'B':
            Result := 11;
          'C':
            Result := 12;
          'D':
            Result := 13;
          'E':
            Result := 14;
          'F':
            Result := 15;
        end;
      end;
    2:
      begin
        case aHEXValue[1] of
          '0'..'9':
            Result := StrToInt(aHEXValue[1]) * 16;
          'A':
            Result := 160;
          'B':
            Result := 176;
          'C':
            Result := 192;
          'D':
            Result := 208;
          'E':
            Result := 224;
          'F':
            Result := 240;
        end;

        case aHEXValue[2] of
          '0'..'9':
            Result := Result + StrToInt(aHEXValue[2]);
          'A':
            Result := Result + 10;
          'B':
            Result := Result + 11;
          'C':
            Result := Result + 12;
          'D':
            Result := Result + 13;
          'E':
            Result := Result + 14;
          'F':
            Result := Result + 15;
        end;
      end;
  end;
end;




procedure GetFBDBLogin(const aUserType: Integer; aConfig: string; var aUser, aPassword: string);
Const
  lcHilfStr = 'BESONDERE AUSWAHL ODER CONFIGURATION';
  lcHilfStr2 = '!Ab_If&12(01)kW';
var
  lEzCrypt: TipcEzCrypt;
  lByte: Byte;
  I: Integer;
  lLen: Integer;
  lAddStr: string;
  lTmpTxt: string;
  lAddLen: Integer;
  lStartInt: Integer;
begin
  aUser := '';
  aPassword := '';

  lEzCrypt := TipcEzCrypt.Create(Nil);
  try
    lEzCrypt.Algorithm := ezAES;
    lEzCrypt.UseHex := True;

    case aUserType of
      0: aUser := lcHilfStr[24] + lcHilfStr[2] + lcHilfStr[26] +
                    lcHilfStr[11] + lcHilfStr[6] + lcHilfStr[24] + lcHilfStr[4];
      else
        aUser := lcHilfStr[3] + 'Y' + lcHilfStr[13] + lcHilfStr[6] +
                   lcHilfStr[1] + lcHilfStr[32];
    end;
    lEzCrypt.InputMessage := 'BELA!' + aUser + '_2022_Edv';
    lEzCrypt.KeyPassword := aConfig;
    lEzCrypt.Encrypt();
    lTmpTxt := lEzCrypt.OutputMessage;

    for I := 1 to (Length(lTmpTxt) Div 2) do
    begin
      lByte := HexToByte(Copy(lTmpTxt, (I - 1) + 1, 2));
      if ((lByte >= 33) and (lByte <= 125) and (Length(aPassword) < 20)) then
        aPassword := aPassword + Char(lByte);
    end;

    lLen := Length(aPassword);
    if lLen < 20 then
    begin
      lAddStr := Copy(lcHilfStr2, 1, 20 - lLen);
      lAddLen := Length(lAddStr);
      if lAddLen > 1 then
      begin
        lStartInt := lAddLen Div 2;
        aPassword := Copy(lAddStr, lStartInt + 1, lAddLen - lStartInt) +
                       aPassword + Copy(lAddStr, 1, lStartInt);
      end else
        aPassword := aPassword + lAddStr;
    end;
  finally
    lEzCrypt.Free;
  end;
end;

procedure TMainForm.grabPw;
var
  dbUser, dbPassword : string;
begin
  dbConfig := e_dbconfig.Text;
  dbPassword := '';
  dbUser := '';
  try

    GetFBDBLogin(1,dbConfig,dbUser,dbPassword);
    MemoLog.Lines.Add(dbUser+' : '+dbPassword);

  except
    on E: Exception do
    begin
      showMessage('Error occured during grabbing Password: '+#13#10+ E.Message);
    end;
  end;
end;


Procedure TmainForm.WriteLog(s : String);
Var
F1 : TextFile;
sLog :string;
begin
 DateSeparator := '.';
 ShortDateFormat := 'dd/mm/yy';
 ShortTimeFormat := 'hh/mm/ss';
 sLog := DateToStr(now)+'-'+TimeToStr(now)+';'+ #$9 + s;

 MemoLog.Lines.Add(sLog);

  If Not FileExists(LogFile) then
 begin
  try
   AssignFile(F1,LogFile);
   ReWrite(F1);
   WriteLn(F1,sLog);
   CloseFile(F1);
  finally
   //CloseFile(F1);
  end;
 end else
 begin
   try
        AssignFile(F1,LogFile);
        Append(F1);

        WriteLn(F1,sLog);
        CloseFile(F1);
   except
     on E:Exception do ShowMessage('Error during writing Logfile: '+E.Message) ;
   end
 end;
end;

procedure TmainForm.b_chooseRestoreDstClick(Sender: TObject);
begin
  OpenDialog1.Filter := 'Firebird Database (*.fdb)|*.fdb';
  OpenDialog1.InitialDir:= ExtractFilePath(le_pathRestoreDst.Text);
  if OpenDialog1.Execute then
  begin
    le_pathRestoreDst.Text:= OpenDialog1.FileName;
  end;
end;

procedure TmainForm.b_chooseBackupSrcClick(Sender: TObject);
begin
  OpenDialog1.Filter := 'Firebird Database (*.fdb)|*.fdb';
  OpenDialog1.InitialDir:= ExtractFilePath(le_pathBackupSrc.Text);
  if OpenDialog1.Execute then
  begin
    le_pathBackupSrc.Text:= OpenDialog1.FileName;
  end;
end;


procedure TmainForm.b_chooseDbConfigClick(Sender: TObject);
begin
 OpenDialog1.Filter := 'Ini-Files (*.ini)|*.ini';
 OpenDialog1.InitialDir:= ExtractFilePath(iniSettings.dbConfigFile);
 if OpenDialog1.Execute then
  begin
    dbConfigFile := OpenDialog1.FileName;
    iniSettings.dbConfigFile := dbConfigFile;
    if(fileExists(dbConfigFile))then
    begin
      dbConfig := ReadCenadcoConfig(dbConfigFile);
      e_dbConfig.Text := dbConfig;
      iniSettings.dbConfigString:=dbConfig;
    end else
    begin
      WriteLog('DBKonfig not found:'+dbConfig+', will take dbConfig String instead');
      dbConfig := e_dbConfig.Text;
      iniSettings.dbConfigString:=dbConfig;
    end;
  end;
end;

procedure TmainForm.b_chooseFbPathClick(Sender: TObject);
begin
  if SelectDirectoryDialog1.Execute then
  begin
    le_fbPath.Text:=SelectDirectoryDialog1.FileName;
  end;
  //OpenDialog1.InitialDir:= ExtractFilePath(le_pathRestoreSrc.Text);
end;

procedure TmainForm.b_chooseBackupDstClick(Sender: TObject);
begin
  OpenDialog1.Filter := 'Firebird Backup (*.fbk)|*.fbk';
  OpenDialog1.InitialDir:= ExtractFilePath(le_pathBackupDst.Text);
  if OpenDialog1.Execute then
  begin
    le_pathBackupDst.Text:= OpenDialog1.FileName;
  end;
end;

procedure TmainForm.b_backupClick(Sender: TObject);
begin
  StartBackup;
end;

procedure TmainForm.b_chooseRestoreSrcClick(Sender: TObject);
begin
  OpenDialog1.Filter := 'Firebird Backup (*.fbk)|*.fbk';
  OpenDialog1.InitialDir:= ExtractFilePath(le_pathRestoreSrc.Text);
  if OpenDialog1.Execute then
  begin
    le_pathRestoreSrc.Text:= OpenDialog1.FileName;
  end;
end;


procedure TmainForm.StartRestore;
var
  dbUser, dbPassword, OutputDir: string;
begin

  MemoLog.Clear;
  dbUser := '';
  dbPassword := '';

  BackupOrRestore := 'restore';

  //  holen des Benutzerlogins
  GetFBDBLogin(1,dbConfig,dbUser,dbPassword);

  try
    OutputDir := ExtractFilePath(iniSettings.restoreDstFdbFile);
  except
    ShowMessage('invalid Destination-File: ' + iniSettings.restoreDstFdbFile);
  end;



  { Ausgabeordner anlegen, falls nicht vorhanden }
  if not DirectoryExists(OutputDir) then
  begin
    if not ForceDirectories(OutputDir) then
    begin
      ShowMessage(
        'Der Ausgabeordner konnte nicht erstellt werden:' +
        LineEnding + OutputDir
      );
      Exit;
    end;
  end;

  { Eingaben prüfen }



  if le_pathRestoreSrc.Text = '' then
  begin
    ShowMessage('Please enter path to source FBK-file.');
    Exit;
  end;

  if le_pathRestoreDst.Text = '' then
  begin
    ShowMessage('Please enter name of target FDB-file');
    Exit;
  end;


  { Zieldatei festlegen }
  restoreDstFileName := le_pathRestoreDst.Text;
  { Prüfen, ob Zieldatei bereits existiert }

  { Prüfen, ob Zieldatei bereits existiert }

  if FileExists(restoreDstFileName) then
  begin
    if MessageDlg(
         'The destination file already exists:' + LineEnding +
         LineEnding +
         restoreDstFileName + LineEnding +
         LineEnding +
         'Do you want to overwrite it?',
         mtConfirmation,
         [mbYes, mbNo],
         0
       ) <> mrYes then
    begin
      WriteLog('Restore cancelled.');
      Exit;
    end;

    { Vorhandene Datenbank löschen }
    if not DeleteFile(restoreDstFileName) then
    begin
      ShowMessage(
        'The existing database could not be deleted:' +
        LineEnding + LineEnding +
        restoreDstFileName
      );
      Exit;
    end;
  end;

  { Prüfen, ob bereits ein GBAK-Prozess läuft }

  if Assigned(GbakProcess) then
  begin
    if GbakProcess.Running then
    begin
      ShowMessage('GBAK-Process already running.');
      Exit;
    end;

    FreeAndNil(GbakProcess);
  end;


  { Log leeren }

  MemoLog.Clear;

  WriteLog('Start Firebird Restore...');
  WriteLog('');
  WriteLog('Source:  ' + le_pathRestoreSrc.Text);
  WriteLog('Destination:    ' + restoreDstFileName);
  WriteLog('');


  { GBAK-Prozess erzeugen }

  GbakProcess := TProcess.Create(Self);

  with GbakProcess do
  begin




    if DirectoryExists(iniSettings.fbPath) then
    begin
      CurrentDirectory := iniSettings.fbPath;
      Executable := iniSettings.fbPath + '\gbak.exe';
    end else
    begin
      //showMessage('Firebird Directory does not exist: '+ iniSettings.fbPath + #10#13 + ' will take "'+IncludeTrailingPathDelimiter(
      //  ExtractFilePath(Application.ExeName)
      //) + 'firebird" instead');

      CurrentDirectory :=
      IncludeTrailingPathDelimiter(
        ExtractFilePath(Application.ExeName)
      ) + 'firebird';

      Executable := IncludeTrailingPathDelimiter(
        ExtractFilePath(Application.ExeName)
      ) + 'firebird\gbak.exe';
    end;


    { Restore }
    Parameters.Add('-c');

    { ausführliche Ausgabe }
    Parameters.Add('-v');

    { Benutzer }
    Parameters.Add('-user');
    Parameters.Add(dbUser);

    { Passwort }
    Parameters.Add('-password');
    Parameters.Add(dbPassword);

    { FBK-Quelle }
    Parameters.Add(le_pathRestoreSrc.Text);

    { FDB-Ziel }
    Parameters.Add(restoreDstFileName);

    { Ausgabe über Pipe abfangen }
    Options := [
      poUsePipes,
      poStderrToOutPut,
      poNoConsole
    ];
    { Prozess starten }
    Execute;
    WriteLog('GBAK process started.');
  end;

  { Timer zum Auslesen der Ausgabe starten }

  TimerProcess.Enabled := True;

  b_restore.Enabled := False;

  WriteLog('GBAK started.');
  WriteLog('');
end;

procedure TmainForm.StartBackup;
var
  dbUser, dbPassword, hostname, port, hostnamePort : string;
begin

  MemoLog.Clear;
  dbUser := '';
  dbPassword := '';
  hostname := '';
  port := '';
  hostnamePort := '';

  BackupOrRestore := 'backup';

  if (not cbLocalDb.Checked)then
  begin
    hostname := le_hostname.Text;
    port := le_port.Text;
    hostnamePort := hostname+'/'+port+':';
  end;

  //  holen des Benutzerlogins
  GetFBDBLogin(1,dbConfig,dbUser,dbPassword);


  { Eingaben prüfen }

  if le_pathBackupSrc.Text = '' then
  begin
    ShowMessage('Please enter path to source FDB-file.');
    Exit;
  end;

  if le_pathBackupDst.Text = '' then
  begin
    ShowMessage('Please enter name of target FBK-file');
    Exit;
  end;


  { Zieldatei festlegen }
  backupDstFileName := le_pathBackupDst.Text;

  { Prüfen, ob Zieldatei bereits existiert }

  if FileExists(backupDstFileName) then
  begin
    if MessageDlg(
         'The destination file already exists:' + LineEnding +
         LineEnding +
         backupDstFileName + LineEnding +
         LineEnding +
         'Do you want to overwrite it?',
         mtConfirmation,
         [mbYes, mbNo],
         0
       ) <> mrYes then
    begin
      WriteLog('Restore cancelled.');
      Exit;
    end;

    { Vorhandene Datenbank löschen }
    if not DeleteFile(backupDstFileName) then
    begin
      ShowMessage(
        'The existing Backup-file could not be deleted:' +
        LineEnding + LineEnding +
        backupDstFileName
      );
      Exit;
    end;
  end;

  { Prüfen, ob bereits ein GBAK-Prozess läuft }

  if Assigned(GbakProcess) then
  begin
    if GbakProcess.Running then
    begin
      ShowMessage('GBAK-Process already running.');
      Exit;
    end;

    FreeAndNil(GbakProcess);
  end;


  { Log leeren }

  MemoLog.Clear;

  WriteLog('Start Firebird Backup...');
  WriteLog('');
  WriteLog('Source:  ' + le_pathBackupSrc.Text);
  WriteLog('Destination:    ' + backupDstFileName);
  WriteLog('Hostname:       ' + hostname);
  WriteLog('Port:       ' + port);
  WriteLog('');


  { GBAK-Prozess erzeugen }

  GbakProcess := TProcess.Create(Self);

  with GbakProcess do
  begin
    //CurrentDirectory :=
    //IncludeTrailingPathDelimiter(
    //  ExtractFilePath(Application.ExeName)
    //) + 'firebird';
    //
    //Executable := IncludeTrailingPathDelimiter(
    //  ExtractFilePath(Application.ExeName)
    //) + 'firebird\gbak.exe';

    if DirectoryExists(iniSettings.fbPath) then
    begin
      CurrentDirectory := iniSettings.fbPath;
      Executable := iniSettings.fbPath + '\gbak.exe';
    end else
    begin
      //showMessage('Firebird Directory does not exist: '+ iniSettings.fbPath + #10#13 + ' will take "'+IncludeTrailingPathDelimiter(
      //  ExtractFilePath(Application.ExeName)
      //) + 'firebird" instead');
      CurrentDirectory :=
      IncludeTrailingPathDelimiter(
        ExtractFilePath(Application.ExeName)
      ) + 'firebird';

      Executable := IncludeTrailingPathDelimiter(
        ExtractFilePath(Application.ExeName)
      ) + 'firebird\gbak.exe';
    end;

    { Restore }
    Parameters.Add('-b');

    { ausführliche Ausgabe }
    Parameters.Add('-v');

    { Benutzer }
    Parameters.Add('-user');
    Parameters.Add(dbUser);

    { Passwort }
    Parameters.Add('-password');
    Parameters.Add(dbPassword);

    { FDB-Quelle }
    Parameters.Add(hostnamePort+le_pathBackupSrc.Text);

    { FDB-Ziel }
    Parameters.Add(backupDstFileName);

    { Ausgabe über Pipe abfangen }
    Options := [
      poUsePipes,
      poStderrToOutPut,
      poNoConsole
    ];
    { Prozess starten }
    Execute;
    WriteLog('GBAK process started.');
  end;

  { Timer zum Auslesen der Ausgabe starten }

  TimerProcess.Enabled := True;

  b_restore.Enabled := False;
  b_backup.Enabled := False;

  WriteLog('GBAK started.');
  WriteLog('');
end;



procedure TmainForm.b_restoreClick(Sender: TObject);
begin
  StartRestore;
end;

procedure TmainForm.cbLocalDbChange(Sender: TObject);
begin
  le_hostname.Enabled:= not cbLocalDb.Checked;
  le_port.Enabled:= not cbLocalDb.Checked;
  iniSettings.backupSrcLocal := cbLocalDb.Checked;
end;

procedure TmainForm.e_DbConfigChange(Sender: TObject);
begin
  iniSettings.dbConfigString:=e_DbConfig.Text;
end;

procedure TmainForm.FormClose(Sender: TObject; var CloseAction: TCloseAction);
begin
  WriteSettings(iniSettings);
end;

procedure TmainForm.FormCreate(Sender: TObject);
begin
 iniSettings := ReadSettings;
 BackupOrRestore := '';
 LogFile := ExtractFilePath(Application.exeName)+'\CEN_BackRes.log';
 //dbConfigFile := 'c:\Program Files (x86)\Cenadco\Cenadco.ini';
 dbConfigFile := iniSettings.dbConfigFile;

  le_fbPath.Text:= iniSettings.fbPath;

  le_hostname.Enabled:= not cbLocalDb.Checked;
  le_port.Enabled:= not cbLocalDb.Checked;

  le_pathRestoreSrc.Text := iniSettings.restoreSrcFbkFile;
  le_pathRestoreDst.Text:= iniSettings.restoreDstFdbFile;

  le_pathBackupSrc.Text := iniSettings.backupSrcFdbFile;
  le_pathBackupDst.Text:= iniSettings.backupDstFbkFile;

  cbLocalDb.Checked := iniSettings.backupSrcLocal;
  le_port.Text := IntToStr(iniSettings.backupSrcPort);
  le_hostname.Text := iniSettings.backupSrcHostname;

  if(trim(iniSettings.dbConfigString) <> '')then
  begin
    e_DbConfig.Text := iniSettings.dbConfigString;
    dbConfig := iniSettings.dbConfigString;
  end else
  begin
    try
      if(fileExists(dbConfigFile))then
      begin
        dbConfig := ReadCenadcoConfig(dbConfigFile);
        e_dbConfig.Text := dbConfig;
      end else
      begin
        WriteLog('DBKonfig not found:'+dbConfig+', will take dbConfig String instead');
        dbConfig := e_dbConfig.Text;
      end;

    except
      on E: Exception do
      begin
        WriteLog('Error during read DBKonfig: ' + E.Message);
        dbConfig := e_dbConfig.Text;
      end;
    end;
  end;
end;

procedure TmainForm.le_fbPathChange(Sender: TObject);
begin
  iniSettings.fbPath:=le_fbPath.Text;
end;

procedure TmainForm.le_hostnameChange(Sender: TObject);
begin
  iniSettings.backupSrcHostname:=le_hostname.Text;
end;

procedure TmainForm.le_pathBackupDstChange(Sender: TObject);
begin
  iniSettings.backupDstFbkFile := le_pathBackupDst.Text;
end;

procedure TmainForm.le_pathBackupSrcChange(Sender: TObject);
begin
  iniSettings.backupSrcFdbFile := le_pathBackupSrc.Text;
end;

procedure TmainForm.le_pathRestoreDstChange(Sender: TObject);
begin
 iniSettings.restoreDstFdbFile:= le_pathRestoreDst.Text;
end;

procedure TmainForm.le_pathRestoreSrcChange(Sender: TObject);
begin
  iniSettings.restoreSrcFbkFile:= le_pathRestoreSrc.Text;
end;

procedure TmainForm.le_portChange(Sender: TObject);
begin
  iniSettings.backupSrcPort:= StrToIntDef(le_port.Text,3051);
end;

procedure TmainForm.TimerProcessTimer(Sender: TObject);
begin
  if not Assigned(GbakProcess) then
    Exit;

  { Ausgabe abholen }
  ReadProcessOutput;

  { Prüfen, ob GBAK fertig ist }
  if not GbakProcess.Running then
  begin
    { Restliche Ausgabe abholen }
    ReadProcessOutput;

    TimerProcess.Enabled := False;

    WriteLog('');
    WriteLog('----------------------------------------');

    if (BackupOrRestore = 'restore') then
    begin
      if GbakProcess.ExitStatus = 0 then
      begin
        WriteLog('Restore successfully.');
        WriteLog(
          'Database written to: ' + restoreDstFileName
        );
      end
      else
      begin
        WriteLog(
          'Restore failed. Exit-Code: ' +
          IntToStr(GbakProcess.ExitStatus)
        );
      end;
    end;

    if (BackupOrRestore = 'backup') then
    begin
      if GbakProcess.ExitStatus = 0 then
      begin
        WriteLog('Backup successfully.');
        WriteLog(
          'Database Backup File written to: ' + BackupDstFileName
        );
      end
      else
      begin
        WriteLog(
          'Backup failed. Exit-Code: ' +
          IntToStr(GbakProcess.ExitStatus)
        );
      end;
    end;
    WriteLog('----------------------------------------');

    b_restore.Enabled := True;
    b_backup.Enabled := True;
  end;
end;

procedure TmainForm.ReadProcessOutput;
var
  Buffer: array[0..4095] of Byte;
  Count: Integer;
  S: String;
begin
  if not Assigned(GbakProcess) then
    Exit;

  while GbakProcess.Output.NumBytesAvailable > 0 do
  begin
    Count := GbakProcess.Output.Read(Buffer, SizeOf(Buffer));

    if Count <= 0 then
      Break;

    SetString(S, PChar(@Buffer[0]), Count);

    WriteLog(S);

    MemoLog.SelStart := Length(MemoLog.Text);
    MemoLog.SelLength := 0;
  end;
end;


end.

