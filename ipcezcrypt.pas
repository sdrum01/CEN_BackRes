

unit ipcezcrypt;



{$UNDEF USE_DYNAMIC_LOADING}
{$UNDEF USE_EXPLICIT_INIT}
{$UNDEF ANSICHAR_IS_BYTE}
{$UNDEF NO_ANSI}
{$UNDEF USE_CDECL}

{$IFDEF FPC}  //Lazarus
  {$IFDEF FPC_UNICODESTRINGS}
    // ensure that mode Delphi Unicode is enabled, not a modeswitch unicodestrings
    {$MODE DELPHIUNICODE}
  {$ELSE}
    {$MODE DELPHI}
  {$ENDIF}
  {$DEFINE USEIPWORKSENCRYPTDLL}
{$ENDIF}

{$IFNDEF FPC}
  {$IF CompilerVersion >= 24} // XE3+
    {$LEGACYIFEND ON}
  {$IFEND}
{$ENDIF}

{$IF DEFINED(LINUX) OR DEFINED(ANDROID) OR DEFINED(MACOS) OR DEFINED(IOS)}
  {$DEFINE USEIPWORKSENCRYPTDLL}
  {$DEFINE ANSICHAR_IS_BYTE}
  {$DEFINE NO_ANSI}
  {$DEFINE USE_CDECL}
{$IFEND}

{$IF DEFINED(LINUX) OR DEFINED(MACOS)}
  {$IFNDEF IOS}
    {$DEFINE USE_DYNAMIC_LOADING}
  {$ENDIF}
{$IFEND}

{$IF DEFINED(ANDROID)}
  {$DEFINE USE_EXPLICIT_INIT}
{$IFEND}

{$IFDEF USE_IPWORKSENCRYPT_ANDROID_SHARED_LIBRARY}
  {$DEFINE USE_DYNAMIC_LOADING}
{$ENDIF}



{$IF DEFINED(UNICODE) AND NOT DEFINED(MSWINDOWS)}
  {$DEFINE NONWINUNICODE}
{$IFEND}



{$IFNDEF USEIPWORKSENCRYPTDLL}
  // in case if loading DLL from resources
  {$DEFINE USE_DYNAMIC_LOADING}
{$ENDIF}

{$UNDEF UNICODELIB}
{$IF DEFINED(MSWINDOWS)}
  {$DEFINE UNICODELIB}
{$IFEND}


{$IFDEF UNICODE}
  {$IFNDEF UNICODELIB}
    {$DEFINE UNICODE_ON_ANSI}
  {$ELSE}
    {$DEFINE UNICODE_ON_UNICODE}
  {$ENDIF}
{$ELSE}
  {$IFDEF UNICODELIB}
    {$DEFINE ANSI_ON_UNICODE}
  {$ELSE}
    {$DEFINE ANSI_ON_ANSI}
  {$ENDIF}
{$ENDIF}


interface

uses
{$IFDEF FPC}  //Lazarus
  SysUtils, Classes,
{$ELSE}
  {$IF CompilerVersion >= 23}System.SysUtils{$ELSE}SysUtils{$IFEND}, {$IF CompilerVersion >= 23}System.Classes{$ELSE}Classes{$IFEND}, 
{$ENDIF}
  {$IFDEF FPC}
  dynlibs,
  {$ELSE}
  {$IFDEF POSIX}
  Posix.Base,
  {$ENDIF}
  {$ENDIF}
  ipctypes, ipccore, ipckeys;

type

  (*** Enum Types ***)

  TipcezcryptAlgorithms = ipctypes.TipcTEzCryptAlgorithms;


  TipcezcryptCipherModes = ipctypes.TipcTCipherModes;


  TipcezcryptPaddingModes = ipctypes.TipcTPaddingModes;


  (*** Event Delegate Types ***)
  TErrorEvent = procedure (
    Sender: TObject;
    ErrorCode: Integer;
    const Description: String
  ) of Object;

  TProgressEvent = procedure (
    Sender: TObject;
    BytesProcessed: Int64;
    PercentProcessed: Integer
  ) of Object;


  (*** Exception Type ***)
  EipcEzCrypt = class(EIPWorksEncrypt)
  end;

  (*** Component Type ***)
{$IFNDEF FPC}
  {$IF CompilerVersion >= 23}
  [ComponentPlatformsAttribute(
    pidWin32 or pidWin64










   )]
  {$IFEND}
{$ENDIF}
  TipcEzCrypt = class(TipcTypesCore)
    private
      (*** Event Handler Procedure Pointers ***)
      FOnError: TErrorEvent;
      FOnProgress: TProgressEvent;

      m_ctl: Pointer;
      m_streamFromSetInputStream : TStream;
      m_streamFromSetOutputStream : TStream;

      (*** Inner objects for types and collections ***)

      function HasData: Boolean;
      procedure ReadHnd(Reader: TStream);
      procedure WriteHnd(Writer: TStream);
      function BStr2CStr(pBStr: Pointer; lenBStr: Integer; bArr: TBytes): String;

      procedure SetRuntimeLicense(key: String);
      function GetRuntimeLicense: String;

    protected
      procedure AboutDlg; override;
      procedure DefineProperties(Filer: TFiler); override;

      function ThrowCoreException(Err: Integer; const Desc: {$ifndef NO_ANSI}AnsiString{$else}string{$endif}): EIPWorksEncrypt;
      procedure TreatErr(Err: Integer; const Desc: String);

      (*** Property Getters/Setters ***)
      function  get_Algorithm: TipcezcryptAlgorithms;
      procedure set_Algorithm(valAlgorithm: TipcezcryptAlgorithms);
      function  get_CipherMode: TipcezcryptCipherModes;
      procedure set_CipherMode(valCipherMode: TipcezcryptCipherModes);
      function  get_InputFile: String;
      procedure set_InputFile(valInputFile: String);
      function  get_InputMessage: String;
      procedure set_InputMessage(valInputMessage: String);
      function  get_InputMessageB: TBytes;
      procedure set_InputMessageB(valInputMessage: TBytes);
      function  get_IV: String;
      procedure set_IV(valIV: String);
      function  get_IVB: TBytes;
      procedure set_IVB(valIV: TBytes);
      function  get_Key: String;
      procedure set_Key(valKey: String);
      function  get_KeyB: TBytes;
      procedure set_KeyB(valKey: TBytes);
      function  get_KeyPassword: String;
      procedure set_KeyPassword(valKeyPassword: String);
      function  get_OutputFile: String;
      procedure set_OutputFile(valOutputFile: String);
      function  get_OutputMessage: String;
      function  get_OutputMessageB: TBytes;
      function  get_Overwrite: Boolean;
      procedure set_Overwrite(valOverwrite: Boolean);
      function  get_PaddingMode: TipcezcryptPaddingModes;
      procedure set_PaddingMode(valPaddingMode: TipcezcryptPaddingModes);
      function  get_UseHex: Boolean;
      procedure set_UseHex(valUseHex: Boolean);


      (*** Property Getters/Setters: OO API ***)


    public
      constructor Create(AOwner: TComponent); overload; override;
      constructor Create(AOwner: TComponent; OEMKey: string); reintroduce; overload;
      destructor Destroy; override;
      function ReportEventException(E: Exception; Event: String; ReFire: Boolean = True): Integer;

      property RuntimeLicense: String read GetRuntimeLicense write SetRuntimeLicense;

      procedure SetInputMessage(lpInputMessage: PLXAnsiChar; lenInputMessage: Cardinal);
      procedure SetIV(lpIV: PLXAnsiChar; lenIV: Cardinal);
      procedure SetKey(lpKey: PLXAnsiChar; lenKey: Cardinal);
      procedure SetOutputMessage(lpOutputMessage: PLXAnsiChar; lenOutputMessage: Cardinal);


      (*** Runtime Property Definitions ***)

      property InputMessageB: TBytes read get_InputMessageB write set_InputMessageB;


      property IVB: TBytes read get_IVB write set_IVB;


      property KeyB: TBytes read get_KeyB write set_KeyB;


      property OutputMessage: String read get_OutputMessage;


      property OutputMessageB: TBytes read get_OutputMessageB;



      (*** Runtime properties: OO API ***)


{$IFNDEF DELPHI3}
      (*** Method Definitions ***)
      function  Config(ConfigurationString: String): String;
      procedure Decrypt();
      function  DecryptBlock(InputBuffer: TBytes; LastBlock: Boolean): TBytes;
      procedure Encrypt();
      function  EncryptBlock(InputBuffer: TBytes; LastBlock: Boolean): TBytes;
      procedure Reset();
      procedure SetInputStream(InputStream: TStream);
      procedure SetOutputStream(OutputStream: TStream);
{$ENDIF}

    published
      (*** Design-time Property Definitions ***)

      property Algorithm: TipcezcryptAlgorithms read get_Algorithm write set_Algorithm default ezAES;


      property CipherMode: TipcezcryptCipherModes read get_CipherMode write set_CipherMode default cmCBC;


      property InputFile: String read get_InputFile write set_InputFile;


      property InputMessage: String read get_InputMessage write set_InputMessage;


      property IV: String read get_IV write set_IV;


      property Key: String read get_Key write set_Key;


      property KeyPassword: String read get_KeyPassword write set_KeyPassword;


      property OutputFile: String read get_OutputFile write set_OutputFile;


      property Overwrite: Boolean read get_Overwrite write set_Overwrite default false;


      property PaddingMode: TipcezcryptPaddingModes read get_PaddingMode write set_PaddingMode default pmPKCS7;


      property UseHex: Boolean read get_UseHex write set_UseHex default false;


      (*** Event Handler Bindings ***)
      property OnError: TErrorEvent read FOnError write FOnError;
      property OnProgress: TProgressEvent read FOnProgress write FOnProgress;

    end;

    procedure Register;

implementation


{$T-}

{$IFDEF MSWINDOWS} // Both DLL and DRU loading require Windows dependency
{$IFDEF FPC}  //Lazarus
uses Messages;
{$ELSE}
uses {$IF CompilerVersion >= 23}Winapi.Windows{$ELSE}Windows{$IFEND}, {$IF CompilerVersion >= 23}Winapi.Messages{$ELSE}Messages{$IFEND};
{$ENDIF}
{$ENDIF}

const
  PID_EzCrypt_Algorithm                                          = 1;
  PID_EzCrypt_CipherMode                                         = 2;
  PID_EzCrypt_InputFile                                          = 3;
  PID_EzCrypt_InputMessage                                       = 4;
  PID_EzCrypt_IV                                                 = 5;
  PID_EzCrypt_Key                                                = 6;
  PID_EzCrypt_KeyPassword                                        = 7;
  PID_EzCrypt_OutputFile                                         = 8;
  PID_EzCrypt_OutputMessage                                      = 9;
  PID_EzCrypt_Overwrite                                          = 10;
  PID_EzCrypt_PaddingMode                                        = 11;
  PID_EzCrypt_UseHex                                             = 12;


  EID_EzCrypt_Error = 1;
  EID_EzCrypt_Progress = 2;

  MID_EzCrypt_Config = 2;
  MID_EzCrypt_Decrypt = 3;
  MID_EzCrypt_DecryptBlock = 4;
  MID_EzCrypt_Encrypt = 5;
  MID_EzCrypt_EncryptBlock = 6;
  MID_EzCrypt_Reset = 7;
  MID_EzCrypt_SetInputStream = 8;
  MID_EzCrypt_SetOutputStream = 9;

  CREATE_OPT = {$IFDEF UNICODE}1{$ELSE}0{$ENDIF};
  EVTSTR_OPT = {$IFDEF UNICODE}2{$ELSE}1{$ENDIF};

  {$IFDEF MSWINDOWS}
  DLLNAME = 'IPWORKSENCRYPT20.DLL';
  {$ENDIF}
  {$IFDEF LINUX}
  DLLNAME = 'libipworksencrypt.so.20.0';
  {$ENDIF}
  {$IFDEF ANDROID}
  {$IFDEF USE_DYNAMIC_LOADING}
  DLLNAME = 'libipworksencrypt.so.20.0';
  {$ELSE}
  DLLNAME = 'libipworksencrypt.20.0.a';
  {$ENDIF}
  {$ENDIF}
  {$IFDEF IOS}
  DLLNAME = 'libipworksencrypt.20.0.a';
  {$ELSE}
  {$IFDEF MACOS}
  DLLNAME = 'libipworksencrypt.20.0.dylib';
  {$ENDIF}
  {$ENDIF}

{$WARNINGS OFF}

type
  INTARR = array[0..32] of Integer;
  LPINTARR = ^INTARR;
  LPINT = ^Cardinal;
  MEventHandle = function(lpContext: TipcEzCrypt; event_id: Integer; cparam: Integer; params: LPVOIDARR; cbparam: LPINTARR): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF};
  PEventHandle = ^MEventHandle;


{$IFNDEF USEIPWORKSENCRYPTDLL}
var
  pEntryPoint: Pointer;
  pBaseAddress: Pointer;
  iLoadCount: Integer;
{$ELSE}
{$IFDEF USE_DYNAMIC_LOADING}
var
  hLib : {$ifndef FPC}HMODULE{$else}TLibHandle{$endif};
  iLoadCount: Integer;
{$ENDIF USE_DYNAMIC_LOADING}
{$ENDIF USEIPWORKSENCRYPTDLL}


{$IFDEF USE_DYNAMIC_LOADING}
  _IPWorksEncrypt_EvtStr:                        function(pEvtStr: Pointer; id: Integer; value: Pointer; opt: Integer): Pointer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF};
  _IPWorksEncrypt_Stream:                        function(pStream: Pointer; op: Integer; params: LPVOIDARR; retVal: Pointer): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF};
  _IPWorksEncrypt_EzCrypt_Create:                function(pMethod: PEventHandle; pObject: TipcEzCrypt; pKey: Pointer; opts: Integer): Pointer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF};
  _IPWorksEncrypt_EzCrypt_Destroy:               function(p: Pointer): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF};
  _IPWorksEncrypt_EzCrypt_Set:                   function(p: Pointer; index: Integer; arridx: Integer; value: Pointer; len: Cardinal): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF};
  _IPWorksEncrypt_EzCrypt_Get:                   function(p: Pointer; index: Integer; arridx: Integer; len: LPINT; llVal: PInt64): Pointer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF};
  _IPWorksEncrypt_EzCrypt_GetLastError:          function(p: Pointer): PLXAnsiChar; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF};
  _IPWorksEncrypt_EzCrypt_GetLastErrorCode:      function(p: Pointer): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF};
  _IPWorksEncrypt_EzCrypt_SetLastErrorAndCode:   function(p: Pointer; code: Integer; message: Pointer): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF};
  _IPWorksEncrypt_EzCrypt_GetEventError:         function(p: Pointer): PLXAnsiChar; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF};
  _IPWorksEncrypt_EzCrypt_GetEventErrorCode:     function(p: Pointer): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF};
  _IPWorksEncrypt_EzCrypt_SetEventErrorAndCode:  function(p: Pointer; code: Integer; message: Pointer): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF};
  {$IFDEF USE_EXPLICIT_INIT}
  _IPWorksEncrypt_EzCrypt_StaticInit:            function(instance: Pointer): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF};
  _IPWorksEncrypt_EzCrypt_StaticDestroy:         function(): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF};
  {$ENDIF}
  _IPWorksEncrypt_EzCrypt_CheckIndex:            function(p: Pointer; index: Integer; arridx: Integer): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF};
  _IPWorksEncrypt_EzCrypt_Do:                    function(p: Pointer; method_id: Integer; cparam: Integer; params: LPVOIDARR; cbparam: LPINTARR; llVal: PInt64): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF};
{$ELSE}
  function _IPWorksEncrypt_EvtStr                       (pEvtStr: Pointer; id: Integer; value: Pointer; opt: Integer): Pointer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF}; external DLLNAME name {$IFNDEF FPC}{$IFDEF POSIX}_PU +{$ENDIF}{$ENDIF} 'IPWorksEncrypt_EvtStr';
  function _IPWorksEncrypt_Stream                       (pStream: Pointer; op: Integer; params: LPVOIDARR; retVal: Pointer): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF}; external DLLNAME name {$IFNDEF FPC}{$IFDEF POSIX}_PU +{$ENDIF}{$ENDIF} 'IPWorksEncrypt_Stream';
  function _IPWorksEncrypt_EzCrypt_Create               (pMethod: PEventHandle; pObject: TipcEzCrypt; pKey: Pointer; opts: Integer): Pointer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF}; external DLLNAME name {$IFNDEF FPC}{$IFDEF POSIX}_PU +{$ENDIF}{$ENDIF} 'IPWorksEncrypt_EzCrypt_Create';
  function _IPWorksEncrypt_EzCrypt_Destroy              (p: Pointer): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF}; external DLLNAME name {$IFNDEF FPC}{$IFDEF POSIX}_PU +{$ENDIF}{$ENDIF} 'IPWorksEncrypt_EzCrypt_Destroy';
  function _IPWorksEncrypt_EzCrypt_Set                  (p: Pointer; index: Integer; arridx: Integer; value: Pointer; len: Cardinal): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF}; external DLLNAME name {$IFNDEF FPC}{$IFDEF POSIX}_PU +{$ENDIF}{$ENDIF} 'IPWorksEncrypt_EzCrypt_Set';
  function _IPWorksEncrypt_EzCrypt_Get                  (p: Pointer; index: Integer; arridx: Integer; len: LPINT; llVal: PInt64): Pointer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF}; external DLLNAME name {$IFNDEF FPC}{$IFDEF POSIX}_PU +{$ENDIF}{$ENDIF} 'IPWorksEncrypt_EzCrypt_Get';
  function _IPWorksEncrypt_EzCrypt_GetLastError         (p: Pointer): PLXAnsiChar; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF}; external DLLNAME name {$IFNDEF FPC}{$IFDEF POSIX}_PU +{$ENDIF}{$ENDIF} 'IPWorksEncrypt_EzCrypt_GetLastError';
  function _IPWorksEncrypt_EzCrypt_GetLastErrorCode     (p: Pointer): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF}; external DLLNAME name {$IFNDEF FPC}{$IFDEF POSIX}_PU +{$ENDIF}{$ENDIF} 'IPWorksEncrypt_EzCrypt_GetLastErrorCode';
  function _IPWorksEncrypt_EzCrypt_SetLastErrorAndCode  (p: Pointer; code: Integer; message: Pointer): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF}; external DLLNAME name {$IFNDEF FPC}{$IFDEF POSIX}_PU +{$ENDIF}{$ENDIF} 'IPWorksEncrypt_EzCrypt_SetLastErrorAndCode';
  function _IPWorksEncrypt_EzCrypt_GetEventError        (p: Pointer): PLXAnsiChar; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF}; external DLLNAME name {$IFNDEF FPC}{$IFDEF POSIX}_PU +{$ENDIF}{$ENDIF} 'IPWorksEncrypt_EzCrypt_GetEventError';
  function _IPWorksEncrypt_EzCrypt_GetEventErrorCode    (p: Pointer): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF}; external DLLNAME name {$IFNDEF FPC}{$IFDEF POSIX}_PU +{$ENDIF}{$ENDIF} 'IPWorksEncrypt_EzCrypt_GetEventErrorCode';
  function _IPWorksEncrypt_EzCrypt_SetEventErrorAndCode (p: Pointer; code: Integer; message: Pointer): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF}; external DLLNAME name {$IFNDEF FPC}{$IFDEF POSIX}_PU +{$ENDIF}{$ENDIF} 'IPWorksEncrypt_EzCrypt_SetEventErrorAndCode';
  function _IPWorksEncrypt_EzCrypt_StaticInit           (instance: Pointer): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF}; external DLLNAME name {$IFNDEF FPC}{$IFDEF POSIX}_PU +{$ENDIF}{$ENDIF} 'IPWorksEncrypt_EzCrypt_StaticInit';
  function _IPWorksEncrypt_EzCrypt_StaticDestroy        (): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF}; external DLLNAME name {$IFNDEF FPC}{$IFDEF POSIX}_PU +{$ENDIF}{$ENDIF} 'IPWorksEncrypt_EzCrypt_StaticDestroy';
  function _IPWorksEncrypt_EzCrypt_CheckIndex           (p: Pointer; index: Integer; arridx: Integer): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF}; external DLLNAME name {$IFNDEF FPC}{$IFDEF POSIX}_PU +{$ENDIF}{$ENDIF} 'IPWorksEncrypt_EzCrypt_CheckIndex';
  function _IPWorksEncrypt_EzCrypt_Do                   (p: Pointer; method_id: Integer; cparam: Integer; params: LPVOIDARR; cbparam: LPINTARR; llVal: PInt64): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF}; external DLLNAME name {$IFNDEF FPC}{$IFDEF POSIX}_PU +{$ENDIF}{$ENDIF} 'IPWorksEncrypt_EzCrypt_Do';
{$ENDIF}

{$HINTS OFF}

(*** Fire Event Methods ***)
function FireError(lpContext: TipcEzCrypt; cparam: Integer; params: LPVOIDARR; cbparam: LPINTARR): Integer;
var
  tmp_ErrorCode: Integer;
  tmp_Description: String;
begin
  result := 0;
  if not Assigned(lpContext.FOnError) then exit;

  tmp_ErrorCode := Integer(params^[0]);
  tmp_Description := {$ifdef UNICODE_ON_ANSI}FromLinuxAnsiString{$else}PChar{$endif}(params^[1]);

  try lpContext.FOnError(lpContext, tmp_ErrorCode, tmp_Description)
  except on E: Exception do result := lpContext.ReportEventException(E, 'Error', False); end;

end;

function FireProgress(lpContext: TipcEzCrypt; cparam: Integer; params: LPVOIDARR; cbparam: LPINTARR): Integer;
var
  tmp_BytesProcessed: Int64;
  tmp_PercentProcessed: Integer;
begin
  result := 0;
  if not Assigned(lpContext.FOnProgress) then exit;

  tmp_BytesProcessed := PInt64(params^[0])^;
  tmp_PercentProcessed := Integer(params^[1]);

  try lpContext.FOnProgress(lpContext, tmp_BytesProcessed, tmp_PercentProcessed)
  except on E: Exception do result := lpContext.ReportEventException(E, 'Progress'); end;

end;

function MapID2Stream(lpContext: TipcEzCrypt; params: LPVOIDARR) : TStream;
var
  streamID : Integer;
  arrayidx : Integer;
begin
  streamID := PInteger(params^[0])^;
  if (streamID and $40000000) = 0 then
  begin
    if streamID = MID_EzCrypt_SetInputStream then
    begin
      result := lpContext.m_streamFromSetInputStream;
      exit;
    end;
    if streamID = MID_EzCrypt_SetOutputStream then
    begin
      result := lpContext.m_streamFromSetOutputStream;
      exit;
    end;
  end;
  if (streamID and $40000000) = $40000000 then
  begin
    arrayidx := (streamID and $BFFFFFFF) shr 16;
    streamID := (streamID and $0000FFFF);
  
  end;
  result := nil;
end;

function FireStreamEvents_Read(lpContext: TipcEzCrypt; cparam: Integer; params: LPVOIDARR; cbparam: LPINTARR): Integer;
var
  tmp_stream: TStream;
  x: Integer;
begin
  result := 0;
  try
    tmp_stream := MapID2Stream(lpContext, params);
    if tmp_stream = nil then
    begin
      result := -10000;
      exit;
    end;
    x := tmp_stream.Read(PByte(params^[1])^, cbparam^[1]);
    cbparam^[1] := x;
  except on E: Exception do
    begin
      result := -10000;
      exit;
    end;
  end;
end;

function FireStreamEvents_Write(lpContext: TipcEzCrypt; cparam: Integer; params: LPVOIDARR; cbparam: LPINTARR): Integer;
var
  tmp_stream: TStream;
  x: Integer;
begin
  result := 0;
  try
    tmp_stream := MapID2Stream(lpContext, params);
    if tmp_stream = nil then
    begin
      result := -10000;
      exit;
    end;
    x := tmp_stream.Write(PByte(params^[1])^, cbparam^[1]);
    cbparam^[1] := x;
  except on E: Exception do
    begin
      result := -10000;
      exit;
    end;
  end;
end;

function FireStreamEvents_Size(lpContext: TipcEzCrypt; cparam: Integer; params: LPVOIDARR; cbparam: LPINTARR): Integer;
var
  tmp_stream: TStream;
begin
  result := 0;
  try
    tmp_stream := MapID2Stream(lpContext, params);
    if tmp_stream = nil then
    begin
      result := -10000;
      exit;
    end;
    (PInt64(params^[1]))^ := tmp_stream.Size;
  except on E: Exception do
    begin
      result := -10000;
      exit;
    end;
  end;
end;

function FireStreamEvents_Close(lpContext: TipcEzCrypt; cparam: Integer; params: LPVOIDARR; cbparam: LPINTARR): Integer;
var
  tmp_stream: TStream;
begin
  result := 0;
  try
    tmp_stream := MapID2Stream(lpContext, params);
    if tmp_stream = nil then
    begin
      result := -10000;
      exit;
    end;
    tmp_stream.Free;
  except on E: Exception do
    begin
      result := -10000;
      exit;
    end;
  end;
end;

function FireStreamEvents_Seek(lpContext: TipcEzCrypt; cparam: Integer; params: LPVOIDARR; cbparam: LPINTARR): Integer;
var 
  tmp_stream: TStream;
  tmp_seeklen: Integer;
  tmp_seekpos: Integer;
  x: Int64;
begin
  result := 0;
  try
    tmp_stream := MapID2Stream(lpContext, params);
    if tmp_stream = nil then
    begin
      result := -10000;
      exit;
    end;
    tmp_seeklen := PInt64(params^[1])^;
    tmp_seekpos := PInt64(params^[2])^;
    case tmp_seekpos of
      STREAM_SEEK_FROM_END: begin x := tmp_stream.Seek(tmp_seeklen, soEnd); end;
      STREAM_SEEK_FROM_BEGIN: begin x := tmp_stream.Seek(tmp_seeklen, soBeginning); end;
      STREAM_SEEK_FROM_CURRENT: begin x := tmp_stream.Seek(tmp_seeklen, soCurrent); end;
    end;
    (PInt64(params^[1]))^ := x;
  except on E : Exception do
    begin
      result := -10000;
      exit;
    end;
  end;
end;


(*** Event Sink ***)
function FireEvents(lpContext: TipcEzCrypt; event_id: Integer; cparam: Integer; params: LPVOIDARR; cbparam: LPINTARR): Integer; {$IFDEF USE_CDECL}cdecl{$ELSE}stdcall{$ENDIF};
var
  x: Integer;
begin
  result := 0;

  case event_id of
    EID_EzCrypt_Error: begin result := FireError(lpContext, cparam, params, cbparam); end;
    EID_EzCrypt_Progress: begin result := FireProgress(lpContext, cparam, params, cbparam); end;
    STREAM_OP_READ: begin result := FireStreamEvents_Read(lpContext, cparam, params, cbparam); end;
    STREAM_OP_WRITE: begin result := FireStreamEvents_Write(lpContext, cparam, params, cbparam); end;
    STREAM_OP_GET_LENGTH: begin result := FireStreamEvents_Size(lpContext, cparam, params, cbparam); end;
    STREAM_OP_CLOSE: begin result := FireStreamEvents_Close(lpContext, cparam, params, cbparam); end;
    STREAM_OP_SEEK: begin result := FireStreamEvents_Seek(lpContext, cparam, params, cbparam); end;
    99999: begin x := 0; end;
  end;
end;

procedure Register;
begin
  ipcCore.Register;
  RegisterComponents('IPWorks Encrypt', [TipcEzCrypt]);
end;

{*********************************************************************************}
procedure TipcEzCrypt.SetInputMessage(lpInputMessage: PLXAnsiChar; lenInputMessage: Cardinal);
var
  err: integer;
begin
  if @_IPWorksEncrypt_EzCrypt_Set = nil then exit;
  err := _IPWorksEncrypt_EzCrypt_Set(m_ctl, PID_EzCrypt_InputMessage, 0, Pointer(lpInputMessage), lenInputMessage);
  if err <> 0 then TreatErr(err, '');
end;
procedure TipcEzCrypt.SetIV(lpIV: PLXAnsiChar; lenIV: Cardinal);
var
  err: integer;
begin
  if @_IPWorksEncrypt_EzCrypt_Set = nil then exit;
  err := _IPWorksEncrypt_EzCrypt_Set(m_ctl, PID_EzCrypt_IV, 0, Pointer(lpIV), lenIV);
  if err <> 0 then TreatErr(err, '');
end;
procedure TipcEzCrypt.SetKey(lpKey: PLXAnsiChar; lenKey: Cardinal);
var
  err: integer;
begin
  if @_IPWorksEncrypt_EzCrypt_Set = nil then exit;
  err := _IPWorksEncrypt_EzCrypt_Set(m_ctl, PID_EzCrypt_Key, 0, Pointer(lpKey), lenKey);
  if err <> 0 then TreatErr(err, '');
end;
procedure TipcEzCrypt.SetOutputMessage(lpOutputMessage: PLXAnsiChar; lenOutputMessage: Cardinal);
var
  err: integer;
begin
  if @_IPWorksEncrypt_EzCrypt_Set = nil then exit;
  err := _IPWorksEncrypt_EzCrypt_Set(m_ctl, PID_EzCrypt_OutputMessage, 0, Pointer(lpOutputMessage), lenOutputMessage);
  if err <> 0 then TreatErr(err, '');
end;
















{*********************************************************************************}

constructor TipcEzCrypt.Create(AOwner: TComponent);
begin
  Create(AOwner, IPWORKSENCRYPT_OEMKEY_25);
  Config('CodePage=65001');
end;

constructor TipcEzCrypt.Create(AOwner: TComponent; OEMKey: string);
begin
  inherited Create(AOwner);
  m_ctl := nil;

  if @_IPWorksEncrypt_EzCrypt_Create <> nil then
    m_ctl := _IPWorksEncrypt_EzCrypt_Create(@FireEvents, self, nil, CREATE_OPT);
  if m_ctl = nil then
    TreatErr(-1, 'IPWorks Encrypt EzCrypt: Error creating component');
  _IPWorksEncrypt_EzCrypt_Set(m_ctl, 255, 0, 
    {$ifdef ANSICHAR_IS_BYTE}
    Pointer(ToLinuxAnsiString(OEMKey)),
    {$else}
    Pointer(PAnsiChar(AnsiString(OEMKey))),
    {$endif}
    0);



  try set_Algorithm(ezAES) except on E:Exception do end;
  try set_CipherMode(cmCBC) except on E:Exception do end;
  try set_InputFile('') except on E:Exception do end;
  try set_InputMessage('') except on E:Exception do end;
  try set_IV('') except on E:Exception do end;
  try set_Key('') except on E:Exception do end;
  try set_KeyPassword('') except on E:Exception do end;
  try set_OutputFile('') except on E:Exception do end;
  try set_Overwrite(false) except on E:Exception do end;
  try set_PaddingMode(pmPKCS7) except on E:Exception do end;
  try set_UseHex(false) except on E:Exception do end;

end;

destructor TipcEzCrypt.Destroy;
begin

  if m_ctl <> nil then begin
    if @_IPWorksEncrypt_EzCrypt_Destroy <> nil then
      _IPWorksEncrypt_EzCrypt_Destroy(m_ctl);
  end;
  m_ctl := nil;
  inherited Destroy;
end;

function TipcEzCrypt.ThrowCoreException(err: Integer; const desc: {$ifndef NO_ANSI}AnsiString{$else}string{$endif}): EIPWorksEncrypt;
begin
  result := EipcEzCrypt.CreateCode(err, desc);
end;

function TipcEzCrypt.ReportEventException(e: Exception; Event: String; ReFire: Boolean): Integer;
var
  msg: String;
begin
  result := -1;
  msg := 'An unhandled error occurred in the ' + Event + ' event handler: ' + E.Message;

  if (m_ctl <> nil) and (@_IPWorksEncrypt_EzCrypt_SetEventErrorAndCode <> nil) then begin
    if E is EIPWorksEncrypt then begin
      result := EIPWorksEncrypt(e).Code;
      msg := E.Message;
    end;
    _IPWorksEncrypt_EzCrypt_SetEventErrorAndCode(m_ctl, result, 
      {$ifdef ANSICHAR_IS_BYTE}
      Pointer(ToLinuxAnsiString(msg)));
      {$else}
      Pointer(PAnsiChar(AnsiString(msg))));
      {$endif}
  end;
  if ReFire and Assigned(FOnError) then FOnError(self, result, msg);
end;

{*********************************************************************************}

procedure TipcEzCrypt.AboutDlg;
var
  p : LPVOIDARR;
  pc: LPINTARR;
begin
{$IFDEF LINUX}
  inherited AboutDlg;
{$ELSE}
  p := nil;
  pc := nil;
  if @_IPWorksEncrypt_EzCrypt_Do <> nil then
    _IPWorksEncrypt_EzCrypt_Do(m_ctl, 255, 0, p, pc, nil);
{$ENDIF}
end;

{*********************************************************************************}

procedure TipcEzCrypt.SetRuntimeLicense(key: String);
var
  err: Integer;
begin
  err := 0;
  if @_IPWorksEncrypt_EzCrypt_Set = nil then exit;
  err := _IPWorksEncrypt_EzCrypt_Set(m_ctl, 2011, 0, 
    {$ifdef ANSICHAR_IS_BYTE}
    Pointer(ToLinuxAnsiString(key)),
    {$else}
    Pointer(PAnsiChar(AnsiString(key))),
    {$endif}
    0);

  if err <> 0 then TreatErr(err, '');
end;

function TipcEzCrypt.GetRuntimeLicense: String;
var
  tmp: Pointer;
begin
  result := '';
  if @_IPWorksEncrypt_EzCrypt_Get = nil then exit;
  tmp := _IPWorksEncrypt_EzCrypt_Get(m_ctl, 2011, 0, nil, nil);
  {$ifdef ANSICHAR_IS_BYTE}
  result := FromLinuxAnsiString(PLXAnsiChar(tmp));
  {$else}
  result := PAnsiChar(tmp);
  {$endif}
end;

{*********************************************************************************}

function TipcEzCrypt.HasData: Boolean;
begin
  result := false;
end;

procedure TipcEzCrypt.ReadHnd(Reader: TStream);
begin
end;

procedure TipcEzCrypt.WriteHnd(Writer: TStream);
begin
end;

function TipcEzCrypt.BStr2CStr(pBStr: Pointer; lenBStr: Integer; bArr: TBytes): String;
{$IF DEFINED(UNICODE) AND DEFINED(MSWINDOWS)}
var
  param: array[0..2] of Pointer;
  paramcb: array[0..2] of Integer;
{$IFEND}
begin
{$IFDEF UNICODE}
  {$IFDEF MSWINDOWS}
  param[0] := pBStr; paramcb[0] := lenBStr;
  param[1] := nil;   paramcb[1] := 0;
  param[2] := nil;   paramcb[2] := 0;
  _IPWorksEncrypt_EzCrypt_Do(m_ctl, 2003, 2, @param, @paramcb, nil);
  SetLength(Result, Integer(param[2]));
  if Length(Result) > 0 then begin
    param[1] := PChar(Result); paramcb[1] := Length(Result);
    _IPWorksEncrypt_EzCrypt_Do(m_ctl, 2003, 2, @param, @paramcb, nil);
  end;
  {$ELSE}
  Result := TEncoding.Default.GetString(bArr);
  {$ENDIF}
{$ELSE}
  SetString(Result, PAnsiChar(pBStr), lenBStr);
{$ENDIF}
end;

procedure TipcEzCrypt.DefineProperties(Filer: TFiler);
begin
  inherited DefineProperties(Filer);
  Filer.DefineBinaryProperty('RegHnd', ReadHnd, WriteHnd, HasData);
end;

{*********************************************************************************}

procedure TipcEzCrypt.TreatErr(Err: Integer; const desc: String);
var
  msg : {$ifdef NO_ANSI}string{$else}LXAnsiString{$endif};
begin
  {$ifdef NO_ANSI}
  msg := desc;
  {$else}
  {$ifdef ANSICHAR_IS_BYTE}
  msg := ToLinuxAnsiString(desc);
  {$else}
  msg := LXAnsiString(desc);
  {$endif}
  {$endif}
  if Length(msg) = 0 then
  begin
    if @_IPWorksEncrypt_EzCrypt_GetLastError <> nil then
      {$ifdef NO_ANSI}
      {$ifdef ANSICHAR_IS_BYTE}
      msg := FromLinuxAnsiString(_IPWorksEncrypt_EzCrypt_GetLastError(m_ctl));
      {$else}
      msg := _IPWorksEncrypt_EzCrypt_GetLastError(m_ctl);
      {$endif}
      {$else}
      msg := _IPWorksEncrypt_EzCrypt_GetLastError(m_ctl);
      {$endif}
  end;

  raise ThrowCoreException(err, msg);
end;

{*********************************************************************************}

(*** Property Getters/Setters ***)
function TipcEzCrypt.get_Algorithm: TipcezcryptAlgorithms;
var
  tmp: Pointer;
begin
  result := TipcezcryptAlgorithms(0);

  if @_IPWorksEncrypt_EzCrypt_Get = nil then exit;
  tmp := _IPWorksEncrypt_EzCrypt_Get(m_ctl, PID_EzCrypt_Algorithm, 0, nil, nil);
  result := TipcezcryptAlgorithms(tmp);
end;

procedure TipcEzCrypt.set_Algorithm(valAlgorithm: TipcezcryptAlgorithms);
var
  err: Integer;
begin
  err := 0;
  if @_IPWorksEncrypt_EzCrypt_Set = nil then exit;
  err := _IPWorksEncrypt_EzCrypt_Set(m_ctl, PID_EzCrypt_Algorithm, 0, Pointer(valAlgorithm), 0);
  if err <> 0 then TreatErr(err, '');
end;

function TipcEzCrypt.get_CipherMode: TipcezcryptCipherModes;
var
  tmp: Pointer;
begin
  result := TipcezcryptCipherModes(0);

  if @_IPWorksEncrypt_EzCrypt_Get = nil then exit;
  tmp := _IPWorksEncrypt_EzCrypt_Get(m_ctl, PID_EzCrypt_CipherMode, 0, nil, nil);
  result := TipcezcryptCipherModes(tmp);
end;

procedure TipcEzCrypt.set_CipherMode(valCipherMode: TipcezcryptCipherModes);
var
  err: Integer;
begin
  err := 0;
  if @_IPWorksEncrypt_EzCrypt_Set = nil then exit;
  err := _IPWorksEncrypt_EzCrypt_Set(m_ctl, PID_EzCrypt_CipherMode, 0, Pointer(valCipherMode), 0);
  if err <> 0 then TreatErr(err, '');
end;

function TipcEzCrypt.get_InputFile: String;
var
  tmp: Pointer;
begin
  result := '';

  if @_IPWorksEncrypt_EzCrypt_Get = nil then exit;
  tmp := _IPWorksEncrypt_EzCrypt_Get(m_ctl, PID_EzCrypt_InputFile{$IFDEF UNICODE_ON_UNICODE}+10000{$ENDIF}, 0, nil, nil);
  result := {$ifndef UNICODE_ON_ANSI}PChar{$else}FromLinuxAnsiString{$endif}(tmp);
end;

procedure TipcEzCrypt.set_InputFile(valInputFile: String);
var
  err: Integer;
  {$IFDEF UNICODE_ON_ANSI}tmp: LXAnsiString;{$ENDIF}
begin
  err := 0;
  if @_IPWorksEncrypt_EzCrypt_Set = nil then exit;
  {$IFDEF UNICODE_ON_ANSI}
  tmp := ToLinuxAnsiString(valInputFile);
  {$ENDIF}
  err := _IPWorksEncrypt_EzCrypt_Set(m_ctl, PID_EzCrypt_InputFile{$IFDEF UNICODE_ON_UNICODE}+10000{$ENDIF}, 0, 
    Pointer({$ifndef UNICODE_ON_ANSI}PChar(valInputFile){$else}@tmp[0]{$endif}), 0);

  if err <> 0 then TreatErr(err, '');
end;

function TipcEzCrypt.get_InputMessage: String;
var
  tmp: {$IFDEF NONWINUNICODE}TBytes{$ELSE}Pointer; len: Cardinal{$ENDIF};
begin
  result := '';

  if @_IPWorksEncrypt_EzCrypt_Get = nil then exit;
  tmp := {$IFDEF NONWINUNICODE}get_InputMessageB{$ELSE}_IPWorksEncrypt_EzCrypt_Get(m_ctl, PID_EzCrypt_InputMessage{$IFDEF UNICODE_ON_UNICODE}+20000{$ENDIF}, 0, @len, nil){$ENDIF};
  {$IFDEF NONWINUNICODE}result := TEncoding.UTF8.GetString(tmp);{$ELSE}SetString(result, PChar(tmp), len);{$ENDIF}
end;

procedure TipcEzCrypt.set_InputMessage(valInputMessage: String);
var
  err: Integer;
  {$IFDEF NONWINUNICODE}tmp: TBytes;{$ENDIF}
begin
  err := 0;
  if @_IPWorksEncrypt_EzCrypt_Set = nil then exit;
{$IFDEF UNICODE}
  {$IFDEF MSWINDOWS}
  err := _IPWorksEncrypt_EzCrypt_Set(m_ctl, PID_EzCrypt_InputMessage+20000, 0, Pointer(PWideChar(valInputMessage)), Length(valInputMessage));
  {$ELSE}
  tmp := TEncoding.UTF8.GetBytes(valInputMessage);
  set_InputMessageB(tmp);
  {$ENDIF}
{$ELSE}
  err := _IPWorksEncrypt_EzCrypt_Set(m_ctl, PID_EzCrypt_InputMessage, 0, Pointer(PAnsiChar(valInputMessage)), Length(valInputMessage));
{$ENDIF}

  if err <> 0 then TreatErr(err, '');
end;

function TipcEzCrypt.get_InputMessageB: TBytes;
var
  tmp: Pointer;
  len: Cardinal;
begin
  result := nil;

  if @_IPWorksEncrypt_EzCrypt_Get = nil then exit;
  tmp := _IPWorksEncrypt_EzCrypt_Get(m_ctl, PID_EzCrypt_InputMessage, 0, @len, nil);
  SetLength(result, len);
  Move(Pointer(tmp)^, Pointer(result)^, len); // IMPORTANT: Do NOT multiply the length value!
end;

procedure TipcEzCrypt.set_InputMessageB(valInputMessage: TBytes);
var
  err: Integer;
begin
  err := _IPWorksEncrypt_EzCrypt_Set(m_ctl, PID_EzCrypt_InputMessage, 0, Pointer(valInputMessage), Length(valInputMessage));
  if err <> 0 then TreatErr(err, '');
end;

function TipcEzCrypt.get_IV: String;
var
  tmp: {$IFDEF NONWINUNICODE}TBytes{$ELSE}Pointer; len: Cardinal{$ENDIF};
begin
  result := '';

  if @_IPWorksEncrypt_EzCrypt_Get = nil then exit;
  tmp := {$IFDEF NONWINUNICODE}get_IVB{$ELSE}_IPWorksEncrypt_EzCrypt_Get(m_ctl, PID_EzCrypt_IV{$IFDEF UNICODE_ON_UNICODE}+20000{$ENDIF}, 0, @len, nil){$ENDIF};
  {$IFDEF NONWINUNICODE}result := TEncoding.UTF8.GetString(tmp);{$ELSE}SetString(result, PChar(tmp), len);{$ENDIF}
end;

procedure TipcEzCrypt.set_IV(valIV: String);
var
  err: Integer;
  {$IFDEF NONWINUNICODE}tmp: TBytes;{$ENDIF}
begin
  err := 0;
  if @_IPWorksEncrypt_EzCrypt_Set = nil then exit;
{$IFDEF UNICODE}
  {$IFDEF MSWINDOWS}
  err := _IPWorksEncrypt_EzCrypt_Set(m_ctl, PID_EzCrypt_IV+20000, 0, Pointer(PWideChar(valIV)), Length(valIV));
  {$ELSE}
  tmp := TEncoding.UTF8.GetBytes(valIV);
  set_IVB(tmp);
  {$ENDIF}
{$ELSE}
  err := _IPWorksEncrypt_EzCrypt_Set(m_ctl, PID_EzCrypt_IV, 0, Pointer(PAnsiChar(valIV)), Length(valIV));
{$ENDIF}

  if err <> 0 then TreatErr(err, '');
end;

function TipcEzCrypt.get_IVB: TBytes;
var
  tmp: Pointer;
  len: Cardinal;
begin
  result := nil;

  if @_IPWorksEncrypt_EzCrypt_Get = nil then exit;
  tmp := _IPWorksEncrypt_EzCrypt_Get(m_ctl, PID_EzCrypt_IV, 0, @len, nil);
  SetLength(result, len);
  Move(Pointer(tmp)^, Pointer(result)^, len); // IMPORTANT: Do NOT multiply the length value!
end;

procedure TipcEzCrypt.set_IVB(valIV: TBytes);
var
  err: Integer;
begin
  err := _IPWorksEncrypt_EzCrypt_Set(m_ctl, PID_EzCrypt_IV, 0, Pointer(valIV), Length(valIV));
  if err <> 0 then TreatErr(err, '');
end;

function TipcEzCrypt.get_Key: String;
var
  tmp: {$IFDEF NONWINUNICODE}TBytes{$ELSE}Pointer; len: Cardinal{$ENDIF};
begin
  result := '';

  if @_IPWorksEncrypt_EzCrypt_Get = nil then exit;
  tmp := {$IFDEF NONWINUNICODE}get_KeyB{$ELSE}_IPWorksEncrypt_EzCrypt_Get(m_ctl, PID_EzCrypt_Key{$IFDEF UNICODE_ON_UNICODE}+20000{$ENDIF}, 0, @len, nil){$ENDIF};
  {$IFDEF NONWINUNICODE}result := TEncoding.UTF8.GetString(tmp);{$ELSE}SetString(result, PChar(tmp), len);{$ENDIF}
end;

procedure TipcEzCrypt.set_Key(valKey: String);
var
  err: Integer;
  {$IFDEF NONWINUNICODE}tmp: TBytes;{$ENDIF}
begin
  err := 0;
  if @_IPWorksEncrypt_EzCrypt_Set = nil then exit;
{$IFDEF UNICODE}
  {$IFDEF MSWINDOWS}
  err := _IPWorksEncrypt_EzCrypt_Set(m_ctl, PID_EzCrypt_Key+20000, 0, Pointer(PWideChar(valKey)), Length(valKey));
  {$ELSE}
  tmp := TEncoding.UTF8.GetBytes(valKey);
  set_KeyB(tmp);
  {$ENDIF}
{$ELSE}
  err := _IPWorksEncrypt_EzCrypt_Set(m_ctl, PID_EzCrypt_Key, 0, Pointer(PAnsiChar(valKey)), Length(valKey));
{$ENDIF}

  if err <> 0 then TreatErr(err, '');
end;

function TipcEzCrypt.get_KeyB: TBytes;
var
  tmp: Pointer;
  len: Cardinal;
begin
  result := nil;

  if @_IPWorksEncrypt_EzCrypt_Get = nil then exit;
  tmp := _IPWorksEncrypt_EzCrypt_Get(m_ctl, PID_EzCrypt_Key, 0, @len, nil);
  SetLength(result, len);
  Move(Pointer(tmp)^, Pointer(result)^, len); // IMPORTANT: Do NOT multiply the length value!
end;

procedure TipcEzCrypt.set_KeyB(valKey: TBytes);
var
  err: Integer;
begin
  err := _IPWorksEncrypt_EzCrypt_Set(m_ctl, PID_EzCrypt_Key, 0, Pointer(valKey), Length(valKey));
  if err <> 0 then TreatErr(err, '');
end;

function TipcEzCrypt.get_KeyPassword: String;
var
  tmp: Pointer;
begin
  result := '';

  if @_IPWorksEncrypt_EzCrypt_Get = nil then exit;
  tmp := _IPWorksEncrypt_EzCrypt_Get(m_ctl, PID_EzCrypt_KeyPassword{$IFDEF UNICODE_ON_UNICODE}+10000{$ENDIF}, 0, nil, nil);
  result := {$ifndef UNICODE_ON_ANSI}PChar{$else}FromLinuxAnsiString{$endif}(tmp);
end;

procedure TipcEzCrypt.set_KeyPassword(valKeyPassword: String);
var
  err: Integer;
  {$IFDEF UNICODE_ON_ANSI}tmp: LXAnsiString;{$ENDIF}
begin
  err := 0;
  if @_IPWorksEncrypt_EzCrypt_Set = nil then exit;
  {$IFDEF UNICODE_ON_ANSI}
  tmp := ToLinuxAnsiString(valKeyPassword);
  {$ENDIF}
  err := _IPWorksEncrypt_EzCrypt_Set(m_ctl, PID_EzCrypt_KeyPassword{$IFDEF UNICODE_ON_UNICODE}+10000{$ENDIF}, 0, 
    Pointer({$ifndef UNICODE_ON_ANSI}PChar(valKeyPassword){$else}@tmp[0]{$endif}), 0);

  if err <> 0 then TreatErr(err, '');
end;

function TipcEzCrypt.get_OutputFile: String;
var
  tmp: Pointer;
begin
  result := '';

  if @_IPWorksEncrypt_EzCrypt_Get = nil then exit;
  tmp := _IPWorksEncrypt_EzCrypt_Get(m_ctl, PID_EzCrypt_OutputFile{$IFDEF UNICODE_ON_UNICODE}+10000{$ENDIF}, 0, nil, nil);
  result := {$ifndef UNICODE_ON_ANSI}PChar{$else}FromLinuxAnsiString{$endif}(tmp);
end;

procedure TipcEzCrypt.set_OutputFile(valOutputFile: String);
var
  err: Integer;
  {$IFDEF UNICODE_ON_ANSI}tmp: LXAnsiString;{$ENDIF}
begin
  err := 0;
  if @_IPWorksEncrypt_EzCrypt_Set = nil then exit;
  {$IFDEF UNICODE_ON_ANSI}
  tmp := ToLinuxAnsiString(valOutputFile);
  {$ENDIF}
  err := _IPWorksEncrypt_EzCrypt_Set(m_ctl, PID_EzCrypt_OutputFile{$IFDEF UNICODE_ON_UNICODE}+10000{$ENDIF}, 0, 
    Pointer({$ifndef UNICODE_ON_ANSI}PChar(valOutputFile){$else}@tmp[0]{$endif}), 0);

  if err <> 0 then TreatErr(err, '');
end;

function TipcEzCrypt.get_OutputMessage: String;
var
  tmp: {$IFDEF NONWINUNICODE}TBytes{$ELSE}Pointer; len: Cardinal{$ENDIF};
begin
  result := '';

  if @_IPWorksEncrypt_EzCrypt_Get = nil then exit;
  tmp := {$IFDEF NONWINUNICODE}get_OutputMessageB{$ELSE}_IPWorksEncrypt_EzCrypt_Get(m_ctl, PID_EzCrypt_OutputMessage{$IFDEF UNICODE_ON_UNICODE}+20000{$ENDIF}, 0, @len, nil){$ENDIF};
  {$IFDEF NONWINUNICODE}result := TEncoding.UTF8.GetString(tmp);{$ELSE}SetString(result, PChar(tmp), len);{$ENDIF}
end;

function TipcEzCrypt.get_OutputMessageB: TBytes;
var
  tmp: Pointer;
  len: Cardinal;
begin
  result := nil;

  if @_IPWorksEncrypt_EzCrypt_Get = nil then exit;
  tmp := _IPWorksEncrypt_EzCrypt_Get(m_ctl, PID_EzCrypt_OutputMessage, 0, @len, nil);
  SetLength(result, len);
  Move(Pointer(tmp)^, Pointer(result)^, len); // IMPORTANT: Do NOT multiply the length value!
end;

function TipcEzCrypt.get_Overwrite: Boolean;
var
  tmp: Pointer;
begin
  result := Boolean(0);

  if @_IPWorksEncrypt_EzCrypt_Get = nil then exit;
  tmp := _IPWorksEncrypt_EzCrypt_Get(m_ctl, PID_EzCrypt_Overwrite, 0, nil, nil);
  result := Boolean(tmp);
end;

procedure TipcEzCrypt.set_Overwrite(valOverwrite: Boolean);
var
  err: Integer;
begin
  err := 0;
  if @_IPWorksEncrypt_EzCrypt_Set = nil then exit;
  err := _IPWorksEncrypt_EzCrypt_Set(m_ctl, PID_EzCrypt_Overwrite, 0, Pointer(valOverwrite), 0);
  if err <> 0 then TreatErr(err, '');
end;

function TipcEzCrypt.get_PaddingMode: TipcezcryptPaddingModes;
var
  tmp: Pointer;
begin
  result := TipcezcryptPaddingModes(0);

  if @_IPWorksEncrypt_EzCrypt_Get = nil then exit;
  tmp := _IPWorksEncrypt_EzCrypt_Get(m_ctl, PID_EzCrypt_PaddingMode, 0, nil, nil);
  result := TipcezcryptPaddingModes(tmp);
end;

procedure TipcEzCrypt.set_PaddingMode(valPaddingMode: TipcezcryptPaddingModes);
var
  err: Integer;
begin
  err := 0;
  if @_IPWorksEncrypt_EzCrypt_Set = nil then exit;
  err := _IPWorksEncrypt_EzCrypt_Set(m_ctl, PID_EzCrypt_PaddingMode, 0, Pointer(valPaddingMode), 0);
  if err <> 0 then TreatErr(err, '');
end;

function TipcEzCrypt.get_UseHex: Boolean;
var
  tmp: Pointer;
begin
  result := Boolean(0);

  if @_IPWorksEncrypt_EzCrypt_Get = nil then exit;
  tmp := _IPWorksEncrypt_EzCrypt_Get(m_ctl, PID_EzCrypt_UseHex, 0, nil, nil);
  result := Boolean(tmp);
end;

procedure TipcEzCrypt.set_UseHex(valUseHex: Boolean);
var
  err: Integer;
begin
  err := 0;
  if @_IPWorksEncrypt_EzCrypt_Set = nil then exit;
  err := _IPWorksEncrypt_EzCrypt_Set(m_ctl, PID_EzCrypt_UseHex, 0, Pointer(valUseHex), 0);
  if err <> 0 then TreatErr(err, '');
end;



{*********************************************************************************}

(*** Property Getters/Setters: OO API ***)


{*********************************************************************************}

{$IFNDEF DELPHI3}
(*** Methods ***)
function TipcEzCrypt.Config(ConfigurationString: String): String;
var
  param: array[0..1] of Pointer;
  paramcb: array[0..1] of Integer;
  i, err: Integer;
  tmp_ConfigurationString: {$ifndef UNICODE_ON_ANSI}string{$else}LXAnsiString{$endif};
begin
{$IFDEF WIN64}
  m_ctl := m_ctl; //Without this, the method can't be invoked correctly in 64bit. (Delphi XE Version 16.0.4115.38113)
{$ENDIF}
  for i := 0 to 1 do 
  begin
    param[i] := nil;
    paramcb[i] := 0;
  end;
   
  result := '';

  tmp_ConfigurationString := {$ifndef UNICODE_ON_ANSI}ConfigurationString{$else}ToLinuxAnsiString(ConfigurationString){$endif};
  param[0] := {$ifndef UNICODE_ON_ANSI}PChar(tmp_ConfigurationString){$else}@tmp_ConfigurationString[0]{$endif};


  if @_IPWorksEncrypt_EzCrypt_Do = nil then exit;
  err := _IPWorksEncrypt_EzCrypt_Do(m_ctl, MID_EzCrypt_Config{$IFDEF UNICODE_ON_UNICODE}+10000{$ENDIF}, 1, @param, @paramcb, nil);
  if err <> 0 then TreatErr(err, '');

  result := {$ifdef UNICODE_ON_ANSI}FromLinuxAnsiString{$else}PChar{$endif}(param[1]);
end;

procedure TipcEzCrypt.Decrypt();
var
  param: array[0..0] of Pointer;
  paramcb: array[0..0] of Integer;
  i, err: Integer;
begin
{$IFDEF WIN64}
  m_ctl := m_ctl; //Without this, the method can't be invoked correctly in 64bit. (Delphi XE Version 16.0.4115.38113)
{$ENDIF}
  for i := 0 to 0 do 
  begin
    param[i] := nil;
    paramcb[i] := 0;
  end;
  


  if @_IPWorksEncrypt_EzCrypt_Do = nil then exit;
  err := _IPWorksEncrypt_EzCrypt_Do(m_ctl, MID_EzCrypt_Decrypt{$IFDEF UNICODE_ON_UNICODE}+10000{$ENDIF}, 0, @param, @paramcb, nil);
  if err <> 0 then TreatErr(err, '');

end;

function TipcEzCrypt.DecryptBlock(InputBuffer: TBytes; LastBlock: Boolean): TBytes;
var
  param: array[0..2] of Pointer;
  paramcb: array[0..2] of Integer;
  i, err: Integer;
begin
{$IFDEF WIN64}
  m_ctl := m_ctl; //Without this, the method can't be invoked correctly in 64bit. (Delphi XE Version 16.0.4115.38113)
{$ENDIF}
  for i := 0 to 2 do 
  begin
    param[i] := nil;
    paramcb[i] := 0;
  end;
   
  result := nil;

  param[0] := Pointer(InputBuffer);
  paramcb[0] := Length(InputBuffer);

  param[1] := Pointer(LastBlock);


  if @_IPWorksEncrypt_EzCrypt_Do = nil then exit;
  err := _IPWorksEncrypt_EzCrypt_Do(m_ctl, MID_EzCrypt_DecryptBlock{$IFDEF UNICODE_ON_UNICODE}+10000{$ENDIF}, 2, @param, @paramcb, nil);
  if err <> 0 then TreatErr(err, '');

  SetLength(result, paramcb[2]);
  Move(Pointer(param[2])^, Pointer(result)^, paramcb[2]); // IMPORTANT: Do NOT multiply the length value!
end;

procedure TipcEzCrypt.Encrypt();
var
  param: array[0..0] of Pointer;
  paramcb: array[0..0] of Integer;
  i, err: Integer;
begin
{$IFDEF WIN64}
  m_ctl := m_ctl; //Without this, the method can't be invoked correctly in 64bit. (Delphi XE Version 16.0.4115.38113)
{$ENDIF}
  for i := 0 to 0 do 
  begin
    param[i] := nil;
    paramcb[i] := 0;
  end;
  


  if @_IPWorksEncrypt_EzCrypt_Do = nil then exit;
  err := _IPWorksEncrypt_EzCrypt_Do(m_ctl, MID_EzCrypt_Encrypt{$IFDEF UNICODE_ON_UNICODE}+10000{$ENDIF}, 0, @param, @paramcb, nil);
  if err <> 0 then TreatErr(err, '');

end;

function TipcEzCrypt.EncryptBlock(InputBuffer: TBytes; LastBlock: Boolean): TBytes;
var
  param: array[0..2] of Pointer;
  paramcb: array[0..2] of Integer;
  i, err: Integer;
begin
{$IFDEF WIN64}
  m_ctl := m_ctl; //Without this, the method can't be invoked correctly in 64bit. (Delphi XE Version 16.0.4115.38113)
{$ENDIF}
  for i := 0 to 2 do 
  begin
    param[i] := nil;
    paramcb[i] := 0;
  end;
   
  result := nil;

  param[0] := Pointer(InputBuffer);
  paramcb[0] := Length(InputBuffer);

  param[1] := Pointer(LastBlock);


  if @_IPWorksEncrypt_EzCrypt_Do = nil then exit;
  err := _IPWorksEncrypt_EzCrypt_Do(m_ctl, MID_EzCrypt_EncryptBlock{$IFDEF UNICODE_ON_UNICODE}+10000{$ENDIF}, 2, @param, @paramcb, nil);
  if err <> 0 then TreatErr(err, '');

  SetLength(result, paramcb[2]);
  Move(Pointer(param[2])^, Pointer(result)^, paramcb[2]); // IMPORTANT: Do NOT multiply the length value!
end;

procedure TipcEzCrypt.Reset();
var
  param: array[0..0] of Pointer;
  paramcb: array[0..0] of Integer;
  i, err: Integer;
begin
{$IFDEF WIN64}
  m_ctl := m_ctl; //Without this, the method can't be invoked correctly in 64bit. (Delphi XE Version 16.0.4115.38113)
{$ENDIF}
  for i := 0 to 0 do 
  begin
    param[i] := nil;
    paramcb[i] := 0;
  end;
  


  if @_IPWorksEncrypt_EzCrypt_Do = nil then exit;
  err := _IPWorksEncrypt_EzCrypt_Do(m_ctl, MID_EzCrypt_Reset{$IFDEF UNICODE_ON_UNICODE}+10000{$ENDIF}, 0, @param, @paramcb, nil);
  if err <> 0 then TreatErr(err, '');

end;

procedure TipcEzCrypt.SetInputStream(InputStream: TStream);
var
  param: array[0..1] of Pointer;
  paramcb: array[0..1] of Integer;
  i, err: Integer;
begin
{$IFDEF WIN64}
  m_ctl := m_ctl; //Without this, the method can't be invoked correctly in 64bit. (Delphi XE Version 16.0.4115.38113)
{$ENDIF}
  for i := 0 to 1 do 
  begin
    param[i] := nil;
    paramcb[i] := 0;
  end;
  

  if InputStream <> nil then param[0] := Pointer(1);
  m_streamFromSetInputStream := InputStream;


  if @_IPWorksEncrypt_EzCrypt_Do = nil then exit;
  err := _IPWorksEncrypt_EzCrypt_Do(m_ctl, MID_EzCrypt_SetInputStream{$IFDEF UNICODE_ON_UNICODE}+10000{$ENDIF}, 1, @param, @paramcb, nil);
  if err <> 0 then TreatErr(err, '');

end;

procedure TipcEzCrypt.SetOutputStream(OutputStream: TStream);
var
  param: array[0..1] of Pointer;
  paramcb: array[0..1] of Integer;
  i, err: Integer;
begin
{$IFDEF WIN64}
  m_ctl := m_ctl; //Without this, the method can't be invoked correctly in 64bit. (Delphi XE Version 16.0.4115.38113)
{$ENDIF}
  for i := 0 to 1 do 
  begin
    param[i] := nil;
    paramcb[i] := 0;
  end;
  

  if OutputStream <> nil then param[0] := Pointer(1);
  m_streamFromSetOutputStream := OutputStream;


  if @_IPWorksEncrypt_EzCrypt_Do = nil then exit;
  err := _IPWorksEncrypt_EzCrypt_Do(m_ctl, MID_EzCrypt_SetOutputStream{$IFDEF UNICODE_ON_UNICODE}+10000{$ENDIF}, 1, @param, @paramcb, nil);
  if err <> 0 then TreatErr(err, '');

end;

{$ENDIF}


{$IFDEF USE_DYNAMIC_LOADING}

procedure ClearProcs();
begin
  _IPWorksEncrypt_EvtStr := nil;
  _IPWorksEncrypt_Stream := nil;
  _IPWorksEncrypt_EzCrypt_Create := nil;
  _IPWorksEncrypt_EzCrypt_Destroy := nil;
  _IPWorksEncrypt_EzCrypt_Set := nil;
  _IPWorksEncrypt_EzCrypt_Get := nil;
  _IPWorksEncrypt_EzCrypt_GetLastError := nil;
  _IPWorksEncrypt_EzCrypt_GetLastErrorCode := nil;
  _IPWorksEncrypt_EzCrypt_SetLastErrorAndCode := nil;
  _IPWorksEncrypt_EzCrypt_GetEventError := nil;
  _IPWorksEncrypt_EzCrypt_GetEventErrorCode := nil;
  _IPWorksEncrypt_EzCrypt_SetEventErrorAndCode := nil;
  {$IFDEF USE_EXPLICIT_INIT}
  _IPWorksEncrypt_EzCrypt_StaticInit := nil;
  _IPWorksEncrypt_EzCrypt_StaticDestroy := nil;
  {$ENDIF}
  _IPWorksEncrypt_EzCrypt_CheckIndex := nil;
  _IPWorksEncrypt_EzCrypt_Do := nil;
end;

{$IFDEF USEIPWORKSENCRYPTDLL}
procedure LoadDLL();
begin
  ClearProcs();

  hLib := LoadLibrary(PChar(DLLNAME));
  if hLib = 0 then exit;

  @_IPWorksEncrypt_EvtStr                       := {$ifndef FPC}GetProcAddress{$else}GetProcedureAddress{$endif}(hLib, 'IPWorksEncrypt_EvtStr');
  @_IPWorksEncrypt_Stream                       := {$ifndef FPC}GetProcAddress{$else}GetProcedureAddress{$endif}(hLib, 'IPWorksEncrypt_Stream');
  @_IPWorksEncrypt_EzCrypt_Create               := {$ifndef FPC}GetProcAddress{$else}GetProcedureAddress{$endif}(hLib, 'IPWorksEncrypt_EzCrypt_Create');
  @_IPWorksEncrypt_EzCrypt_Destroy              := {$ifndef FPC}GetProcAddress{$else}GetProcedureAddress{$endif}(hLib, 'IPWorksEncrypt_EzCrypt_Destroy');
  @_IPWorksEncrypt_EzCrypt_Set                  := {$ifndef FPC}GetProcAddress{$else}GetProcedureAddress{$endif}(hLib, 'IPWorksEncrypt_EzCrypt_Set');
  @_IPWorksEncrypt_EzCrypt_Get                  := {$ifndef FPC}GetProcAddress{$else}GetProcedureAddress{$endif}(hLib, 'IPWorksEncrypt_EzCrypt_Get');
  @_IPWorksEncrypt_EzCrypt_GetLastError         := {$ifndef FPC}GetProcAddress{$else}GetProcedureAddress{$endif}(hLib, 'IPWorksEncrypt_EzCrypt_GetLastError');
  @_IPWorksEncrypt_EzCrypt_GetLastErrorCode     := {$ifndef FPC}GetProcAddress{$else}GetProcedureAddress{$endif}(hLib, 'IPWorksEncrypt_EzCrypt_GetLastErrorCode');
  @_IPWorksEncrypt_EzCrypt_SetLastErrorAndCode  := {$ifndef FPC}GetProcAddress{$else}GetProcedureAddress{$endif}(hLib, 'IPWorksEncrypt_EzCrypt_SetLastErrorAndCode');
  @_IPWorksEncrypt_EzCrypt_GetEventError        := {$ifndef FPC}GetProcAddress{$else}GetProcedureAddress{$endif}(hLib, 'IPWorksEncrypt_EzCrypt_GetEventError');
  @_IPWorksEncrypt_EzCrypt_GetEventErrorCode    := {$ifndef FPC}GetProcAddress{$else}GetProcedureAddress{$endif}(hLib, 'IPWorksEncrypt_EzCrypt_GetEventErrorCode');
  @_IPWorksEncrypt_EzCrypt_SetEventErrorAndCode := {$ifndef FPC}GetProcAddress{$else}GetProcedureAddress{$endif}(hLib, 'IPWorksEncrypt_EzCrypt_SetEventErrorAndCode');
  {$IFDEF USE_EXPLICIT_INIT}
  @_IPWorksEncrypt_EzCrypt_StaticInit           := {$ifndef FPC}GetProcAddress{$else}GetProcedureAddress{$endif}(hLib, 'IPWorksEncrypt_EzCrypt_StaticInit');
  @_IPWorksEncrypt_EzCrypt_StaticDestroy        := {$ifndef FPC}GetProcAddress{$else}GetProcedureAddress{$endif}(hLib, 'IPWorksEncrypt_EzCrypt_StaticDestroy');
  {$ENDIF}
  @_IPWorksEncrypt_EzCrypt_CheckIndex           := {$ifndef FPC}GetProcAddress{$else}GetProcedureAddress{$endif}(hLib, 'IPWorksEncrypt_EzCrypt_CheckIndex');
  @_IPWorksEncrypt_EzCrypt_Do                   := {$ifndef FPC}GetProcAddress{$else}GetProcedureAddress{$endif}(hLib, 'IPWorksEncrypt_EzCrypt_Do');
end;
{$ELSE}
procedure LoadRESDLL();
var
  hResInfo: HRSRC;
  hResData: HGLOBAL;
  pResData: Pointer;
begin
  ClearProcs();

  hResInfo := FindResource(HInstance, 'ipworksencrypt20_dta', RT_RCDATA);
  if hResInfo = 0 then exit;

  hResData := LoadResource(HInstance, hResInfo);
  if hResData = 0 then exit;

  pResData := LockResource(hResData);
  if pResData = nil then exit;

  pBaseAddress := IPWorksEncryptLoadDRU(pResData, pEntryPoint);
  if Assigned(pBaseAddress) then begin
    @_IPWorksEncrypt_EvtStr                       := IPWorksEncryptFindFunc(pBaseAddress, 'IPWorksEncrypt_EvtStr');
    @_IPWorksEncrypt_Stream                       := IPWorksEncryptFindFunc(pBaseAddress, 'IPWorksEncrypt_Stream');
    @_IPWorksEncrypt_EzCrypt_Create               := IPWorksEncryptFindFunc(pBaseAddress, 'IPWorksEncrypt_EzCrypt_Create');
    @_IPWorksEncrypt_EzCrypt_Destroy              := IPWorksEncryptFindFunc(pBaseAddress, 'IPWorksEncrypt_EzCrypt_Destroy');
    @_IPWorksEncrypt_EzCrypt_Set                  := IPWorksEncryptFindFunc(pBaseAddress, 'IPWorksEncrypt_EzCrypt_Set');
    @_IPWorksEncrypt_EzCrypt_Get                  := IPWorksEncryptFindFunc(pBaseAddress, 'IPWorksEncrypt_EzCrypt_Get');
    @_IPWorksEncrypt_EzCrypt_GetLastError         := IPWorksEncryptFindFunc(pBaseAddress, 'IPWorksEncrypt_EzCrypt_GetLastError');
    @_IPWorksEncrypt_EzCrypt_GetLastErrorCode     := IPWorksEncryptFindFunc(pBaseAddress, 'IPWorksEncrypt_EzCrypt_GetLastErrorCode');
    @_IPWorksEncrypt_EzCrypt_SetLastErrorAndCode  := IPWorksEncryptFindFunc(pBaseAddress, 'IPWorksEncrypt_EzCrypt_SetLastErrorAndCode');
    @_IPWorksEncrypt_EzCrypt_GetEventError        := IPWorksEncryptFindFunc(pBaseAddress, 'IPWorksEncrypt_EzCrypt_GetEventError');
    @_IPWorksEncrypt_EzCrypt_GetEventErrorCode    := IPWorksEncryptFindFunc(pBaseAddress, 'IPWorksEncrypt_EzCrypt_GetEventErrorCode');
    @_IPWorksEncrypt_EzCrypt_SetEventErrorAndCode := IPWorksEncryptFindFunc(pBaseAddress, 'IPWorksEncrypt_EzCrypt_SetEventErrorAndCode');
    @_IPWorksEncrypt_EzCrypt_CheckIndex           := IPWorksEncryptFindFunc(pBaseAddress, 'IPWorksEncrypt_EzCrypt_CheckIndex');
    @_IPWorksEncrypt_EzCrypt_Do                   := IPWorksEncryptFindFunc(pBaseAddress, 'IPWorksEncrypt_EzCrypt_Do');
  end;

  FreeResource(hResData);
end;
{$ENDIF USEIPWORKSENCRYPTDLL}

initialization
begin
  iLoadCount := iLoadCount + 1;
  if iLoadCount > 1 then exit;

  {$IFDEF USEIPWORKSENCRYPTDLL}
  hLib := 0;
  LoadDLL();
  {$ELSE}
  pBaseAddress := nil;
  pEntryPoint := nil;
  LoadResDLL();
  {$ENDIF}

  {$IFDEF USE_EXPLICIT_INIT}
  if @_IPWorksEncrypt_EzCrypt_StaticInit <> nil then
    _IPWorksEncrypt_EzCrypt_StaticInit(nil);
  {$ENDIF}
end;

finalization
begin
  iLoadCount := iLoadCount - 1;
  if iLoadCount > 0 then exit;

  {$IFDEF USE_EXPLICIT_INIT}
  if @_IPWorksEncrypt_EzCrypt_StaticDestroy <> nil then
    _IPWorksEncrypt_EzCrypt_StaticDestroy();
  {$ENDIF}

  ClearProcs();

  {$IFDEF USEIPWORKSENCRYPTDLL}
  if hLib <> 0 then
  begin
    {$ifndef FPC}FreeLibrary{$else}UnloadLibrary{$endif}(hLib);
    hLib := 0;
  end;
  {$ELSE}
  IPWorksEncryptFreeDRU(pBaseAddress, pEntryPoint);
  pBaseAddress := nil;
  pEntryPoint := nil;
  {$ENDIF}
  iLoadCount := 0;
end;

{$ELSE USE_DYNAMIC_LOADING}

// in case if static library used

{$IFDEF USE_EXPLICIT_INIT}

initialization
  _IPWorksEncrypt_EzCrypt_StaticInit(nil);

finalization
  _IPWorksEncrypt_EzCrypt_StaticDestroy();

{$ENDIF USE_EXPLICIT_INIT}

{$ENDIF USE_DYNAMIC_LOADING}


end.
