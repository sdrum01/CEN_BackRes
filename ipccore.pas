
unit ipccore;

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







{$IFNDEF USEIPWORKSENCRYPTDLL}
{$IFDEF WIN64}
{$R 'ipworksencrypt64.dru'}
{$ELSE}
{$R 'ipworksencrypt.dru'}
{$ENDIF}
{$ENDIF}




interface

uses




{$IFDEF FPC}  //Lazarus
  SyncObjs, SysUtils, Classes {$IFDEF MSWINDOWS}, Windows{$ENDIF};
{$ELSE}
  {$IF CompilerVersion >= 23}System.SyncObjs{$else}SyncObjs{$IFEND},
  {$ifdef MSWINDOWS}{$IF CompilerVersion >= 23}Winapi.Windows{$ELSE}Windows{$IFEND}, {$endif}{$IF CompilerVersion >= 23}System.SysUtils{$ELSE}SysUtils{$IFEND}, {$IF CompilerVersion >= 23}System.Classes{$ELSE}Classes{$IFEND};
{$ENDIF}

type
  {$ifdef ANSICHAR_IS_BYTE}
  {$ifdef VER150}
  LXAnsiString = array of Byte;
  {$else}
  LXAnsiString = TBytes;
  {$endif}
  LXAnsiChar = Byte;
  PLXAnsiChar = ^Byte;
  {$else}
  LXAnsiString = AnsiString;
  LXAnsiChar = AnsiChar;
  PLXAnsiChar = PAnsiChar;
  {$endif}

  VOIDARR = array[0..32] of Pointer;
  LPVOIDARR = ^VOIDARR;
  {$IFNDEF FPC}
  {$IF CompilerVersion <= 18.0}TBytes = array of Byte;{$IFEND}
  {$ENDIF}
  TipcCore = class;
  TAbout = Longint;
  EIPWorksEncrypt = class(Exception)
    public
      Code: integer;
      constructor CreateCode(err: Integer; desc: {$ifndef NO_ANSI}AnsiString{$else}string{$endif});
  end;

  TipcCore = class(TComponent)
  private

  protected
    function AboutReadNoop: TAbout;
    procedure AboutWriteNoop(NewVal: TAbout);

    procedure AboutDlg; virtual;

    procedure SetNoopString(x: String);
    procedure SetNoopAnsiString(x: {$ifndef NO_ANSI}AnsiString{$else}string{$endif});
    procedure SetNoopInteger(x: Integer);
    procedure SetNoopLongint(x: Longint);
    procedure SetNoopInt64(x: Int64);
    procedure SetNoopBoolean(x: Boolean);
    procedure SetNoopTDateTime(x: TDateTime);

    {$ifdef MSWINDOWS}
    function FileTimeToDateTime(const FTime: Int64): TDateTime;
    function DateTimeToFileTime(const DTime: TDateTime): Int64;
    {$endif}
    function StringToSPTRBuf(const Str: String; Dest: Pointer; DestLen: Integer): Integer;

  public
    constructor Create(AOwner: TComponent); override;

  published
    property About: TAbout read AboutReadNoop write AboutWriteNoop stored False;
  end;

  procedure Register;


{$IFNDEF LINUX}
{$IFNDEF USEIPWORKSENCRYPTDLL}
	function IsWinNT : boolean;
	function IPWorksEncryptLoadDRU(FileBuffer: Pointer; var EntryPoint: Pointer): Pointer;
	function IPWorksEncryptFindFunc(pBaseAddress: Pointer; FuncName: PAnsiChar): Pointer;
	function IPWorksEncryptFreeDRU(BaseAddress: Pointer; EntryPoint: Pointer): Boolean;
{$ENDIF USEIPWORKSENCRYPTDLL}
{$ENDIF LINUX}


const
  STREAM_OP_READ            = 500;
  STREAM_OP_WRITE           = 501;
  STREAM_OP_SEEK            = 502;
  STREAM_OP_FLUSH           = 503;
  STREAM_OP_CLOSE           = 504;
  STREAM_OP_CHECK           = 505;
  STREAM_OP_GET_LENGTH      = 506;
  STREAM_OP_SET_LENGTH      = 507;
  STREAM_OP_LAST_ERROR      = 508;
  STREAM_OP_LAST_ERROR_CODE = 509;

  STREAM_SEEK_FROM_BEGIN    = 0;
  STREAM_SEEK_FROM_CURRENT  = 1;
  STREAM_SEEK_FROM_END      = 2;



const
  LXAnsiStringStartOffset = {$ifdef ANSICHAR_IS_BYTE}0{$else}1{$endif};

{$ifdef ANSICHAR_IS_BYTE}
function ToLinuxAnsiString(const S : string): LXAnsiString;
function FromLinuxAnsiString(const S : LXAnsiString): string; overload;
function FromLinuxAnsiString(S : PLXAnsiChar): string; overload;
{$endif}

implementation

{$IFNDEF USEIPWORKSENCRYPTDLL}
{$WARNINGS OFF}

const
  FD_READ                            = $01;
  FD_WRITE                           = $02;
  FD_OOB                             = $04;
  FD_ACCEPT                          = $08;
  FD_CONNECT                         = $10;
  FD_CLOSE                           = $20;
{$IFDEF WIN64}
  ORDINAL_MASK                       = $7FFFFFFFFFFFFFFF;
{$ELSE}
  ORDINAL_MASK                       = $7FFFFFFF;
{$ENDIF}
  IMAGE_REL_BASED_ABSOLUTE           = 0;
  IMAGE_REL_BASED_HIGH               = 1;
  IMAGE_REL_BASED_LOW                = 2;
  IMAGE_REL_BASED_HIGHLOW            = 3;
  IMAGE_REL_BASED_HIGHADJ            = 4;
  IMAGE_REL_BASED_MIPS_JMPADDR       = 5;
  IMAGE_REL_BASED_MIPS_JMPADDR16     = 9;
  IMAGE_REL_BASED_IA64_IMM64         = 9;
  IMAGE_REL_BASED_DIR64              = 10;



type
  PShort    = ^Short;
  TShortArr = array of Short;
  PShortArr = ^TShortArr;
  TDWORDArr = array of DWORD;
  PDWORDArr = ^TDWORDArr;

  // PE file header structures used to parse the dll for correct dll loading.
  // For detailed infromation about this sructures refer to MSDN library

  TIIDUnion = record
    case Integer of
      0: (Characteristics: DWORD);
      1: (OriginalFirstThunk: DWORD);
  end;

  TImgSecHdrMisc = record
    case Integer of
      0: (PhysicalAddress: DWORD);
      1: (VirtualSize: DWORD);
  end;

  _IMAGE_SECTION_HEADER = record
    Name: array[0..IMAGE_SIZEOF_SHORT_NAME - 1] of Byte;
    Misc: TImgSecHdrMisc;
    VirtualAddress: DWORD;
    SizeOfRawData: DWORD;
    PointerToRawData: DWORD;
    PointerToRelocations: DWORD;
    PointerToLinenumbers: DWORD;
    NumberOfRelocations: WORD;
    NumberOfLinenumbers: WORD;
    Characteristics: DWORD;
  end;

  IMAGE_SECTION_HEADER = _IMAGE_SECTION_HEADER;
  PIMAGE_SECTION_HEADER = ^IMAGE_SECTION_HEADER;

  PIMAGE_IMPORT_DESCRIPTOR = ^IMAGE_IMPORT_DESCRIPTOR;
  _IMAGE_IMPORT_DESCRIPTOR = record
    Union: TIIDUnion;
    TimeDateStamp: DWORD;
    ForwarderChain: DWORD;
    Name: DWORD;
    FirstThunk: DWORD;
  end;
  IMAGE_IMPORT_DESCRIPTOR = _IMAGE_IMPORT_DESCRIPTOR;

  PIMAGE_THUNK_DATA32 = ^IMAGE_THUNK_DATA32;
  _IMAGE_THUNK_DATA32 = record
    case Integer of
      0: (ForwarderString: DWORD);
      1: (Function_: DWORD);
      2: (Ordinal: DWORD);
      3: (AddressOfData: DWORD);
  end;
  IMAGE_THUNK_DATA32 = _IMAGE_THUNK_DATA32;

{$IFDEF WIN64}
  PIMAGE_THUNK_DATA64 = ^IMAGE_THUNK_DATA64;
  _IMAGE_THUNK_DATA64 = record
    case Integer of
      0: (ForwarderString: DWORD64);
      1: (Function_: DWORD64);
      2: (Ordinal: DWORD64);
      3: (AddressOfData: DWORD64);
  end;
  IMAGE_THUNK_DATA64 = _IMAGE_THUNK_DATA64;
{$ENDIF}

  PIMAGE_IMPORT_BY_NAME = ^IMAGE_IMPORT_BY_NAME;
  _IMAGE_IMPORT_BY_NAME = record
    Hint: WORD;
    Name: array[0..0] of Byte;
  end;
  IMAGE_IMPORT_BY_NAME = _IMAGE_IMPORT_BY_NAME;

  PIMAGE_EXPORT_DIRECTORY = ^IMAGE_EXPORT_DIRECTORY;
  _IMAGE_EXPORT_DIRECTORY = record
    Characteristics: DWORD;
    TimeDateStamp: DWORD;
    MajorVersion: WORD;
    MinorVersion: WORD;
    Name: DWORD;
    Base: DWORD;
    NumberOfFunctions: DWORD;
    NumberOfNames: DWORD;
    AddressOfFunctions: DWORD;
    AddressOfNames: DWORD;
    AddressOfNameOrdinals: DWORD;
  end;

  IMAGE_EXPORT_DIRECTORY = _IMAGE_EXPORT_DIRECTORY;
{$IFDEF WIN64}
  PIMAGE_NT_HEADERS = ^_IMAGE_NT_HEADERS64;
  IMAGE_THUNK_DATA  = IMAGE_THUNK_DATA64;
  PIMAGE_THUNK_DATA = ^IMAGE_THUNK_DATA64;
  MY_POINTER        = DWORD64;
  PMY_POINTER       = ^DWORD64;
{$ELSE}
  PIMAGE_NT_HEADERS = ^_IMAGE_NT_HEADERS;
  IMAGE_THUNK_DATA  = IMAGE_THUNK_DATA32;
  PIMAGE_THUNK_DATA = ^IMAGE_THUNK_DATA32;
  MY_POINTER        = DWORD;
  PMY_POINTER       = ^DWORD;
{$ENDIF}
  TEntryPointProc = function(hinstDll: HINST; fdwReason: DWORD; lpvREserved: Pointer): Boolean; stdcall; // the dll entry point procedure type

{$ENDIF USEIPWORKSENCRYPTDLL}

{$ifdef ANSICHAR_IS_BYTE}

{$IF DEFINED(VER230)} // XE2
function AtomicCmpExchange(var Target : Pointer; NewValue, Comperand : Pointer) : Pointer; register;
asm
  {$ifndef CPUX64} // CPUX64 define supported since XE2
  // eax - Target
  // ecx - Comperand
  // edx - NewValue
  xchg eax, ecx
  lock cmpxchg [ecx], edx
  {$else CPUX64}
  // rcx - Target
  // r8 - Comperand
  // rdx - NewValue
  mov rax, r8
  lock cmpxchg [rcx], rdx
  {$endif}
  // eax/rax - Result
end;
{$IFEND}

function ToLinuxAnsiString(const S : string): LXAnsiString;
begin
  Result := TEncoding.UTF8.GetBytes(S);
  SetLength(Result, Length(Result) + 1);
  Result[Length(Result) - 1] := 0;
end;

function FromLinuxAnsiString(const S : LXAnsiString): string;
var
  I : integer;
begin
  I := LXAnsiStringStartOffset;
  while (I < Length(S)) and (S[I] <> 0) do
    Inc(I);
  Result := TEncoding.UTF8.GetString(S, 0, I);
end;

function FromLinuxAnsiString(S : PLXAnsiChar): string;
var
  I : integer;
  Ptr : PLXAnsiChar;
  Buf : LXAnsiString;
begin
  if S = nil then
  begin
    Result := '';
    Exit;
  end;

  I := 0;
  Ptr := S;
  while (Ptr^ <> 0) do
  begin
    Inc(Ptr);
    Inc(I);
  end;

  if (S = nil) or (I = 0) then
    Result := ''
  else
  begin
    SetLength(Buf, I);
    Move(S^, Buf[0], Length(Buf));
  
    Result := TEncoding.UTF8.GetString(Buf);
  end;
end;
{$endif}

constructor TipcCore.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
end;

procedure Register;
begin

end;

procedure TipcCore.AboutDlg;
begin
end;

function TipcCore.AboutReadNoop: TAbout;
begin
  if csDesigning in ComponentState
  then Result := Longint(self)
  else Result := 0;
end;

procedure TipcCore.AboutWriteNoop(NewVal: TAbout);
begin
end;
procedure TipcCore.SetNoopString(x: String);
begin
end;
procedure TipcCore.SetNoopAnsiString(x: {$ifndef NO_ANSI}AnsiString{$else}string{$endif});
begin
end;
procedure TipcCore.SetNoopInteger(x: Integer);
begin
end;
procedure TipcCore.SetNoopLongint(x: Longint);
begin
end;
procedure TipcCore.SetNoopInt64(x: Int64);
begin
end;
procedure TipcCore.SetNoopBoolean(x: Boolean);
begin
end;
procedure TipcCore.SetNoopTDateTime(x: TDateTime);
begin
end;

{$ifdef MSWINDOWS}
function TipcCore.FileTimeToDateTime(const FTime: Int64): TDateTime;
var
  FTRec: TFileTime;
  STRec: TSystemTime;
begin
  FTRec.dwHighDateTime := (FTime and $FFFFFFFF00000000) shr 32;
  FTRec.dwLowDateTime := FTime and $00000000FFFFFFFF;
  FileTimeToSystemTime(FTRec, STRec);
  Result := SystemTimeToDateTime(STRec);
end;

function TipcCore.DateTimeToFileTime(const DTime: TDateTime): Int64;
var
  FTRec: TFileTime;
  STRec: TSystemTime;
begin
  DateTimeToSystemTime(DTime, STRec);
  SystemTimeToFileTime(STRec, FTRec);
  Result := FTRec.dwHighDateTime;
  Result := (Result shl 32) or FTRec.dwLowDateTime;
end;
{$endif}

// Helper method to marshal strings user provides for SPTR event parameters back to component memory. Returns length
// (not including terminating null characters) of unmanaged string, or 0 if an error occurs. Keep in mind that both
// DestLen and the returned length are either a number of 'char' or 'wchar_t' characters, __NOT__ a number of bytes!
// Conveniently, thats how String.Length (whether it's AnsiString or UnicodeString) works too.
function TipcCore.StringToSPTRBuf(const Str: String; Dest: Pointer; DestLen: Integer): Integer;
begin
  Result := 0;
  if (Length(Str) > 0) and (Dest <> nil) then begin
    if (Length(Str) > DestLen) then raise Exception.Create('Cannot copy string, too large for destination buffer.');
    Move(Pointer(PChar(Str))^, Dest^, Length(Str) * SizeOf(Char));
    Result := Length(Str);
  end;
end;



constructor EIPWorksEncrypt.CreateCode(err: integer; desc: {$ifndef NO_ANSI}AnsiString{$else}string{$endif});
begin
  code := err;
  Create(IntToStr(err) + ': ' + desc);
end;



{$IFNDEF USEIPWORKSENCRYPTDLL}
{$WARNINGS OFF}

function IsWinNT : Boolean;
var
   osv : TOSVERSIONINFO;
begin
   osv.dwOSVersionInfoSize := sizeOf(OSVERSIONINFO);
   GetVersionEx(osv);
   result := (osv.dwPlatformId = VER_PLATFORM_WIN32_NT);
end;

var
  G_CS : TCriticalSection = nil;
  G_DllEntryPoint : pointer = nil;
  G_DllBaseAddress : pointer = nil;
  G_RefCount : integer = 0;



function IPWorksEncryptLoadDRU(FileBuffer: Pointer; var EntryPoint: Pointer): Pointer;
var
  peHeader: PIMAGE_NT_HEADERS;
  peSectHeader: PIMAGE_SECTION_HEADER;
  peSectRelocHeader: PIMAGE_SECTION_HEADER;
  DllBuffer: Pointer;
  DllHandle: THandle;
  TempBuffer: Pointer;
  i: DWORD;
  j: DWORD;
  k: MY_POINTER;
  ImportDesc: PIMAGE_IMPORT_DESCRIPTOR;
  ThunkData: PIMAGE_THUNK_DATA;
  ImportByName: PIMAGE_IMPORT_BY_NAME;
  AddressOfEntryPoint: MY_POINTER;
  Offset: DWORD;
  Address: PDWORD;
  DllName: PAnsiChar;
  DllModule: HMODULE;
  AddresTable: Pointer;
  ProcAddress: Pointer;
  Ordinal: Boolean;
  MoveAddr: Pointer;
  Entry: WORD;
  EntryType: WORD;
  EntryOffset: WORD;
{$IFDEF WIN64}
  Address64: PDWORD64;
{$ENDIF}
begin
  Result := nil;
  peSectRelocHeader := nil;
  if not IsWinNT then begin
    DllHandle := LoadLibraryA(PAnsiChar('ipworksencrypt20.dll'));
    Result := Pointer(DllHandle);
    exit;
  end;

  G_CS.Enter;
  try
     if (G_RefCount > 0) and (G_DllBaseAddress <> nil) and (G_DllEntryPoint <> nil) then
     begin
      Inc(G_RefCount);
      Result := G_DllBaseAddress;
      EntryPoint := G_DllEntryPoint;
      Exit;
    end;

    if Assigned(FileBuffer) then
      begin
        peHeader := PIMAGE_NT_HEADERS(DWORD(FileBuffer) + PDWORD(DWORD(FileBuffer) + $3C)^);
        if (PDWORD(peHeader)^ = $4550) then
          begin
            DllBuffer := VirtualAlloc(nil, peHeader.OptionalHeader.SizeOfImage,
              MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if Assigned(DllBuffer) then
              begin
                Move(FileBuffer^, DllBuffer^, peHeader.OptionalHeader.SizeOfHeaders);
                peSectHeader := Pointer(MY_POINTER(DllBuffer) + MY_POINTER(@peHeader.OptionalHeader) - MY_POINTER(FileBuffer) + peHeader.FileHeader.SizeOfOptionalHeader);
                for i := 0 to Pred(peHeader.FileHeader.NumberOfSections) do
                  begin
                    if strcomp(PAnsiChar(@peSectHeader.Name), '.reloc') = 0 then
                      peSectRelocHeader := peSectHeader;
                    TempBuffer := Pointer(MY_POINTER(DllBuffer) + peSectHeader.VirtualAddress);
                    MoveAddr := Pointer(MY_POINTER(FileBuffer) + peSectHeader.PointerToRawData);
                    Move(MoveAddr^, TempBuffer^, peSectHeader.SizeOfRawData);
                    peSectHeader.Misc.PhysicalAddress := DWORD(TempBuffer);
                    peSectHeader := PIMAGE_SECTION_HEADER(MY_POINTER(peSectHeader) + sizeof(IMAGE_SECTION_HEADER));
                  end;
                if Assigned(peSectRelocHeader) then
                  begin
                    TempBuffer := Pointer(MY_POINTER(FileBuffer) + peSectRelocHeader.PointerToRawData);
                    i := 0;
                    while i < peSectRelocHeader.SizeOfRawData do
                      begin
                        j := 8;
                        while j < PDWORD(MY_POINTER(TempBuffer) + 4)^ do
                          begin
                            Entry := PWord(MY_POINTER(TempBuffer) + j)^;
                            EntryType := (Entry Shr 12) and $F;
                            EntryOffset := Entry and $FFF;
                            case EntryType of
                              IMAGE_REL_BASED_HIGHLOW:
                              begin
                                Offset := EntryOffset + PDWORD(MY_POINTER(TempBuffer))^;
                                Address := PDWORD(MY_POINTER(DllBuffer) + Offset);
                                Address^ := Address^ - peHeader.OptionalHeader.ImageBase + MY_POINTER(DllBuffer);
                              end;
{$IFDEF WIN64}
                              IMAGE_REL_BASED_DIR64:
                              begin
                                Offset := EntryOffset + PDWORD(MY_POINTER(TempBuffer))^;
                                Address64 := PDWORD64(MY_POINTER(DllBuffer) + Offset);
                                Address64^ := Address64^ - peHeader.OptionalHeader.ImageBase + MY_POINTER(DllBuffer);
                              end;
{$ENDIF}
                            end;
                            Inc(j, 2);
                          end;
                        TempBuffer := Pointer(MY_POINTER(TempBuffer) + PDWORD(MY_POINTER(TempBuffer) + 4)^);
                        i := i + j;
                      end;
                    if peHeader.OptionalHeader.DataDirectory[1].VirtualAddress <> 0 then
                      begin
                        ImportDesc := PIMAGE_IMPORT_DESCRIPTOR(MY_POINTER(DllBuffer) + peHeader.OptionalHeader.DataDirectory[1].VirtualAddress);
                        while (ImportDesc.Union.OriginalFirstThunk <> 0) do
                          begin
                            DllName := PAnsiChar(MY_POINTER(DllBuffer) + ImportDesc.Name);
                            AddresTable := Pointer(MY_POINTER(DllBuffer) + ImportDesc.FirstThunk);
                            DllModule := GetModuleHandleA(DllName);
                            if DllModule = 0 then
                              begin
                                DllModule := LoadLibraryA(DllName);
                                if DllModule = 0 then
                                  Exit;
                              end;
                            ThunkData := PIMAGE_THUNK_DATA(MY_POINTER(DllBuffer) + ImportDesc.Union.OriginalFirstThunk);
                            while PDWORD(ThunkData)^ <> 0 do
                              begin
                                Ordinal := False;
                                k := ThunkData.Ordinal;
                                if ((k and ORDINAL_MASK) <> k) then
                                  begin
                                    Ordinal := True;
                                    k := k and ORDINAL_MASK;
                                  end;
                                if not Ordinal then
                                  begin
                                    ImportByName := PIMAGE_IMPORT_BY_NAME(MY_POINTER(DllBuffer) + k);
                                    ProcAddress := GetProcAddress(DllModule, PAnsiChar(@ImportByName.Name));
                                  end
                                else
                                  ProcAddress := GetProcAddress(DllModule, PAnsiChar(k));
                                PMY_POINTER(AddresTable)^ := MY_POINTER(ProcAddress);
                                AddresTable := PMY_POINTER(MY_POINTER(AddresTable) + sizeof(MY_POINTER));
                                ThunkData := PIMAGE_THUNK_DATA(MY_POINTER(ThunkData) + sizeof(IMAGE_THUNK_DATA));
                              end;
                            ImportDesc := PIMAGE_IMPORT_DESCRIPTOR(MY_POINTER(ImportDesc) + sizeof(IMAGE_IMPORT_DESCRIPTOR));
                          end;
                      end;
                  end;
                AddressOfEntryPoint := peHeader.OptionalHeader.AddressOfEntryPoint + MY_POINTER(DllBuffer);
                if not TEntryPointProc(AddressOfEntryPoint)(HINST(DllBuffer), DLL_PROCESS_ATTACH, nil) then
                  Exit;
                EntryPoint := Pointer(AddressOfEntryPoint);
                Result := DllBuffer;

                G_RefCount := 1;
                G_DllBaseAddress := Result;
                G_DllEntryPoint := EntryPoint;
              end;
          end;
      end;
  finally
    G_CS.Leave;
  end;
end;



function IPWorksEncryptFreeDRU(BaseAddress: Pointer; EntryPoint: Pointer): Boolean;
begin
  Result := False;
  if not IsWinNT then begin
  	if Assigned(BaseAddress) then FreeLibrary(THandle(BaseAddress));
  	exit;
  end;
  if Assigned(BaseAddress) and Assigned(EntryPoint) then
  begin
    G_CS.Enter;
    try
      if (BaseAddress = G_DllBaseAddress) and (EntryPoint = G_DllEntryPoint) then
      begin
        Dec(G_RefCount);
        if G_RefCount = 0 then
        begin
          try
            if TEntryPointProc(EntryPoint)(HINST(BaseAddress), DLL_PROCESS_DETACH, nil) then
              Result := VirtualFree(BaseAddress, 0, MEM_RELEASE);
          finally
            G_DllBaseAddress := nil;
            G_DllEntryPoint := nil;
          end;
        end;
      end
      else // Unknown address and entry point, just letting it proceed and release the DLL
      if TEntryPointProc(EntryPoint)(HINST(BaseAddress), DLL_PROCESS_DETACH, nil) then
        Result := VirtualFree(BaseAddress, 0, MEM_RELEASE);
    finally
      G_CS.Leave;
    end;
  end;
end;



function IPWorksEncryptFindFunc(pBaseAddress: Pointer; FuncName: PAnsiChar): Pointer;
var
  pinth: PIMAGE_NT_HEADERS;
  pied: PIMAGE_EXPORT_DIRECTORY;
  k: Integer;
  FuncAddr: Pointer;
  dwBaseAddress: MY_POINTER;
begin
  FuncAddr := nil;
  Result := nil;
  if not IsWinNT then begin
    Result := GetProcAddress(THandle(pBaseAddress), FuncName);
    exit;
  end;
  dwBaseAddress := MY_POINTER(pBaseAddress);
  if (dwBaseAddress <> 0) then
    begin
      pinth := PIMAGE_NT_HEADERS(dwBaseAddress + PDWORD(dwBaseAddress + $3C)^);
      pied := PIMAGE_EXPORT_DIRECTORY(pinth.OptionalHeader.DataDirectory[0].VirtualAddress + dwBaseAddress);
      for k := 0 to Pred(pied.NumberOfNames) do
        begin
          if strcomp(PAnsiChar(TDWORDArr(pied.AddressOfNames + dwBaseAddress)[k] + dwBaseAddress), FuncName) = 0 then
            begin
              FuncAddr := Pointer(TDWORDArr(pied.AddressOfFunctions + dwBaseAddress)
                    [TShortArr(pied.AddressOfNameOrdinals + dwBaseAddress)[k]]);
              FuncAddr := Pointer(MY_POINTER(FuncAddr) + dwBaseAddress);
            end;
        end;
      Result := FuncAddr;
    end;
end;

initialization
  G_CS := TCriticalSection.Create;

finalization
  FreeAndNil(G_CS);

{$ENDIF USEIPWORKSENCRYPTDLL}



end.