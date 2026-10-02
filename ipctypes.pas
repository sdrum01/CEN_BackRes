
unit ipctypes;

{$IFDEF fpc}  //Lazarus
  {$IFDEF FPC_UNICODESTRINGS}
      // ensure that mode Delphi Unicode is enabled, not a modeswitch unicodestrings
    {$MODE DELPHIUNICODE}
  {$ELSE}
    {$MODE DELPHI}
  {$ENDIF}
{$ENDIF}

{$IFDEF VER130}
  {$DEFINE DELPHI_5}
{$ENDIF}

interface

uses
  ipccore,
{$IFDEF fpc}  //Lazarus
  SysUtils, Classes;
{$ELSE}
  {$IF CompilerVersion >= 23}System.SysUtils{$ELSEIF True}SysUtils{$IFEND}, {$IF CompilerVersion >= 23}System.Classes{$ELSEIF True}Classes{$IFEND};
{$ENDIF}

// Collections can exist in one of two modes: freestanding and bound
// A freestanding collection is not bound to any parent control. All objects and associated content are kept internally.
// A bound collection is bound to a parent control. Any calls are redirected to the parent control.

type
  TipcTypesCore = class(TipcCore)
  end;

  TipcTAESCipherModes = (
                   acmCBC{$IFNDEF DELPHI_5}=Ord(0){$ENDIF},
                   acmECB{$IFNDEF DELPHI_5}=Ord(1){$ENDIF},
                   acmOFB{$IFNDEF DELPHI_5}=Ord(2){$ENDIF},
                   acmCFB{$IFNDEF DELPHI_5}=Ord(3){$ENDIF},
                   acmCTS{$IFNDEF DELPHI_5}=Ord(4){$ENDIF},
                   acm8OFB{$IFNDEF DELPHI_5}=Ord(5){$ENDIF},
                   acmGCM{$IFNDEF DELPHI_5}=Ord(6){$ENDIF},
                   acm8CFB{$IFNDEF DELPHI_5}=Ord(7){$ENDIF},
                   acmCTR{$IFNDEF DELPHI_5}=Ord(8){$ENDIF},
                   acmXTS{$IFNDEF DELPHI_5}=Ord(9){$ENDIF});

  TipcTPaddingModes = (
                   pmPKCS7{$IFNDEF DELPHI_5}=Ord(0){$ENDIF},
                   pmZeros{$IFNDEF DELPHI_5}=Ord(1){$ENDIF},
                   pmNone{$IFNDEF DELPHI_5}=Ord(2){$ENDIF},
                   pmANSIX923{$IFNDEF DELPHI_5}=Ord(3){$ENDIF},
                   pmISO10126{$IFNDEF DELPHI_5}=Ord(4){$ENDIF});

  TipcTCipherModes = (
                   cmCBC{$IFNDEF DELPHI_5}=Ord(0){$ENDIF},
                   cmECB{$IFNDEF DELPHI_5}=Ord(1){$ENDIF},
                   cmOFB{$IFNDEF DELPHI_5}=Ord(2){$ENDIF},
                   cmCFB{$IFNDEF DELPHI_5}=Ord(3){$ENDIF},
                   cmCTS{$IFNDEF DELPHI_5}=Ord(4){$ENDIF},
                   cm8OFB{$IFNDEF DELPHI_5}=Ord(5){$ENDIF},
                   cm8CFB{$IFNDEF DELPHI_5}=Ord(7){$ENDIF});

  TipcCertStoreTypes = (
                   cstUser,
                   cstMachine,
                   cstPFXFile,
                   cstPFXBlob,
                   cstJKSFile,
                   cstJKSBlob,
                   cstPEMKeyFile,
                   cstPEMKeyBlob,
                   cstPublicKeyFile,
                   cstPublicKeyBlob,
                   cstSSHPublicKeyBlob,
                   cstP7BFile,
                   cstP7BBlob,
                   cstSSHPublicKeyFile,
                   cstPPKFile,
                   cstPPKBlob,
                   cstXMLFile,
                   cstXMLBlob,
                   cstJWKFile,
                   cstJWKBlob,
                   cstSecurityKey,
                   cstBCFKSFile,
                   cstBCFKSBlob,
                   cstAuto{$IFNDEF DELPHI_5}=Ord(99){$ENDIF});

  TipcIncludeCertificates = (
                   icsNone{$IFNDEF DELPHI_5}=Ord(0){$ENDIF},
                   icsSignerCerts{$IFNDEF DELPHI_5}=Ord(1){$ENDIF},
                   icsSignerCertsAndChain{$IFNDEF DELPHI_5}=Ord(2){$ENDIF});

  TipcDSAHashAlgorithms = (
                   dhaSHA1{$IFNDEF DELPHI_5}=Ord(0){$ENDIF},
                   dhaSHA224{$IFNDEF DELPHI_5}=Ord(1){$ENDIF},
                   dhaSHA256{$IFNDEF DELPHI_5}=Ord(2){$ENDIF},
                   dhaSHA384{$IFNDEF DELPHI_5}=Ord(3){$ENDIF},
                   dhaSHA512{$IFNDEF DELPHI_5}=Ord(4){$ENDIF},
                   dhaRIPEMD160{$IFNDEF DELPHI_5}=Ord(5){$ENDIF});

  TipcECCComputeSecretKDFs = (
                   ekdSHA1{$IFNDEF DELPHI_5}=Ord(0){$ENDIF},
                   ekdSHA256{$IFNDEF DELPHI_5}=Ord(1){$ENDIF},
                   ekdSHA384{$IFNDEF DELPHI_5}=Ord(2){$ENDIF},
                   ekdSHA512{$IFNDEF DELPHI_5}=Ord(3){$ENDIF},
                   ekdMD2{$IFNDEF DELPHI_5}=Ord(4){$ENDIF},
                   ekdMD4{$IFNDEF DELPHI_5}=Ord(5){$ENDIF},
                   ekdMD5{$IFNDEF DELPHI_5}=Ord(6){$ENDIF},
                   ekdHMACSHA1{$IFNDEF DELPHI_5}=Ord(7){$ENDIF},
                   ekdHMACSHA256{$IFNDEF DELPHI_5}=Ord(8){$ENDIF},
                   ekdHMACSHA384{$IFNDEF DELPHI_5}=Ord(9){$ENDIF},
                   ekdHMACSHA512{$IFNDEF DELPHI_5}=Ord(10){$ENDIF},
                   ekdHMACMD5{$IFNDEF DELPHI_5}=Ord(11){$ENDIF},
                   ekdTLS{$IFNDEF DELPHI_5}=Ord(12){$ENDIF},
                   ekdConcat{$IFNDEF DELPHI_5}=Ord(13){$ENDIF});

  TipcECCEncryptionAlgorithms = (
                   iesAES{$IFNDEF DELPHI_5}=Ord(0){$ENDIF},
                   iesTripleDES{$IFNDEF DELPHI_5}=Ord(1){$ENDIF},
                   iesXOR{$IFNDEF DELPHI_5}=Ord(2){$ENDIF});

  TipcECCHashAlgorithms = (
                   ehaSHA1{$IFNDEF DELPHI_5}=Ord(0){$ENDIF},
                   ehaSHA224{$IFNDEF DELPHI_5}=Ord(1){$ENDIF},
                   ehaSHA256{$IFNDEF DELPHI_5}=Ord(2){$ENDIF},
                   ehaSHA384{$IFNDEF DELPHI_5}=Ord(3){$ENDIF},
                   ehaSHA512{$IFNDEF DELPHI_5}=Ord(4){$ENDIF},
                   ehaMD2{$IFNDEF DELPHI_5}=Ord(5){$ENDIF},
                   ehaMD4{$IFNDEF DELPHI_5}=Ord(6){$ENDIF},
                   ehaMD5{$IFNDEF DELPHI_5}=Ord(7){$ENDIF},
                   ehaMD5SHA1{$IFNDEF DELPHI_5}=Ord(8){$ENDIF},
                   ehaRIPEMD160{$IFNDEF DELPHI_5}=Ord(9){$ENDIF});

  TipcECCHMACAlgorithms = (
                   iesHMACSHA1{$IFNDEF DELPHI_5}=Ord(0){$ENDIF},
                   iesHMACSHA224{$IFNDEF DELPHI_5}=Ord(1){$ENDIF},
                   iesHMACSHA256{$IFNDEF DELPHI_5}=Ord(2){$ENDIF},
                   iesHMACSHA384{$IFNDEF DELPHI_5}=Ord(3){$ENDIF},
                   iesHMACSHA512{$IFNDEF DELPHI_5}=Ord(4){$ENDIF},
                   iesHMACRIPEMD160{$IFNDEF DELPHI_5}=Ord(5){$ENDIF});

  TipcECCKDFHashAlgorithms = (
                   iesSHA1{$IFNDEF DELPHI_5}=Ord(0){$ENDIF},
                   iesSHA224{$IFNDEF DELPHI_5}=Ord(1){$ENDIF},
                   iesSHA256{$IFNDEF DELPHI_5}=Ord(2){$ENDIF},
                   iesSHA384{$IFNDEF DELPHI_5}=Ord(3){$ENDIF},
                   iesSHA512{$IFNDEF DELPHI_5}=Ord(4){$ENDIF});

  TipcECAlgorithms = (
                   eaSecp256r1,
                   eaSecp384r1,
                   eaSecp521r1,
                   eaEd25519,
                   eaEd448,
                   eaX25519,
                   eaX448,
                   eaSecp160k1,
                   eaSecp192k1,
                   eaSecp224k1,
                   eaSecp256k1);

  TipcTEzCryptAlgorithms = (
                   ezAES{$IFNDEF DELPHI_5}=Ord(0){$ENDIF},
                   ezBlowfish,
                   ezCAST,
                   ezDES,
                   ezIDEA,
                   ezRC2,
                   ezRC4,
                   ezTEA,
                   ezTripleDES,
                   ezTwofish,
                   ezRijndael,
                   ezChaCha,
                   ezXSalsa20);

  TipcTRands = (
                   raISAAC{$IFNDEF DELPHI_5}=Ord(0){$ENDIF},
                   raMSCryptoAPI{$IFNDEF DELPHI_5}=Ord(1){$ENDIF},
                   raPlatform{$IFNDEF DELPHI_5}=Ord(2){$ENDIF},
                   raSecurePlatform{$IFNDEF DELPHI_5}=Ord(3){$ENDIF},
                   raRC4Random{$IFNDEF DELPHI_5}=Ord(4){$ENDIF});

  TipcTHASHAlgorithms = (
                   haSHA1,
                   haSHA224,
                   haSHA256,
                   haSHA384,
                   haSHA512,
                   haMD2,
                   haMD4,
                   haMD5,
                   haRIPEMD160,
                   haMD5SHA1,
                   haHMACMD5,
                   haHMACSHA1,
                   haHMACSHA224,
                   haHMACSHA256,
                   haHMACSHA384,
                   haHMACSHA512,
                   haHMACRIPEMD160,
                   haSHA3_224,
                   haSHA3_256,
                   haSHA3_384,
                   haSHA3_512,
                   haSHA512_224,
                   haSHA512_256);

  TipcTContentEncryptionAlgorithms = (
                   ceaA128CBC_HS256,
                   ceaA192CBC_HS384,
                   ceaA256CBC_HS512,
                   ceaA128GCM,
                   ceaA192GCM,
                   ceaA256GCM);

  TipcTEncryptionAlgorithms = (
                   eaRSA1_5,
                   eaRSA_OAEP,
                   eaRSA_OAEP_256,
                   eaA128KW,
                   eaA192KW,
                   eaA256KW,
                   eaDir,
                   eaECDH_ES,
                   eaECDH_ES_A128KW,
                   eaECDH_ES_A192KW,
                   eaECDH_ES_A256KW,
                   eaA128GCMKW,
                   eaA192GCMKW,
                   eaA256GCMKW,
                   eaPBES2_HS256_A128KW,
                   eaPBES2_HS384_A192KW,
                   eaPBES2_HS512_A256KW);

  TipcTDataTypes = (
                   dtObject,
                   dtArray,
                   dtString,
                   dtNumber,
                   dtBool,
                   dtNull);

  TipcTJWSAlgorithms = (
                   jwsHS256,
                   jwsHS384,
                   jwsHS512,
                   jwsRS256,
                   jwsRS384,
                   jwsRS512,
                   jwsES256,
                   jwsES384,
                   jwsES512,
                   jwsPS256,
                   jwsPS384,
                   jwsPS512,
                   jwsNone,
                   jwsES256K);

  TipcTPBKDFAlgorithms = (
                   pbHMACSHA1{$IFNDEF DELPHI_5}=Ord(0){$ENDIF},
                   pbHMACSHA224{$IFNDEF DELPHI_5}=Ord(1){$ENDIF},
                   pbHMACSHA256{$IFNDEF DELPHI_5}=Ord(2){$ENDIF},
                   pbHMACSHA384{$IFNDEF DELPHI_5}=Ord(3){$ENDIF},
                   pbHMACSHA512{$IFNDEF DELPHI_5}=Ord(4){$ENDIF},
                   pbHMACMD5{$IFNDEF DELPHI_5}=Ord(5){$ENDIF},
                   pbHMACRIPEMD160{$IFNDEF DELPHI_5}=Ord(6){$ENDIF},
                   pbSHA1{$IFNDEF DELPHI_5}=Ord(7){$ENDIF},
                   pbMD5{$IFNDEF DELPHI_5}=Ord(8){$ENDIF},
                   pbMD2{$IFNDEF DELPHI_5}=Ord(9){$ENDIF});

  TipcTVersions = (
                   vPBKDF1{$IFNDEF DELPHI_5}=Ord(0){$ENDIF},
                   vPBKDF2{$IFNDEF DELPHI_5}=Ord(1){$ENDIF});

  TipcRSAHashAlgorithms = (
                   rhaSHA1{$IFNDEF DELPHI_5}=Ord(0){$ENDIF},
                   rhaSHA224{$IFNDEF DELPHI_5}=Ord(1){$ENDIF},
                   rhaSHA256{$IFNDEF DELPHI_5}=Ord(2){$ENDIF},
                   rhaSHA384{$IFNDEF DELPHI_5}=Ord(3){$ENDIF},
                   rhaSHA512{$IFNDEF DELPHI_5}=Ord(4){$ENDIF},
                   rhaRIPEMD160{$IFNDEF DELPHI_5}=Ord(5){$ENDIF},
                   rhaMD2{$IFNDEF DELPHI_5}=Ord(6){$ENDIF},
                   rhaMD5{$IFNDEF DELPHI_5}=Ord(7){$ENDIF},
                   rhaMD5SHA1{$IFNDEF DELPHI_5}=Ord(8){$ENDIF});

  TipcSALSAAlgorithms = (
                   saSALSA20{$IFNDEF DELPHI_5}=Ord(0){$ENDIF},
                   saXSALSA20{$IFNDEF DELPHI_5}=Ord(1){$ENDIF});

  TipcTEAAlgorithms = (
                   taXXTEA{$IFNDEF DELPHI_5}=Ord(0){$ENDIF},
                   taXTEA{$IFNDEF DELPHI_5}=Ord(1){$ENDIF},
                   taTEA{$IFNDEF DELPHI_5}=Ord(2){$ENDIF});

  TipcScopes = (
                   sElement,
                   sContent);

  TipcTCanonicalizationMethods = (
                   cmC14N,
                   cmC14NComments,
                   cmC14N11,
                   cmC14N11Comments,
                   cmExcC14N,
                   cmExcC14NComments);




//////////////////////////////////////////////////////////////////////////////////////////

  TipcCertExtension = class(TPersistent)
  protected
    FOwnerCtl: TObject;
    FReadOnlyProp: boolean;
    FIndex: integer;

    FCritical: Boolean;

    FOID: String;

    FValue: TBytes;


    constructor Create(Owner: TObject; ReadOnly: boolean); overload;

    function GetPropCritical: Boolean; virtual;
    procedure SetPropCritical(Value: Boolean); virtual;

    function GetPropOID: String; virtual;
    procedure SetPropOID(Value: String); virtual;

    function GetPropValue: String; virtual;
    procedure SetPropValue(Value: String); virtual;
    function  GetPropValueB : TBytes; virtual;
    procedure SetPropValueB(Value: TBytes); virtual;


  public
    constructor Create(valoid: String; valvalue: TBytes; valcritical: Boolean); overload; virtual;

    destructor Destroy; override;

    procedure Assign(Source: TPersistent); override;
    function Clone: TipcCertExtension; virtual;


    property Critical: Boolean read GetPropCritical;

    property OID: String read GetPropOID;

    property Value: String read GetPropValue;
    property ValueB : TBytes read GetPropValueB;

    property Index: integer read FIndex write FIndex;
  end;

  TipcCertExtensionList = class(TPersistent)
  protected
    FItems: TList;
    FReadOnlyProp: Boolean;
    FOwnerCtl: TObject;
    FCount: integer;
  protected
    function GetCount: Integer;
    function GetItem(Idx: integer): TipcCertExtension;
    procedure SetItem(Idx: integer; Value: TipcCertExtension);
    function GetIsReadOnly: boolean;
    function GetIsFixedSize: boolean;
    function GetSyncRoot: TObject;
    function GetIsSynchronized: boolean;
    procedure ClearList;

    function IsFree: boolean;
    procedure SyncCount;
    procedure InternalSetCount(Value: integer);
    procedure InternalSetItem(Index: integer; Value: TipcCertExtension);

    function CtlGetCount: integer; virtual;
    procedure CtlSetCount(Value: integer); virtual;
    function CreateElemInstance(Index: integer): TipcCertExtension; virtual;


  public
    constructor Create(); overload;
    constructor Create(ReadOnly: Boolean); overload;
    constructor Create(Owner: TObject; ReadOnly: Boolean); overload;
    destructor Destroy; override;

    procedure Assign(Source: TPersistent); override;
    function Clone: TipcCertExtensionList;

    function Add(Value: TipcCertExtension): Integer; overload;
    function Add(): Integer; overload;
    procedure Remove(value: TipcCertExtension);

    function Contains(value: TipcCertExtension): Boolean;
    
    function IndexOf(value: TipcCertExtension): Integer;
    procedure Insert(Idx: Integer; value: TipcCertExtension);
    procedure RemoveAt(idx: Integer);
    
    
    procedure Clear();

    property Count: Integer read GetCount;
    property Item[Index: Integer]: TipcCertExtension read GetItem write SetItem; default;
    property IsReadOnly: boolean read GetIsReadOnly;
    property IsFixedSize: boolean read GetIsFixedSize;
    property SyncRoot: TObject read GetSyncRoot;
    property IsSynchronized: boolean read GetIsSynchronized;
  end;
  TipcDSAKey = class(TPersistent)
  protected
    FOwnerCtl: TObject;
    FReadOnlyProp: boolean;
    FIndex: integer;

    FG: TBytes;

    FP: TBytes;

    FPrivateKey: String;

    FPublicKey: String;

    FQ: TBytes;

    FX: TBytes;

    FY: TBytes;


    constructor Create(Owner: TObject; ReadOnly: boolean); overload;

    function GetPropG: String; virtual;
    procedure SetPropG(Value: String); virtual;
    function  GetPropGB : TBytes; virtual;
    procedure SetPropGB(Value: TBytes); virtual;

    function GetPropP: String; virtual;
    procedure SetPropP(Value: String); virtual;
    function  GetPropPB : TBytes; virtual;
    procedure SetPropPB(Value: TBytes); virtual;

    function GetPropPrivateKey: String; virtual;
    procedure SetPropPrivateKey(Value: String); virtual;

    function GetPropPublicKey: String; virtual;
    procedure SetPropPublicKey(Value: String); virtual;

    function GetPropQ: String; virtual;
    procedure SetPropQ(Value: String); virtual;
    function  GetPropQB : TBytes; virtual;
    procedure SetPropQB(Value: TBytes); virtual;

    function GetPropX: String; virtual;
    procedure SetPropX(Value: String); virtual;
    function  GetPropXB : TBytes; virtual;
    procedure SetPropXB(Value: TBytes); virtual;

    function GetPropY: String; virtual;
    procedure SetPropY(Value: String); virtual;
    function  GetPropYB : TBytes; virtual;
    procedure SetPropYB(Value: TBytes); virtual;


  public
    constructor Create(); overload; virtual;
    constructor Create(valP: TBytes; valQ: TBytes; valG: TBytes; valY: TBytes); overload; virtual;
    constructor Create(valP: TBytes; valQ: TBytes; valG: TBytes; valY: TBytes; valX: TBytes); overload; virtual;

    destructor Destroy; override;

    procedure Assign(Source: TPersistent); override;
    function Clone: TipcDSAKey; virtual;


    property G: String read GetPropG write SetPropG;
    property GB : TBytes read GetPropGB write SetPropGB;

    property P: String read GetPropP write SetPropP;
    property PB : TBytes read GetPropPB write SetPropPB;

    property PrivateKey: String read GetPropPrivateKey write SetPropPrivateKey;

    property PublicKey: String read GetPropPublicKey write SetPropPublicKey;

    property Q: String read GetPropQ write SetPropQ;
    property QB : TBytes read GetPropQB write SetPropQB;

    property X: String read GetPropX write SetPropX;
    property XB : TBytes read GetPropXB write SetPropXB;

    property Y: String read GetPropY write SetPropY;
    property YB : TBytes read GetPropYB write SetPropYB;

    property Index: integer read FIndex write FIndex;
  end;

  TipcDSAKeyList = class(TPersistent)
  protected
    FItems: TList;
    FReadOnlyProp: Boolean;
    FOwnerCtl: TObject;
    FCount: integer;
  protected
    function GetCount: Integer;
    function GetItem(Idx: integer): TipcDSAKey;
    procedure SetItem(Idx: integer; Value: TipcDSAKey);
    function GetIsReadOnly: boolean;
    function GetIsFixedSize: boolean;
    function GetSyncRoot: TObject;
    function GetIsSynchronized: boolean;
    procedure ClearList;

    function IsFree: boolean;
    procedure SyncCount;
    procedure InternalSetCount(Value: integer);
    procedure InternalSetItem(Index: integer; Value: TipcDSAKey);

    function CtlGetCount: integer; virtual;
    procedure CtlSetCount(Value: integer); virtual;
    function CreateElemInstance(Index: integer): TipcDSAKey; virtual;


  public
    constructor Create(); overload;
    constructor Create(ReadOnly: Boolean); overload;
    constructor Create(Owner: TObject; ReadOnly: Boolean); overload;
    destructor Destroy; override;

    procedure Assign(Source: TPersistent); override;
    function Clone: TipcDSAKeyList;

    function Add(Value: TipcDSAKey): Integer; overload;
    function Add(): Integer; overload;
    procedure Remove(value: TipcDSAKey);

    function Contains(value: TipcDSAKey): Boolean;
    
    function IndexOf(value: TipcDSAKey): Integer;
    procedure Insert(Idx: Integer; value: TipcDSAKey);
    procedure RemoveAt(idx: Integer);
    
    
    procedure Clear();

    property Count: Integer read GetCount;
    property Item[Index: Integer]: TipcDSAKey read GetItem write SetItem; default;
    property IsReadOnly: boolean read GetIsReadOnly;
    property IsFixedSize: boolean read GetIsFixedSize;
    property SyncRoot: TObject read GetSyncRoot;
    property IsSynchronized: boolean read GetIsSynchronized;
  end;
  TipcECCKey = class(TPersistent)
  protected
    FOwnerCtl: TObject;
    FReadOnlyProp: boolean;
    FIndex: integer;

    FAlgorithm: TipcECAlgorithms;

    FK: TBytes;

    FPrivateKey: String;

    FPublicKey: String;

    FRx: TBytes;

    FRy: TBytes;

    FXPk: TBytes;

    FXSk: TBytes;


    constructor Create(Owner: TObject; ReadOnly: boolean); overload;

    function GetPropAlgorithm: TipcECAlgorithms; virtual;
    procedure SetPropAlgorithm(Value: TipcECAlgorithms); virtual;

    function GetPropK: String; virtual;
    procedure SetPropK(Value: String); virtual;
    function  GetPropKB : TBytes; virtual;
    procedure SetPropKB(Value: TBytes); virtual;

    function GetPropPrivateKey: String; virtual;
    procedure SetPropPrivateKey(Value: String); virtual;

    function GetPropPublicKey: String; virtual;
    procedure SetPropPublicKey(Value: String); virtual;

    function GetPropRx: String; virtual;
    procedure SetPropRx(Value: String); virtual;
    function  GetPropRxB : TBytes; virtual;
    procedure SetPropRxB(Value: TBytes); virtual;

    function GetPropRy: String; virtual;
    procedure SetPropRy(Value: String); virtual;
    function  GetPropRyB : TBytes; virtual;
    procedure SetPropRyB(Value: TBytes); virtual;

    function GetPropXPk: String; virtual;
    procedure SetPropXPk(Value: String); virtual;
    function  GetPropXPkB : TBytes; virtual;
    procedure SetPropXPkB(Value: TBytes); virtual;

    function GetPropXSk: String; virtual;
    procedure SetPropXSk(Value: String); virtual;
    function  GetPropXSkB : TBytes; virtual;
    procedure SetPropXSkB(Value: TBytes); virtual;


  public
    constructor Create(); overload; virtual;

    destructor Destroy; override;

    procedure Assign(Source: TPersistent); override;
    function Clone: TipcECCKey; virtual;


    property Algorithm: TipcECAlgorithms read GetPropAlgorithm write SetPropAlgorithm;

    property K: String read GetPropK write SetPropK;
    property KB : TBytes read GetPropKB write SetPropKB;

    property PrivateKey: String read GetPropPrivateKey write SetPropPrivateKey;

    property PublicKey: String read GetPropPublicKey write SetPropPublicKey;

    property Rx: String read GetPropRx write SetPropRx;
    property RxB : TBytes read GetPropRxB write SetPropRxB;

    property Ry: String read GetPropRy write SetPropRy;
    property RyB : TBytes read GetPropRyB write SetPropRyB;

    property XPk: String read GetPropXPk write SetPropXPk;
    property XPkB : TBytes read GetPropXPkB write SetPropXPkB;

    property XSk: String read GetPropXSk write SetPropXSk;
    property XSkB : TBytes read GetPropXSkB write SetPropXSkB;

    property Index: integer read FIndex write FIndex;
  end;

  TipcECCKeyList = class(TPersistent)
  protected
    FItems: TList;
    FReadOnlyProp: Boolean;
    FOwnerCtl: TObject;
    FCount: integer;
  protected
    function GetCount: Integer;
    function GetItem(Idx: integer): TipcECCKey;
    procedure SetItem(Idx: integer; Value: TipcECCKey);
    function GetIsReadOnly: boolean;
    function GetIsFixedSize: boolean;
    function GetSyncRoot: TObject;
    function GetIsSynchronized: boolean;
    procedure ClearList;

    function IsFree: boolean;
    procedure SyncCount;
    procedure InternalSetCount(Value: integer);
    procedure InternalSetItem(Index: integer; Value: TipcECCKey);

    function CtlGetCount: integer; virtual;
    procedure CtlSetCount(Value: integer); virtual;
    function CreateElemInstance(Index: integer): TipcECCKey; virtual;


  public
    constructor Create(); overload;
    constructor Create(ReadOnly: Boolean); overload;
    constructor Create(Owner: TObject; ReadOnly: Boolean); overload;
    destructor Destroy; override;

    procedure Assign(Source: TPersistent); override;
    function Clone: TipcECCKeyList;

    function Add(Value: TipcECCKey): Integer; overload;
    function Add(): Integer; overload;
    procedure Remove(value: TipcECCKey);

    function Contains(value: TipcECCKey): Boolean;
    
    function IndexOf(value: TipcECCKey): Integer;
    procedure Insert(Idx: Integer; value: TipcECCKey);
    procedure RemoveAt(idx: Integer);
    
    
    procedure Clear();

    property Count: Integer read GetCount;
    property Item[Index: Integer]: TipcECCKey read GetItem write SetItem; default;
    property IsReadOnly: boolean read GetIsReadOnly;
    property IsFixedSize: boolean read GetIsFixedSize;
    property SyncRoot: TObject read GetSyncRoot;
    property IsSynchronized: boolean read GetIsSynchronized;
  end;
  TipcElgamalKey = class(TPersistent)
  protected
    FOwnerCtl: TObject;
    FReadOnlyProp: boolean;
    FIndex: integer;

    FG: TBytes;

    FP: TBytes;

    FPrivateKey: String;

    FPublicKey: String;

    FX: TBytes;

    FY: TBytes;


    constructor Create(Owner: TObject; ReadOnly: boolean); overload;

    function GetPropG: String; virtual;
    procedure SetPropG(Value: String); virtual;
    function  GetPropGB : TBytes; virtual;
    procedure SetPropGB(Value: TBytes); virtual;

    function GetPropP: String; virtual;
    procedure SetPropP(Value: String); virtual;
    function  GetPropPB : TBytes; virtual;
    procedure SetPropPB(Value: TBytes); virtual;

    function GetPropPrivateKey: String; virtual;
    procedure SetPropPrivateKey(Value: String); virtual;

    function GetPropPublicKey: String; virtual;
    procedure SetPropPublicKey(Value: String); virtual;

    function GetPropX: String; virtual;
    procedure SetPropX(Value: String); virtual;
    function  GetPropXB : TBytes; virtual;
    procedure SetPropXB(Value: TBytes); virtual;

    function GetPropY: String; virtual;
    procedure SetPropY(Value: String); virtual;
    function  GetPropYB : TBytes; virtual;
    procedure SetPropYB(Value: TBytes); virtual;


  public
    constructor Create(); overload; virtual;
    constructor Create(valP: TBytes; valG: TBytes; valY: TBytes); overload; virtual;
    constructor Create(valP: TBytes; valG: TBytes; valY: TBytes; valX: TBytes); overload; virtual;

    destructor Destroy; override;

    procedure Assign(Source: TPersistent); override;
    function Clone: TipcElgamalKey; virtual;


    property G: String read GetPropG write SetPropG;
    property GB : TBytes read GetPropGB write SetPropGB;

    property P: String read GetPropP write SetPropP;
    property PB : TBytes read GetPropPB write SetPropPB;

    property PrivateKey: String read GetPropPrivateKey write SetPropPrivateKey;

    property PublicKey: String read GetPropPublicKey write SetPropPublicKey;

    property X: String read GetPropX write SetPropX;
    property XB : TBytes read GetPropXB write SetPropXB;

    property Y: String read GetPropY write SetPropY;
    property YB : TBytes read GetPropYB write SetPropYB;

    property Index: integer read FIndex write FIndex;
  end;

  TipcElgamalKeyList = class(TPersistent)
  protected
    FItems: TList;
    FReadOnlyProp: Boolean;
    FOwnerCtl: TObject;
    FCount: integer;
  protected
    function GetCount: Integer;
    function GetItem(Idx: integer): TipcElgamalKey;
    procedure SetItem(Idx: integer; Value: TipcElgamalKey);
    function GetIsReadOnly: boolean;
    function GetIsFixedSize: boolean;
    function GetSyncRoot: TObject;
    function GetIsSynchronized: boolean;
    procedure ClearList;

    function IsFree: boolean;
    procedure SyncCount;
    procedure InternalSetCount(Value: integer);
    procedure InternalSetItem(Index: integer; Value: TipcElgamalKey);

    function CtlGetCount: integer; virtual;
    procedure CtlSetCount(Value: integer); virtual;
    function CreateElemInstance(Index: integer): TipcElgamalKey; virtual;


  public
    constructor Create(); overload;
    constructor Create(ReadOnly: Boolean); overload;
    constructor Create(Owner: TObject; ReadOnly: Boolean); overload;
    destructor Destroy; override;

    procedure Assign(Source: TPersistent); override;
    function Clone: TipcElgamalKeyList;

    function Add(Value: TipcElgamalKey): Integer; overload;
    function Add(): Integer; overload;
    procedure Remove(value: TipcElgamalKey);

    function Contains(value: TipcElgamalKey): Boolean;
    
    function IndexOf(value: TipcElgamalKey): Integer;
    procedure Insert(Idx: Integer; value: TipcElgamalKey);
    procedure RemoveAt(idx: Integer);
    
    
    procedure Clear();

    property Count: Integer read GetCount;
    property Item[Index: Integer]: TipcElgamalKey read GetItem write SetItem; default;
    property IsReadOnly: boolean read GetIsReadOnly;
    property IsFixedSize: boolean read GetIsFixedSize;
    property SyncRoot: TObject read GetSyncRoot;
    property IsSynchronized: boolean read GetIsSynchronized;
  end;
  TipcHeader = class(TPersistent)
  protected
    FOwnerCtl: TObject;
    FReadOnlyProp: boolean;
    FIndex: integer;

    FField: String;

    FValue: String;


    constructor Create(Owner: TObject; ReadOnly: boolean); overload;

    function GetPropField: String; virtual;
    procedure SetPropField(Value: String); virtual;

    function GetPropValue: String; virtual;
    procedure SetPropValue(Value: String); virtual;


  public
    constructor Create(); overload; virtual;
    constructor Create(valField: String; valValue: String); overload; virtual;

    destructor Destroy; override;

    procedure Assign(Source: TPersistent); override;
    function Clone: TipcHeader; virtual;


    property Field: String read GetPropField write SetPropField;

    property Value: String read GetPropValue write SetPropValue;

    property Index: integer read FIndex write FIndex;
  end;

  TipcHeaderList = class(TPersistent)
  protected
    FItems: TList;
    FReadOnlyProp: Boolean;
    FOwnerCtl: TObject;
    FCount: integer;
  protected
    function GetCount: Integer;
    function GetItem(Idx: integer): TipcHeader;
    procedure SetItem(Idx: integer; Value: TipcHeader);
    function GetIsReadOnly: boolean;
    function GetIsFixedSize: boolean;
    function GetSyncRoot: TObject;
    function GetIsSynchronized: boolean;
    procedure ClearList;

    function IsFree: boolean;
    procedure SyncCount;
    procedure InternalSetCount(Value: integer);
    procedure InternalSetItem(Index: integer; Value: TipcHeader);

    function CtlGetCount: integer; virtual;
    procedure CtlSetCount(Value: integer); virtual;
    function CreateElemInstance(Index: integer): TipcHeader; virtual;


  public
    constructor Create(); overload;
    constructor Create(ReadOnly: Boolean); overload;
    constructor Create(Owner: TObject; ReadOnly: Boolean); overload;
    destructor Destroy; override;

    procedure Assign(Source: TPersistent); override;
    function Clone: TipcHeaderList;

    function Add(Value: TipcHeader): Integer; overload;
    function Add(): Integer; overload;
    procedure Remove(value: TipcHeader);

    function Contains(value: TipcHeader): Boolean;
    
    function IndexOf(value: TipcHeader): Integer;
    procedure Insert(Idx: Integer; value: TipcHeader);
    procedure RemoveAt(idx: Integer);
    
    
    procedure Clear();

    property Count: Integer read GetCount;
    property Item[Index: Integer]: TipcHeader read GetItem write SetItem; default;
    property IsReadOnly: boolean read GetIsReadOnly;
    property IsFixedSize: boolean read GetIsFixedSize;
    property SyncRoot: TObject read GetSyncRoot;
    property IsSynchronized: boolean read GetIsSynchronized;
  end;
  TipcHeaderParam = class(TPersistent)
  protected
    FOwnerCtl: TObject;
    FReadOnlyProp: boolean;
    FIndex: integer;

    FDataType: TipcTDataTypes;

    FName: String;

    FValue: String;


    constructor Create(Owner: TObject; ReadOnly: boolean); overload;

    function GetPropDataType: TipcTDataTypes; virtual;
    procedure SetPropDataType(Value: TipcTDataTypes); virtual;

    function GetPropName: String; virtual;
    procedure SetPropName(Value: String); virtual;

    function GetPropValue: String; virtual;
    procedure SetPropValue(Value: String); virtual;


  public
    constructor Create(); overload; virtual;
    constructor Create(valName: String; valValue: String); overload; virtual;

    destructor Destroy; override;

    procedure Assign(Source: TPersistent); override;
    function Clone: TipcHeaderParam; virtual;


    property DataType: TipcTDataTypes read GetPropDataType write SetPropDataType;

    property Name: String read GetPropName write SetPropName;

    property Value: String read GetPropValue write SetPropValue;

    property Index: integer read FIndex write FIndex;
  end;

  TipcHeaderParamList = class(TPersistent)
  protected
    FItems: TList;
    FReadOnlyProp: Boolean;
    FOwnerCtl: TObject;
    FCount: integer;
  protected
    function GetCount: Integer;
    function GetItem(Idx: integer): TipcHeaderParam;
    procedure SetItem(Idx: integer; Value: TipcHeaderParam);
    function GetIsReadOnly: boolean;
    function GetIsFixedSize: boolean;
    function GetSyncRoot: TObject;
    function GetIsSynchronized: boolean;
    procedure ClearList;

    function IsFree: boolean;
    procedure SyncCount;
    procedure InternalSetCount(Value: integer);
    procedure InternalSetItem(Index: integer; Value: TipcHeaderParam);

    function CtlGetCount: integer; virtual;
    procedure CtlSetCount(Value: integer); virtual;
    function CreateElemInstance(Index: integer): TipcHeaderParam; virtual;


  public
    constructor Create(); overload;
    constructor Create(ReadOnly: Boolean); overload;
    constructor Create(Owner: TObject; ReadOnly: Boolean); overload;
    destructor Destroy; override;

    procedure Assign(Source: TPersistent); override;
    function Clone: TipcHeaderParamList;

    function Add(Value: TipcHeaderParam): Integer; overload;
    function Add(): Integer; overload;
    procedure Remove(value: TipcHeaderParam);

    function Contains(value: TipcHeaderParam): Boolean;
    
    function IndexOf(value: TipcHeaderParam): Integer;
    procedure Insert(Idx: Integer; value: TipcHeaderParam);
    procedure RemoveAt(idx: Integer);
    
    
    procedure Clear();

    property Count: Integer read GetCount;
    property Item[Index: Integer]: TipcHeaderParam read GetItem write SetItem; default;
    property IsReadOnly: boolean read GetIsReadOnly;
    property IsFixedSize: boolean read GetIsFixedSize;
    property SyncRoot: TObject read GetSyncRoot;
    property IsSynchronized: boolean read GetIsSynchronized;
  end;
  TipcKey = class(TPersistent)
  protected
    FOwnerCtl: TObject;
    FReadOnlyProp: boolean;
    FIndex: integer;

    FCurve: String;

    FEffectiveDate: String;

    FEncoded: TBytes;

    FExpirationDate: String;

    FFingerprint: String;

    FId: String;

    FKeyring: String;

    FOtherUserIds: String;

    FPassphrase: String;

    FPublicKey: String;

    FPublicKeyAlgorithm: String;

    FPublicKeyLength: Integer;

    FRevoked: Boolean;

    FSecretKey: String;

    FSecretKeyAvailable: Boolean;

    FUsage: String;

    FUsageFlags: Integer;

    FUserId: String;


    constructor Create(Owner: TObject; ReadOnly: boolean); overload;

    function GetPropCurve: String; virtual;
    procedure SetPropCurve(Value: String); virtual;

    function GetPropEffectiveDate: String; virtual;
    procedure SetPropEffectiveDate(Value: String); virtual;

    function GetPropEncoded: String; virtual;
    procedure SetPropEncoded(Value: String); virtual;
    function  GetPropEncodedB : TBytes; virtual;
    procedure SetPropEncodedB(Value: TBytes); virtual;

    function GetPropExpirationDate: String; virtual;
    procedure SetPropExpirationDate(Value: String); virtual;

    function GetPropFingerprint: String; virtual;
    procedure SetPropFingerprint(Value: String); virtual;

    function GetPropId: String; virtual;
    procedure SetPropId(Value: String); virtual;

    function GetPropKeyring: String; virtual;
    procedure SetPropKeyring(Value: String); virtual;

    function GetPropOtherUserIds: String; virtual;
    procedure SetPropOtherUserIds(Value: String); virtual;

    function GetPropPassphrase: String; virtual;
    procedure SetPropPassphrase(Value: String); virtual;

    function GetPropPublicKey: String; virtual;
    procedure SetPropPublicKey(Value: String); virtual;

    function GetPropPublicKeyAlgorithm: String; virtual;
    procedure SetPropPublicKeyAlgorithm(Value: String); virtual;

    function GetPropPublicKeyLength: Integer; virtual;
    procedure SetPropPublicKeyLength(Value: Integer); virtual;

    function GetPropRevoked: Boolean; virtual;
    procedure SetPropRevoked(Value: Boolean); virtual;

    function GetPropSecretKey: String; virtual;
    procedure SetPropSecretKey(Value: String); virtual;

    function GetPropSecretKeyAvailable: Boolean; virtual;
    procedure SetPropSecretKeyAvailable(Value: Boolean); virtual;

    function GetPropUsage: String; virtual;
    procedure SetPropUsage(Value: String); virtual;

    function GetPropUsageFlags: Integer; virtual;
    procedure SetPropUsageFlags(Value: Integer); virtual;

    function GetPropUserId: String; virtual;
    procedure SetPropUserId(Value: String); virtual;


  public

    destructor Destroy; override;

    procedure Assign(Source: TPersistent); override;
    function Clone: TipcKey; virtual;


    property Curve: String read GetPropCurve;

    property EffectiveDate: String read GetPropEffectiveDate;

    property Encoded: String read GetPropEncoded write SetPropEncoded;
    property EncodedB : TBytes read GetPropEncodedB write SetPropEncodedB;

    property ExpirationDate: String read GetPropExpirationDate;

    property Fingerprint: String read GetPropFingerprint;

    property Id: String read GetPropId;

    property Keyring: String read GetPropKeyring write SetPropKeyring;

    property OtherUserIds: String read GetPropOtherUserIds;

    property Passphrase: String read GetPropPassphrase write SetPropPassphrase;

    property PublicKey: String read GetPropPublicKey;

    property PublicKeyAlgorithm: String read GetPropPublicKeyAlgorithm;

    property PublicKeyLength: Integer read GetPropPublicKeyLength;

    property Revoked: Boolean read GetPropRevoked;

    property SecretKey: String read GetPropSecretKey;

    property SecretKeyAvailable: Boolean read GetPropSecretKeyAvailable;

    property Usage: String read GetPropUsage;

    property UsageFlags: Integer read GetPropUsageFlags;

    property UserId: String read GetPropUserId write SetPropUserId;

    property Index: integer read FIndex write FIndex;
  end;

  TipcKeyList = class(TPersistent)
  protected
    FItems: TList;
    FReadOnlyProp: Boolean;
    FOwnerCtl: TObject;
    FCount: integer;
  protected
    function GetCount: Integer;
    function GetItem(Idx: integer): TipcKey;
    procedure SetItem(Idx: integer; Value: TipcKey);
    function GetIsReadOnly: boolean;
    function GetIsFixedSize: boolean;
    function GetSyncRoot: TObject;
    function GetIsSynchronized: boolean;
    procedure ClearList;

    function IsFree: boolean;
    procedure SyncCount;
    procedure InternalSetCount(Value: integer);
    procedure InternalSetItem(Index: integer; Value: TipcKey);

    function CtlGetCount: integer; virtual;
    procedure CtlSetCount(Value: integer); virtual;
    function CreateElemInstance(Index: integer): TipcKey; virtual;


  public
    constructor Create(); overload;
    constructor Create(ReadOnly: Boolean); overload;
    constructor Create(Owner: TObject; ReadOnly: Boolean); overload;
    destructor Destroy; override;

    procedure Assign(Source: TPersistent); override;
    function Clone: TipcKeyList;

    function Add(Value: TipcKey): Integer; overload;
    function Add(): Integer; overload;
    procedure Remove(value: TipcKey);

    function Contains(value: TipcKey): Boolean;
    
    function IndexOf(value: TipcKey): Integer;
    procedure Insert(Idx: Integer; value: TipcKey);
    procedure RemoveAt(idx: Integer);
    
    
    procedure Clear();

    property Count: Integer read GetCount;
    property Item[Index: Integer]: TipcKey read GetItem write SetItem; default;
    property IsReadOnly: boolean read GetIsReadOnly;
    property IsFixedSize: boolean read GetIsFixedSize;
    property SyncRoot: TObject read GetSyncRoot;
    property IsSynchronized: boolean read GetIsSynchronized;
  end;
  TipcRSAKey = class(TPersistent)
  protected
    FOwnerCtl: TObject;
    FReadOnlyProp: boolean;
    FIndex: integer;

    FD: TBytes;

    FDP: TBytes;

    FDQ: TBytes;

    FExponent: TBytes;

    FInverseQ: TBytes;

    FModulus: TBytes;

    FP: TBytes;

    FPrivateKey: String;

    FPublicKey: String;

    FQ: TBytes;


    constructor Create(Owner: TObject; ReadOnly: boolean); overload;

    function GetPropD: String; virtual;
    procedure SetPropD(Value: String); virtual;
    function  GetPropDB : TBytes; virtual;
    procedure SetPropDB(Value: TBytes); virtual;

    function GetPropDP: String; virtual;
    procedure SetPropDP(Value: String); virtual;
    function  GetPropDPB : TBytes; virtual;
    procedure SetPropDPB(Value: TBytes); virtual;

    function GetPropDQ: String; virtual;
    procedure SetPropDQ(Value: String); virtual;
    function  GetPropDQB : TBytes; virtual;
    procedure SetPropDQB(Value: TBytes); virtual;

    function GetPropExponent: String; virtual;
    procedure SetPropExponent(Value: String); virtual;
    function  GetPropExponentB : TBytes; virtual;
    procedure SetPropExponentB(Value: TBytes); virtual;

    function GetPropInverseQ: String; virtual;
    procedure SetPropInverseQ(Value: String); virtual;
    function  GetPropInverseQB : TBytes; virtual;
    procedure SetPropInverseQB(Value: TBytes); virtual;

    function GetPropModulus: String; virtual;
    procedure SetPropModulus(Value: String); virtual;
    function  GetPropModulusB : TBytes; virtual;
    procedure SetPropModulusB(Value: TBytes); virtual;

    function GetPropP: String; virtual;
    procedure SetPropP(Value: String); virtual;
    function  GetPropPB : TBytes; virtual;
    procedure SetPropPB(Value: TBytes); virtual;

    function GetPropPrivateKey: String; virtual;
    procedure SetPropPrivateKey(Value: String); virtual;

    function GetPropPublicKey: String; virtual;
    procedure SetPropPublicKey(Value: String); virtual;

    function GetPropQ: String; virtual;
    procedure SetPropQ(Value: String); virtual;
    function  GetPropQB : TBytes; virtual;
    procedure SetPropQB(Value: TBytes); virtual;


  public
    constructor Create(); overload; virtual;
    constructor Create(valModulus: TBytes; valExponent: TBytes); overload; virtual;
    constructor Create(valModulus: TBytes; valD: TBytes; valP: TBytes; valQ: TBytes; valDP: TBytes; valDQ: TBytes); overload; virtual;

    destructor Destroy; override;

    procedure Assign(Source: TPersistent); override;
    function Clone: TipcRSAKey; virtual;


    property D: String read GetPropD write SetPropD;
    property DB : TBytes read GetPropDB write SetPropDB;

    property DP: String read GetPropDP write SetPropDP;
    property DPB : TBytes read GetPropDPB write SetPropDPB;

    property DQ: String read GetPropDQ write SetPropDQ;
    property DQB : TBytes read GetPropDQB write SetPropDQB;

    property Exponent: String read GetPropExponent write SetPropExponent;
    property ExponentB : TBytes read GetPropExponentB write SetPropExponentB;

    property InverseQ: String read GetPropInverseQ write SetPropInverseQ;
    property InverseQB : TBytes read GetPropInverseQB write SetPropInverseQB;

    property Modulus: String read GetPropModulus write SetPropModulus;
    property ModulusB : TBytes read GetPropModulusB write SetPropModulusB;

    property P: String read GetPropP write SetPropP;
    property PB : TBytes read GetPropPB write SetPropPB;

    property PrivateKey: String read GetPropPrivateKey write SetPropPrivateKey;

    property PublicKey: String read GetPropPublicKey write SetPropPublicKey;

    property Q: String read GetPropQ write SetPropQ;
    property QB : TBytes read GetPropQB write SetPropQB;

    property Index: integer read FIndex write FIndex;
  end;

  TipcRSAKeyList = class(TPersistent)
  protected
    FItems: TList;
    FReadOnlyProp: Boolean;
    FOwnerCtl: TObject;
    FCount: integer;
  protected
    function GetCount: Integer;
    function GetItem(Idx: integer): TipcRSAKey;
    procedure SetItem(Idx: integer; Value: TipcRSAKey);
    function GetIsReadOnly: boolean;
    function GetIsFixedSize: boolean;
    function GetSyncRoot: TObject;
    function GetIsSynchronized: boolean;
    procedure ClearList;

    function IsFree: boolean;
    procedure SyncCount;
    procedure InternalSetCount(Value: integer);
    procedure InternalSetItem(Index: integer; Value: TipcRSAKey);

    function CtlGetCount: integer; virtual;
    procedure CtlSetCount(Value: integer); virtual;
    function CreateElemInstance(Index: integer): TipcRSAKey; virtual;


  public
    constructor Create(); overload;
    constructor Create(ReadOnly: Boolean); overload;
    constructor Create(Owner: TObject; ReadOnly: Boolean); overload;
    destructor Destroy; override;

    procedure Assign(Source: TPersistent); override;
    function Clone: TipcRSAKeyList;

    function Add(Value: TipcRSAKey): Integer; overload;
    function Add(): Integer; overload;
    procedure Remove(value: TipcRSAKey);

    function Contains(value: TipcRSAKey): Boolean;
    
    function IndexOf(value: TipcRSAKey): Integer;
    procedure Insert(Idx: Integer; value: TipcRSAKey);
    procedure RemoveAt(idx: Integer);
    
    
    procedure Clear();

    property Count: Integer read GetCount;
    property Item[Index: Integer]: TipcRSAKey read GetItem write SetItem; default;
    property IsReadOnly: boolean read GetIsReadOnly;
    property IsFixedSize: boolean read GetIsFixedSize;
    property SyncRoot: TObject read GetSyncRoot;
    property IsSynchronized: boolean read GetIsSynchronized;
  end;
  TipcXMLEncryptedDataDetail = class(TPersistent)
  protected
    FOwnerCtl: TObject;
    FReadOnlyProp: boolean;
    FIndex: integer;

    FId: String;

    FMIMEType: String;

    FScope: TipcScopes;

    FXMLElement: String;


    constructor Create(Owner: TObject; ReadOnly: boolean); overload;

    function GetPropId: String; virtual;
    procedure SetPropId(Value: String); virtual;

    function GetPropMIMEType: String; virtual;
    procedure SetPropMIMEType(Value: String); virtual;

    function GetPropScope: TipcScopes; virtual;
    procedure SetPropScope(Value: TipcScopes); virtual;

    function GetPropXMLElement: String; virtual;
    procedure SetPropXMLElement(Value: String); virtual;


  public
    constructor Create(); overload; virtual;

    destructor Destroy; override;

    procedure Assign(Source: TPersistent); override;
    function Clone: TipcXMLEncryptedDataDetail; virtual;


    property Id: String read GetPropId write SetPropId;

    property MIMEType: String read GetPropMIMEType write SetPropMIMEType;

    property Scope: TipcScopes read GetPropScope write SetPropScope;

    property XMLElement: String read GetPropXMLElement write SetPropXMLElement;

    property Index: integer read FIndex write FIndex;
  end;

  TipcXMLEncryptedDataDetailList = class(TPersistent)
  protected
    FItems: TList;
    FReadOnlyProp: Boolean;
    FOwnerCtl: TObject;
    FCount: integer;
  protected
    function GetCount: Integer;
    function GetItem(Idx: integer): TipcXMLEncryptedDataDetail;
    procedure SetItem(Idx: integer; Value: TipcXMLEncryptedDataDetail);
    function GetIsReadOnly: boolean;
    function GetIsFixedSize: boolean;
    function GetSyncRoot: TObject;
    function GetIsSynchronized: boolean;
    procedure ClearList;

    function IsFree: boolean;
    procedure SyncCount;
    procedure InternalSetCount(Value: integer);
    procedure InternalSetItem(Index: integer; Value: TipcXMLEncryptedDataDetail);

    function CtlGetCount: integer; virtual;
    procedure CtlSetCount(Value: integer); virtual;
    function CreateElemInstance(Index: integer): TipcXMLEncryptedDataDetail; virtual;


  public
    constructor Create(); overload;
    constructor Create(ReadOnly: Boolean); overload;
    constructor Create(Owner: TObject; ReadOnly: Boolean); overload;
    destructor Destroy; override;

    procedure Assign(Source: TPersistent); override;
    function Clone: TipcXMLEncryptedDataDetailList;

    function Add(Value: TipcXMLEncryptedDataDetail): Integer; overload;
    function Add(): Integer; overload;
    procedure Remove(value: TipcXMLEncryptedDataDetail);

    function Contains(value: TipcXMLEncryptedDataDetail): Boolean;
    
    function IndexOf(value: TipcXMLEncryptedDataDetail): Integer;
    procedure Insert(Idx: Integer; value: TipcXMLEncryptedDataDetail);
    procedure RemoveAt(idx: Integer);
    
    
    procedure Clear();

    property Count: Integer read GetCount;
    property Item[Index: Integer]: TipcXMLEncryptedDataDetail read GetItem write SetItem; default;
    property IsReadOnly: boolean read GetIsReadOnly;
    property IsFixedSize: boolean read GetIsFixedSize;
    property SyncRoot: TObject read GetSyncRoot;
    property IsSynchronized: boolean read GetIsSynchronized;
  end;
  TipcXMLSigReference = class(TPersistent)
  protected
    FOwnerCtl: TObject;
    FReadOnlyProp: boolean;
    FIndex: integer;

    FHashAlgorithm: String;

    FHashValue: String;

    FTransformAlgorithms: String;

    FURI: String;

    FXMLElement: String;


    constructor Create(Owner: TObject; ReadOnly: boolean); overload;

    function GetPropHashAlgorithm: String; virtual;
    procedure SetPropHashAlgorithm(Value: String); virtual;

    function GetPropHashValue: String; virtual;
    procedure SetPropHashValue(Value: String); virtual;

    function GetPropTransformAlgorithms: String; virtual;
    procedure SetPropTransformAlgorithms(Value: String); virtual;

    function GetPropURI: String; virtual;
    procedure SetPropURI(Value: String); virtual;

    function GetPropXMLElement: String; virtual;
    procedure SetPropXMLElement(Value: String); virtual;


  public
    constructor Create(); overload; virtual;
    constructor Create(valXMLElement: String; valURI: String; valHashAlgorithm: String; valTransformAlgorithms: String; valHashValue: String); overload; virtual;

    destructor Destroy; override;

    procedure Assign(Source: TPersistent); override;
    function Clone: TipcXMLSigReference; virtual;


    property HashAlgorithm: String read GetPropHashAlgorithm write SetPropHashAlgorithm;

    property HashValue: String read GetPropHashValue;

    property TransformAlgorithms: String read GetPropTransformAlgorithms write SetPropTransformAlgorithms;

    property URI: String read GetPropURI write SetPropURI;

    property XMLElement: String read GetPropXMLElement write SetPropXMLElement;

    property Index: integer read FIndex write FIndex;
  end;

  TipcXMLSigReferenceList = class(TPersistent)
  protected
    FItems: TList;
    FReadOnlyProp: Boolean;
    FOwnerCtl: TObject;
    FCount: integer;
  protected
    function GetCount: Integer;
    function GetItem(Idx: integer): TipcXMLSigReference;
    procedure SetItem(Idx: integer; Value: TipcXMLSigReference);
    function GetIsReadOnly: boolean;
    function GetIsFixedSize: boolean;
    function GetSyncRoot: TObject;
    function GetIsSynchronized: boolean;
    procedure ClearList;

    function IsFree: boolean;
    procedure SyncCount;
    procedure InternalSetCount(Value: integer);
    procedure InternalSetItem(Index: integer; Value: TipcXMLSigReference);

    function CtlGetCount: integer; virtual;
    procedure CtlSetCount(Value: integer); virtual;
    function CreateElemInstance(Index: integer): TipcXMLSigReference; virtual;


  public
    constructor Create(); overload;
    constructor Create(ReadOnly: Boolean); overload;
    constructor Create(Owner: TObject; ReadOnly: Boolean); overload;
    destructor Destroy; override;

    procedure Assign(Source: TPersistent); override;
    function Clone: TipcXMLSigReferenceList;

    function Add(Value: TipcXMLSigReference): Integer; overload;
    function Add(): Integer; overload;
    procedure Remove(value: TipcXMLSigReference);

    function Contains(value: TipcXMLSigReference): Boolean;
    
    function IndexOf(value: TipcXMLSigReference): Integer;
    procedure Insert(Idx: Integer; value: TipcXMLSigReference);
    procedure RemoveAt(idx: Integer);
    
    
    procedure Clear();

    property Count: Integer read GetCount;
    property Item[Index: Integer]: TipcXMLSigReference read GetItem write SetItem; default;
    property IsReadOnly: boolean read GetIsReadOnly;
    property IsFixedSize: boolean read GetIsFixedSize;
    property SyncRoot: TObject read GetSyncRoot;
    property IsSynchronized: boolean read GetIsSynchronized;
  end;


implementation

{$T-}
{$WARNINGS OFF}
{$HINTS OFF}


//////////////////////////////////////////////////////////////////////////////////////////
// TipcCertExtension type

constructor TipcCertExtension.Create(valoid: String; valvalue: TBytes; valcritical: Boolean);
begin
  inherited Create;
  FIndex := -1;
  FOwnerCtl := nil;
  FReadOnlyProp := false;
  Foid := valoid;
  Fvalue := valvalue;
  Fcritical := valcritical;
end;


constructor TipcCertExtension.Create(Owner: TObject; ReadOnly: boolean);
begin
  inherited Create;
  FOwnerCtl := Owner;
  FReadOnlyProp := ReadOnly;
  FIndex := -1;
end;

destructor TipcCertExtension.Destroy;
begin
  inherited;
end;

procedure TipcCertExtension.Assign(Source: TPersistent);
var
  i: integer;
  Src: TipcCertExtension;
begin
  // Copy contents using setters and getters. No owner or index is copied: this is simply an assignment
  // of a collection of fields to another object, not a creation of a full copy.
      
  if Source is TipcCertExtension then
  begin


    SetPropCritical(TipcCertExtension(Source).GetPropCritical);
    SetPropOID(TipcCertExtension(Source).GetPropOID);
    SetPropValue(TipcCertExtension(Source).GetPropValue);
  end
  else
    inherited;
end;

function TipcCertExtension.Clone: TipcCertExtension;
begin
  // Always clone to a freestanding instance of the base class
  Result := TipcCertExtension.Create(nil, FReadOnlyProp);
  Result.Assign(Self);
end;


function TipcCertExtension.GetPropCritical: Boolean;
begin
  Result := Boolean(FCritical);
end;

procedure TipcCertExtension.SetPropCritical(Value: Boolean);
begin
  FCritical := Value;
end;


function TipcCertExtension.GetPropOID: String;
begin
  Result := String(FOID);
end;

procedure TipcCertExtension.SetPropOID(Value: String);
begin
  FOID := Value;
end;


function TipcCertExtension.GetPropValue: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FValue);
end;

procedure TipcCertExtension.SetPropValue(Value: String);
begin
  FValue := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcCertExtension.GetPropValueB : TBytes; 
begin
  Result := FValue;
end;

procedure TipcCertExtension.SetPropValueB(Value: TBytes); 
begin
  FValue := Value;
end;


//////////////////////////////////////////////////////////////////////////////////////////
// TipcCertExtensionList type
constructor TipcCertExtensionList.Create();
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := false;
  FCount := 0;
  FOwnerCtl := nil;
end;

constructor TipcCertExtensionList.Create(ReadOnly: Boolean);
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := ReadOnly;
  FCount := 0;
  FOwnerCtl := nil;
end;

constructor TipcCertExtensionList.Create(Owner: TObject; ReadOnly: Boolean); 
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := ReadOnly;
  FCount := 0;
  FOwnerCtl := Owner;
end;

destructor TipcCertExtensionList.Destroy; 
begin
  ClearList;
  FreeAndNil(FItems);
  inherited;
end;

procedure TipcCertExtensionList.ClearList;
var
  Inst : TipcCertExtension;
  I: integer;
begin
  try
    for I := 0 to FItems.Count - 1 do
    begin
      Inst := TipcCertExtension(FItems[I]);
      {$ifndef AUTOREFCOUNT}
      Inst.Free;
      {$else}
      Inst.__ObjRelease;
      Inst.DisposeOf;
      {$endif};
    end;
  finally
    FItems.Clear;
  end;
end;

function TipcCertExtensionList.IsFree: boolean;
begin
  // This method tells the requestor whether the collection object is freestanding or bound
  Result := FOwnerCtl = nil;
end;

procedure TipcCertExtensionList.SyncCount;
var
  Inst : TipcCertExtension;
  I: integer;
begin
  // This method updates the number of objects held by the collection. It is only relevant for bound collections.
  if not IsFree then
  begin
    FCount := CtlGetCount();
    while FItems.Count < FCount do
    begin
      Inst := CreateElemInstance(FItems.Count);
      FItems.Add(Inst);
      {$ifdef AUTOREFCOUNT}
      Inst.__ObjAddRef;
      {$endif}
    end;
  end;
end;

procedure TipcCertExtensionList.InternalSetCount(Value: integer);
var
  Inst : TipcCertExtension;
begin
  // This method updates the number of elements in the underlying list. 
  // For both free and bound collections, it will verify that the list has sufficient capacity.
  while FItems.Count < Value do
  begin
    Inst := CreateElemInstance(FItems.Count);
    FItems.Add(Inst);
    {$ifdef AUTOREFCOUNT}
    Inst.__ObjAddRef;
    {$endif}
  end;

  if not IsFree then
    CtlSetCount(Value);
  FCount := Value;
end;

procedure TipcCertExtensionList.InternalSetItem(Index: integer; Value: TipcCertExtension);
begin
  // This method assigns (effectively copies) an item to collection.
  // It is expected that the boundaries have been checked before this method was called.
  TipcCertExtension(FItems[Index]).Assign(Value); // Assign, if needed, will redirect any setters to the underlying control's methods
end;

procedure TipcCertExtensionList.Assign(Source: TPersistent);
var
  i: integer;
  Src: TipcCertExtensionList;
begin
  if Source is TipcCertExtensionList then
  begin
    Src := TipcCertExtensionList(Source);
    InternalSetCount(Src.GetCount);
    for i := 0 to Src.GetCount - 1 do
      InternalSetItem(i, Src.GetItem(i));
      
  end
  else
    inherited;
end;

function TipcCertExtensionList.Clone: TipcCertExtensionList;
begin
  Result := TipcCertExtensionList.Create(FReadOnlyProp); // When cloning, always creating a freestanding object
  Result.Assign(Self);
  
end;

function TipcCertExtensionList.GetCount: Integer;
begin
  SyncCount;
  Result := FCount;
end;

function TipcCertExtensionList.GetItem(Idx: integer): TipcCertExtension;
begin
  SyncCount;  
  
  Result := TipcCertExtension(FItems[Idx]); 
end;

procedure TipcCertExtensionList.SetItem(Idx: integer; Value: TipcCertExtension);
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  
  if (Idx < 0) or (Idx >= GetCount) then
    raise Exception.Create('Index out of bounds');


  InternalSetItem(Idx, Value);
end;

function TipcCertExtensionList.GetIsReadOnly: boolean;
begin
  Result := FReadOnlyProp;
end;

function TipcCertExtensionList.GetIsFixedSize: boolean;
begin
  Result := false;
end;

function TipcCertExtensionList.GetSyncRoot: TObject;
begin
  raise Exception.Create('Not implemented');
end;

function TipcCertExtensionList.GetIsSynchronized: boolean;
begin
  Result := false;
end;

function TipcCertExtensionList.Add(Value: TipcCertExtension): Integer;
var
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  InternalSetCount(OldCount + 1);
  InternalSetItem(OldCount, Value);
  Result := OldCount;
end;

function TipcCertExtensionList.Add(): Integer; 
var
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  InternalSetCount(OldCount + 1);
  Result := OldCount;
end;

procedure TipcCertExtensionList.Remove(value: TipcCertExtension);
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  raise Exception.Create('Not implemented');
end;

function TipcCertExtensionList.Contains(value: TipcCertExtension): Boolean;
begin
  raise Exception.Create('Not implemented');
end;

function TipcCertExtensionList.IndexOf(value: TipcCertExtension): Integer;
begin
  raise Exception.Create('Not implemented');
end;

procedure TipcCertExtensionList.Insert(Idx: Integer; value: TipcCertExtension);
var
  OldCount: integer;
  I: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  if (Idx < 0) or (Idx >= OldCount) then
    raise Exception.Create('Index out of bounds');
  InternalSetCount(OldCount + 1);
  for I := OldCount downto Idx + 1 do
    InternalSetItem(I, GetItem(i - 1));
  InternalSetItem(Idx, value);
end;

procedure TipcCertExtensionList.RemoveAt(idx: Integer);
var
  I: integer;
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  if (Idx < 0) or (Idx >= OldCount) then
    raise Exception.Create('Index out of bounds');
  // Only copying the needed subset of elements, without cleaning them up
  for I := Idx to OldCount - 2 do
    InternalSetItem(I, GetItem(I + 1));
  InternalSetCount(OldCount - 1);
end;


procedure TipcCertExtensionList.Clear();
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  InternalSetCount(0);
end;

function TipcCertExtensionList.CtlGetCount: integer;
begin
  ; // to be overridden in derived classes
end;

procedure TipcCertExtensionList.CtlSetCount(Value: integer);
begin
  ; // to be overridden in derived classes
end;

function TipcCertExtensionList.CreateElemInstance(Index: integer): TipcCertExtension; 
begin
  Result := TipcCertExtension.Create(FOwnerCtl, FReadOnlyProp);
  Result.Index := Index;
end;


//////////////////////////////////////////////////////////////////////////////////////////
// TipcDSAKey type

constructor TipcDSAKey.Create();
begin
  inherited Create;
  FIndex := -1;
  FOwnerCtl := nil;
  FReadOnlyProp := false;
end;
constructor TipcDSAKey.Create(valP: TBytes; valQ: TBytes; valG: TBytes; valY: TBytes);
begin
  inherited Create;
  FIndex := -1;
  FOwnerCtl := nil;
  FReadOnlyProp := false;
  FP := valP;
  FQ := valQ;
  FG := valG;
  FY := valY;
end;
constructor TipcDSAKey.Create(valP: TBytes; valQ: TBytes; valG: TBytes; valY: TBytes; valX: TBytes);
begin
  inherited Create;
  FIndex := -1;
  FOwnerCtl := nil;
  FReadOnlyProp := false;
  FP := valP;
  FQ := valQ;
  FG := valG;
  FY := valY;
  FX := valX;
end;


constructor TipcDSAKey.Create(Owner: TObject; ReadOnly: boolean);
begin
  inherited Create;
  FOwnerCtl := Owner;
  FReadOnlyProp := ReadOnly;
  FIndex := -1;
end;

destructor TipcDSAKey.Destroy;
begin
  inherited;
end;

procedure TipcDSAKey.Assign(Source: TPersistent);
var
  i: integer;
  Src: TipcDSAKey;
begin
  // Copy contents using setters and getters. No owner or index is copied: this is simply an assignment
  // of a collection of fields to another object, not a creation of a full copy.
              
  if Source is TipcDSAKey then
  begin


    SetPropG(TipcDSAKey(Source).GetPropG);
    SetPropP(TipcDSAKey(Source).GetPropP);
    SetPropPrivateKey(TipcDSAKey(Source).GetPropPrivateKey);
    SetPropPublicKey(TipcDSAKey(Source).GetPropPublicKey);
    SetPropQ(TipcDSAKey(Source).GetPropQ);
    SetPropX(TipcDSAKey(Source).GetPropX);
    SetPropY(TipcDSAKey(Source).GetPropY);
  end
  else
    inherited;
end;

function TipcDSAKey.Clone: TipcDSAKey;
begin
  // Always clone to a freestanding instance of the base class
  Result := TipcDSAKey.Create(nil, FReadOnlyProp);
  Result.Assign(Self);
end;


function TipcDSAKey.GetPropG: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FG);
end;

procedure TipcDSAKey.SetPropG(Value: String);
begin
  FG := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcDSAKey.GetPropGB : TBytes; 
begin
  Result := FG;
end;

procedure TipcDSAKey.SetPropGB(Value: TBytes); 
begin
  FG := Value;
end;

function TipcDSAKey.GetPropP: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FP);
end;

procedure TipcDSAKey.SetPropP(Value: String);
begin
  FP := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcDSAKey.GetPropPB : TBytes; 
begin
  Result := FP;
end;

procedure TipcDSAKey.SetPropPB(Value: TBytes); 
begin
  FP := Value;
end;

function TipcDSAKey.GetPropPrivateKey: String;
begin
  Result := String(FPrivateKey);
end;

procedure TipcDSAKey.SetPropPrivateKey(Value: String);
begin
  FPrivateKey := Value;
end;


function TipcDSAKey.GetPropPublicKey: String;
begin
  Result := String(FPublicKey);
end;

procedure TipcDSAKey.SetPropPublicKey(Value: String);
begin
  FPublicKey := Value;
end;


function TipcDSAKey.GetPropQ: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FQ);
end;

procedure TipcDSAKey.SetPropQ(Value: String);
begin
  FQ := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcDSAKey.GetPropQB : TBytes; 
begin
  Result := FQ;
end;

procedure TipcDSAKey.SetPropQB(Value: TBytes); 
begin
  FQ := Value;
end;

function TipcDSAKey.GetPropX: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FX);
end;

procedure TipcDSAKey.SetPropX(Value: String);
begin
  FX := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcDSAKey.GetPropXB : TBytes; 
begin
  Result := FX;
end;

procedure TipcDSAKey.SetPropXB(Value: TBytes); 
begin
  FX := Value;
end;

function TipcDSAKey.GetPropY: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FY);
end;

procedure TipcDSAKey.SetPropY(Value: String);
begin
  FY := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcDSAKey.GetPropYB : TBytes; 
begin
  Result := FY;
end;

procedure TipcDSAKey.SetPropYB(Value: TBytes); 
begin
  FY := Value;
end;


//////////////////////////////////////////////////////////////////////////////////////////
// TipcDSAKeyList type
constructor TipcDSAKeyList.Create();
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := false;
  FCount := 0;
  FOwnerCtl := nil;
end;

constructor TipcDSAKeyList.Create(ReadOnly: Boolean);
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := ReadOnly;
  FCount := 0;
  FOwnerCtl := nil;
end;

constructor TipcDSAKeyList.Create(Owner: TObject; ReadOnly: Boolean); 
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := ReadOnly;
  FCount := 0;
  FOwnerCtl := Owner;
end;

destructor TipcDSAKeyList.Destroy; 
begin
  ClearList;
  FreeAndNil(FItems);
  inherited;
end;

procedure TipcDSAKeyList.ClearList;
var
  Inst : TipcDSAKey;
  I: integer;
begin
  try
    for I := 0 to FItems.Count - 1 do
    begin
      Inst := TipcDSAKey(FItems[I]);
      {$ifndef AUTOREFCOUNT}
      Inst.Free;
      {$else}
      Inst.__ObjRelease;
      Inst.DisposeOf;
      {$endif};
    end;
  finally
    FItems.Clear;
  end;
end;

function TipcDSAKeyList.IsFree: boolean;
begin
  // This method tells the requestor whether the collection object is freestanding or bound
  Result := FOwnerCtl = nil;
end;

procedure TipcDSAKeyList.SyncCount;
var
  Inst : TipcDSAKey;
  I: integer;
begin
  // This method updates the number of objects held by the collection. It is only relevant for bound collections.
  if not IsFree then
  begin
    FCount := CtlGetCount();
    while FItems.Count < FCount do
    begin
      Inst := CreateElemInstance(FItems.Count);
      FItems.Add(Inst);
      {$ifdef AUTOREFCOUNT}
      Inst.__ObjAddRef;
      {$endif}
    end;
  end;
end;

procedure TipcDSAKeyList.InternalSetCount(Value: integer);
var
  Inst : TipcDSAKey;
begin
  // This method updates the number of elements in the underlying list. 
  // For both free and bound collections, it will verify that the list has sufficient capacity.
  while FItems.Count < Value do
  begin
    Inst := CreateElemInstance(FItems.Count);
    FItems.Add(Inst);
    {$ifdef AUTOREFCOUNT}
    Inst.__ObjAddRef;
    {$endif}
  end;

  if not IsFree then
    CtlSetCount(Value);
  FCount := Value;
end;

procedure TipcDSAKeyList.InternalSetItem(Index: integer; Value: TipcDSAKey);
begin
  // This method assigns (effectively copies) an item to collection.
  // It is expected that the boundaries have been checked before this method was called.
  TipcDSAKey(FItems[Index]).Assign(Value); // Assign, if needed, will redirect any setters to the underlying control's methods
end;

procedure TipcDSAKeyList.Assign(Source: TPersistent);
var
  i: integer;
  Src: TipcDSAKeyList;
begin
  if Source is TipcDSAKeyList then
  begin
    Src := TipcDSAKeyList(Source);
    InternalSetCount(Src.GetCount);
    for i := 0 to Src.GetCount - 1 do
      InternalSetItem(i, Src.GetItem(i));
      
  end
  else
    inherited;
end;

function TipcDSAKeyList.Clone: TipcDSAKeyList;
begin
  Result := TipcDSAKeyList.Create(FReadOnlyProp); // When cloning, always creating a freestanding object
  Result.Assign(Self);
  
end;

function TipcDSAKeyList.GetCount: Integer;
begin
  SyncCount;
  Result := FCount;
end;

function TipcDSAKeyList.GetItem(Idx: integer): TipcDSAKey;
begin
  SyncCount;  
  
  Result := TipcDSAKey(FItems[Idx]); 
end;

procedure TipcDSAKeyList.SetItem(Idx: integer; Value: TipcDSAKey);
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  
  if (Idx < 0) or (Idx >= GetCount) then
    raise Exception.Create('Index out of bounds');


  InternalSetItem(Idx, Value);
end;

function TipcDSAKeyList.GetIsReadOnly: boolean;
begin
  Result := FReadOnlyProp;
end;

function TipcDSAKeyList.GetIsFixedSize: boolean;
begin
  Result := false;
end;

function TipcDSAKeyList.GetSyncRoot: TObject;
begin
  raise Exception.Create('Not implemented');
end;

function TipcDSAKeyList.GetIsSynchronized: boolean;
begin
  Result := false;
end;

function TipcDSAKeyList.Add(Value: TipcDSAKey): Integer;
var
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  InternalSetCount(OldCount + 1);
  InternalSetItem(OldCount, Value);
  Result := OldCount;
end;

function TipcDSAKeyList.Add(): Integer; 
var
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  InternalSetCount(OldCount + 1);
  Result := OldCount;
end;

procedure TipcDSAKeyList.Remove(value: TipcDSAKey);
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  raise Exception.Create('Not implemented');
end;

function TipcDSAKeyList.Contains(value: TipcDSAKey): Boolean;
begin
  raise Exception.Create('Not implemented');
end;

function TipcDSAKeyList.IndexOf(value: TipcDSAKey): Integer;
begin
  raise Exception.Create('Not implemented');
end;

procedure TipcDSAKeyList.Insert(Idx: Integer; value: TipcDSAKey);
var
  OldCount: integer;
  I: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  if (Idx < 0) or (Idx >= OldCount) then
    raise Exception.Create('Index out of bounds');
  InternalSetCount(OldCount + 1);
  for I := OldCount downto Idx + 1 do
    InternalSetItem(I, GetItem(i - 1));
  InternalSetItem(Idx, value);
end;

procedure TipcDSAKeyList.RemoveAt(idx: Integer);
var
  I: integer;
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  if (Idx < 0) or (Idx >= OldCount) then
    raise Exception.Create('Index out of bounds');
  // Only copying the needed subset of elements, without cleaning them up
  for I := Idx to OldCount - 2 do
    InternalSetItem(I, GetItem(I + 1));
  InternalSetCount(OldCount - 1);
end;


procedure TipcDSAKeyList.Clear();
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  InternalSetCount(0);
end;

function TipcDSAKeyList.CtlGetCount: integer;
begin
  ; // to be overridden in derived classes
end;

procedure TipcDSAKeyList.CtlSetCount(Value: integer);
begin
  ; // to be overridden in derived classes
end;

function TipcDSAKeyList.CreateElemInstance(Index: integer): TipcDSAKey; 
begin
  Result := TipcDSAKey.Create(FOwnerCtl, FReadOnlyProp);
  Result.Index := Index;
end;


//////////////////////////////////////////////////////////////////////////////////////////
// TipcECCKey type

constructor TipcECCKey.Create();
begin
  inherited Create;
  FIndex := -1;
  FOwnerCtl := nil;
  FReadOnlyProp := false;
end;


constructor TipcECCKey.Create(Owner: TObject; ReadOnly: boolean);
begin
  inherited Create;
  FOwnerCtl := Owner;
  FReadOnlyProp := ReadOnly;
  FIndex := -1;
end;

destructor TipcECCKey.Destroy;
begin
  inherited;
end;

procedure TipcECCKey.Assign(Source: TPersistent);
var
  i: integer;
  Src: TipcECCKey;
begin
  // Copy contents using setters and getters. No owner or index is copied: this is simply an assignment
  // of a collection of fields to another object, not a creation of a full copy.
                
  if Source is TipcECCKey then
  begin


    SetPropAlgorithm(TipcECCKey(Source).GetPropAlgorithm);
    SetPropK(TipcECCKey(Source).GetPropK);
    SetPropPrivateKey(TipcECCKey(Source).GetPropPrivateKey);
    SetPropPublicKey(TipcECCKey(Source).GetPropPublicKey);
    SetPropRx(TipcECCKey(Source).GetPropRx);
    SetPropRy(TipcECCKey(Source).GetPropRy);
    SetPropXPk(TipcECCKey(Source).GetPropXPk);
    SetPropXSk(TipcECCKey(Source).GetPropXSk);
  end
  else
    inherited;
end;

function TipcECCKey.Clone: TipcECCKey;
begin
  // Always clone to a freestanding instance of the base class
  Result := TipcECCKey.Create(nil, FReadOnlyProp);
  Result.Assign(Self);
end;


function TipcECCKey.GetPropAlgorithm: TipcECAlgorithms;
begin
  Result := {T}(FAlgorithm);
end;

procedure TipcECCKey.SetPropAlgorithm(Value: TipcECAlgorithms);
begin
  FAlgorithm := Value;
end;


function TipcECCKey.GetPropK: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FK);
end;

procedure TipcECCKey.SetPropK(Value: String);
begin
  FK := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcECCKey.GetPropKB : TBytes; 
begin
  Result := FK;
end;

procedure TipcECCKey.SetPropKB(Value: TBytes); 
begin
  FK := Value;
end;

function TipcECCKey.GetPropPrivateKey: String;
begin
  Result := String(FPrivateKey);
end;

procedure TipcECCKey.SetPropPrivateKey(Value: String);
begin
  FPrivateKey := Value;
end;


function TipcECCKey.GetPropPublicKey: String;
begin
  Result := String(FPublicKey);
end;

procedure TipcECCKey.SetPropPublicKey(Value: String);
begin
  FPublicKey := Value;
end;


function TipcECCKey.GetPropRx: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FRx);
end;

procedure TipcECCKey.SetPropRx(Value: String);
begin
  FRx := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcECCKey.GetPropRxB : TBytes; 
begin
  Result := FRx;
end;

procedure TipcECCKey.SetPropRxB(Value: TBytes); 
begin
  FRx := Value;
end;

function TipcECCKey.GetPropRy: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FRy);
end;

procedure TipcECCKey.SetPropRy(Value: String);
begin
  FRy := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcECCKey.GetPropRyB : TBytes; 
begin
  Result := FRy;
end;

procedure TipcECCKey.SetPropRyB(Value: TBytes); 
begin
  FRy := Value;
end;

function TipcECCKey.GetPropXPk: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FXPk);
end;

procedure TipcECCKey.SetPropXPk(Value: String);
begin
  FXPk := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcECCKey.GetPropXPkB : TBytes; 
begin
  Result := FXPk;
end;

procedure TipcECCKey.SetPropXPkB(Value: TBytes); 
begin
  FXPk := Value;
end;

function TipcECCKey.GetPropXSk: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FXSk);
end;

procedure TipcECCKey.SetPropXSk(Value: String);
begin
  FXSk := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcECCKey.GetPropXSkB : TBytes; 
begin
  Result := FXSk;
end;

procedure TipcECCKey.SetPropXSkB(Value: TBytes); 
begin
  FXSk := Value;
end;


//////////////////////////////////////////////////////////////////////////////////////////
// TipcECCKeyList type
constructor TipcECCKeyList.Create();
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := false;
  FCount := 0;
  FOwnerCtl := nil;
end;

constructor TipcECCKeyList.Create(ReadOnly: Boolean);
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := ReadOnly;
  FCount := 0;
  FOwnerCtl := nil;
end;

constructor TipcECCKeyList.Create(Owner: TObject; ReadOnly: Boolean); 
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := ReadOnly;
  FCount := 0;
  FOwnerCtl := Owner;
end;

destructor TipcECCKeyList.Destroy; 
begin
  ClearList;
  FreeAndNil(FItems);
  inherited;
end;

procedure TipcECCKeyList.ClearList;
var
  Inst : TipcECCKey;
  I: integer;
begin
  try
    for I := 0 to FItems.Count - 1 do
    begin
      Inst := TipcECCKey(FItems[I]);
      {$ifndef AUTOREFCOUNT}
      Inst.Free;
      {$else}
      Inst.__ObjRelease;
      Inst.DisposeOf;
      {$endif};
    end;
  finally
    FItems.Clear;
  end;
end;

function TipcECCKeyList.IsFree: boolean;
begin
  // This method tells the requestor whether the collection object is freestanding or bound
  Result := FOwnerCtl = nil;
end;

procedure TipcECCKeyList.SyncCount;
var
  Inst : TipcECCKey;
  I: integer;
begin
  // This method updates the number of objects held by the collection. It is only relevant for bound collections.
  if not IsFree then
  begin
    FCount := CtlGetCount();
    while FItems.Count < FCount do
    begin
      Inst := CreateElemInstance(FItems.Count);
      FItems.Add(Inst);
      {$ifdef AUTOREFCOUNT}
      Inst.__ObjAddRef;
      {$endif}
    end;
  end;
end;

procedure TipcECCKeyList.InternalSetCount(Value: integer);
var
  Inst : TipcECCKey;
begin
  // This method updates the number of elements in the underlying list. 
  // For both free and bound collections, it will verify that the list has sufficient capacity.
  while FItems.Count < Value do
  begin
    Inst := CreateElemInstance(FItems.Count);
    FItems.Add(Inst);
    {$ifdef AUTOREFCOUNT}
    Inst.__ObjAddRef;
    {$endif}
  end;

  if not IsFree then
    CtlSetCount(Value);
  FCount := Value;
end;

procedure TipcECCKeyList.InternalSetItem(Index: integer; Value: TipcECCKey);
begin
  // This method assigns (effectively copies) an item to collection.
  // It is expected that the boundaries have been checked before this method was called.
  TipcECCKey(FItems[Index]).Assign(Value); // Assign, if needed, will redirect any setters to the underlying control's methods
end;

procedure TipcECCKeyList.Assign(Source: TPersistent);
var
  i: integer;
  Src: TipcECCKeyList;
begin
  if Source is TipcECCKeyList then
  begin
    Src := TipcECCKeyList(Source);
    InternalSetCount(Src.GetCount);
    for i := 0 to Src.GetCount - 1 do
      InternalSetItem(i, Src.GetItem(i));
      
  end
  else
    inherited;
end;

function TipcECCKeyList.Clone: TipcECCKeyList;
begin
  Result := TipcECCKeyList.Create(FReadOnlyProp); // When cloning, always creating a freestanding object
  Result.Assign(Self);
  
end;

function TipcECCKeyList.GetCount: Integer;
begin
  SyncCount;
  Result := FCount;
end;

function TipcECCKeyList.GetItem(Idx: integer): TipcECCKey;
begin
  SyncCount;  
  
  Result := TipcECCKey(FItems[Idx]); 
end;

procedure TipcECCKeyList.SetItem(Idx: integer; Value: TipcECCKey);
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  
  if (Idx < 0) or (Idx >= GetCount) then
    raise Exception.Create('Index out of bounds');


  InternalSetItem(Idx, Value);
end;

function TipcECCKeyList.GetIsReadOnly: boolean;
begin
  Result := FReadOnlyProp;
end;

function TipcECCKeyList.GetIsFixedSize: boolean;
begin
  Result := false;
end;

function TipcECCKeyList.GetSyncRoot: TObject;
begin
  raise Exception.Create('Not implemented');
end;

function TipcECCKeyList.GetIsSynchronized: boolean;
begin
  Result := false;
end;

function TipcECCKeyList.Add(Value: TipcECCKey): Integer;
var
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  InternalSetCount(OldCount + 1);
  InternalSetItem(OldCount, Value);
  Result := OldCount;
end;

function TipcECCKeyList.Add(): Integer; 
var
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  InternalSetCount(OldCount + 1);
  Result := OldCount;
end;

procedure TipcECCKeyList.Remove(value: TipcECCKey);
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  raise Exception.Create('Not implemented');
end;

function TipcECCKeyList.Contains(value: TipcECCKey): Boolean;
begin
  raise Exception.Create('Not implemented');
end;

function TipcECCKeyList.IndexOf(value: TipcECCKey): Integer;
begin
  raise Exception.Create('Not implemented');
end;

procedure TipcECCKeyList.Insert(Idx: Integer; value: TipcECCKey);
var
  OldCount: integer;
  I: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  if (Idx < 0) or (Idx >= OldCount) then
    raise Exception.Create('Index out of bounds');
  InternalSetCount(OldCount + 1);
  for I := OldCount downto Idx + 1 do
    InternalSetItem(I, GetItem(i - 1));
  InternalSetItem(Idx, value);
end;

procedure TipcECCKeyList.RemoveAt(idx: Integer);
var
  I: integer;
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  if (Idx < 0) or (Idx >= OldCount) then
    raise Exception.Create('Index out of bounds');
  // Only copying the needed subset of elements, without cleaning them up
  for I := Idx to OldCount - 2 do
    InternalSetItem(I, GetItem(I + 1));
  InternalSetCount(OldCount - 1);
end;


procedure TipcECCKeyList.Clear();
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  InternalSetCount(0);
end;

function TipcECCKeyList.CtlGetCount: integer;
begin
  ; // to be overridden in derived classes
end;

procedure TipcECCKeyList.CtlSetCount(Value: integer);
begin
  ; // to be overridden in derived classes
end;

function TipcECCKeyList.CreateElemInstance(Index: integer): TipcECCKey; 
begin
  Result := TipcECCKey.Create(FOwnerCtl, FReadOnlyProp);
  Result.Index := Index;
end;


//////////////////////////////////////////////////////////////////////////////////////////
// TipcElgamalKey type

constructor TipcElgamalKey.Create();
begin
  inherited Create;
  FIndex := -1;
  FOwnerCtl := nil;
  FReadOnlyProp := false;
end;
constructor TipcElgamalKey.Create(valP: TBytes; valG: TBytes; valY: TBytes);
begin
  inherited Create;
  FIndex := -1;
  FOwnerCtl := nil;
  FReadOnlyProp := false;
  FP := valP;
  FG := valG;
  FY := valY;
end;
constructor TipcElgamalKey.Create(valP: TBytes; valG: TBytes; valY: TBytes; valX: TBytes);
begin
  inherited Create;
  FIndex := -1;
  FOwnerCtl := nil;
  FReadOnlyProp := false;
  FP := valP;
  FG := valG;
  FY := valY;
  FX := valX;
end;


constructor TipcElgamalKey.Create(Owner: TObject; ReadOnly: boolean);
begin
  inherited Create;
  FOwnerCtl := Owner;
  FReadOnlyProp := ReadOnly;
  FIndex := -1;
end;

destructor TipcElgamalKey.Destroy;
begin
  inherited;
end;

procedure TipcElgamalKey.Assign(Source: TPersistent);
var
  i: integer;
  Src: TipcElgamalKey;
begin
  // Copy contents using setters and getters. No owner or index is copied: this is simply an assignment
  // of a collection of fields to another object, not a creation of a full copy.
            
  if Source is TipcElgamalKey then
  begin


    SetPropG(TipcElgamalKey(Source).GetPropG);
    SetPropP(TipcElgamalKey(Source).GetPropP);
    SetPropPrivateKey(TipcElgamalKey(Source).GetPropPrivateKey);
    SetPropPublicKey(TipcElgamalKey(Source).GetPropPublicKey);
    SetPropX(TipcElgamalKey(Source).GetPropX);
    SetPropY(TipcElgamalKey(Source).GetPropY);
  end
  else
    inherited;
end;

function TipcElgamalKey.Clone: TipcElgamalKey;
begin
  // Always clone to a freestanding instance of the base class
  Result := TipcElgamalKey.Create(nil, FReadOnlyProp);
  Result.Assign(Self);
end;


function TipcElgamalKey.GetPropG: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FG);
end;

procedure TipcElgamalKey.SetPropG(Value: String);
begin
  FG := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcElgamalKey.GetPropGB : TBytes; 
begin
  Result := FG;
end;

procedure TipcElgamalKey.SetPropGB(Value: TBytes); 
begin
  FG := Value;
end;

function TipcElgamalKey.GetPropP: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FP);
end;

procedure TipcElgamalKey.SetPropP(Value: String);
begin
  FP := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcElgamalKey.GetPropPB : TBytes; 
begin
  Result := FP;
end;

procedure TipcElgamalKey.SetPropPB(Value: TBytes); 
begin
  FP := Value;
end;

function TipcElgamalKey.GetPropPrivateKey: String;
begin
  Result := String(FPrivateKey);
end;

procedure TipcElgamalKey.SetPropPrivateKey(Value: String);
begin
  FPrivateKey := Value;
end;


function TipcElgamalKey.GetPropPublicKey: String;
begin
  Result := String(FPublicKey);
end;

procedure TipcElgamalKey.SetPropPublicKey(Value: String);
begin
  FPublicKey := Value;
end;


function TipcElgamalKey.GetPropX: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FX);
end;

procedure TipcElgamalKey.SetPropX(Value: String);
begin
  FX := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcElgamalKey.GetPropXB : TBytes; 
begin
  Result := FX;
end;

procedure TipcElgamalKey.SetPropXB(Value: TBytes); 
begin
  FX := Value;
end;

function TipcElgamalKey.GetPropY: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FY);
end;

procedure TipcElgamalKey.SetPropY(Value: String);
begin
  FY := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcElgamalKey.GetPropYB : TBytes; 
begin
  Result := FY;
end;

procedure TipcElgamalKey.SetPropYB(Value: TBytes); 
begin
  FY := Value;
end;


//////////////////////////////////////////////////////////////////////////////////////////
// TipcElgamalKeyList type
constructor TipcElgamalKeyList.Create();
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := false;
  FCount := 0;
  FOwnerCtl := nil;
end;

constructor TipcElgamalKeyList.Create(ReadOnly: Boolean);
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := ReadOnly;
  FCount := 0;
  FOwnerCtl := nil;
end;

constructor TipcElgamalKeyList.Create(Owner: TObject; ReadOnly: Boolean); 
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := ReadOnly;
  FCount := 0;
  FOwnerCtl := Owner;
end;

destructor TipcElgamalKeyList.Destroy; 
begin
  ClearList;
  FreeAndNil(FItems);
  inherited;
end;

procedure TipcElgamalKeyList.ClearList;
var
  Inst : TipcElgamalKey;
  I: integer;
begin
  try
    for I := 0 to FItems.Count - 1 do
    begin
      Inst := TipcElgamalKey(FItems[I]);
      {$ifndef AUTOREFCOUNT}
      Inst.Free;
      {$else}
      Inst.__ObjRelease;
      Inst.DisposeOf;
      {$endif};
    end;
  finally
    FItems.Clear;
  end;
end;

function TipcElgamalKeyList.IsFree: boolean;
begin
  // This method tells the requestor whether the collection object is freestanding or bound
  Result := FOwnerCtl = nil;
end;

procedure TipcElgamalKeyList.SyncCount;
var
  Inst : TipcElgamalKey;
  I: integer;
begin
  // This method updates the number of objects held by the collection. It is only relevant for bound collections.
  if not IsFree then
  begin
    FCount := CtlGetCount();
    while FItems.Count < FCount do
    begin
      Inst := CreateElemInstance(FItems.Count);
      FItems.Add(Inst);
      {$ifdef AUTOREFCOUNT}
      Inst.__ObjAddRef;
      {$endif}
    end;
  end;
end;

procedure TipcElgamalKeyList.InternalSetCount(Value: integer);
var
  Inst : TipcElgamalKey;
begin
  // This method updates the number of elements in the underlying list. 
  // For both free and bound collections, it will verify that the list has sufficient capacity.
  while FItems.Count < Value do
  begin
    Inst := CreateElemInstance(FItems.Count);
    FItems.Add(Inst);
    {$ifdef AUTOREFCOUNT}
    Inst.__ObjAddRef;
    {$endif}
  end;

  if not IsFree then
    CtlSetCount(Value);
  FCount := Value;
end;

procedure TipcElgamalKeyList.InternalSetItem(Index: integer; Value: TipcElgamalKey);
begin
  // This method assigns (effectively copies) an item to collection.
  // It is expected that the boundaries have been checked before this method was called.
  TipcElgamalKey(FItems[Index]).Assign(Value); // Assign, if needed, will redirect any setters to the underlying control's methods
end;

procedure TipcElgamalKeyList.Assign(Source: TPersistent);
var
  i: integer;
  Src: TipcElgamalKeyList;
begin
  if Source is TipcElgamalKeyList then
  begin
    Src := TipcElgamalKeyList(Source);
    InternalSetCount(Src.GetCount);
    for i := 0 to Src.GetCount - 1 do
      InternalSetItem(i, Src.GetItem(i));
      
  end
  else
    inherited;
end;

function TipcElgamalKeyList.Clone: TipcElgamalKeyList;
begin
  Result := TipcElgamalKeyList.Create(FReadOnlyProp); // When cloning, always creating a freestanding object
  Result.Assign(Self);
  
end;

function TipcElgamalKeyList.GetCount: Integer;
begin
  SyncCount;
  Result := FCount;
end;

function TipcElgamalKeyList.GetItem(Idx: integer): TipcElgamalKey;
begin
  SyncCount;  
  
  Result := TipcElgamalKey(FItems[Idx]); 
end;

procedure TipcElgamalKeyList.SetItem(Idx: integer; Value: TipcElgamalKey);
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  
  if (Idx < 0) or (Idx >= GetCount) then
    raise Exception.Create('Index out of bounds');


  InternalSetItem(Idx, Value);
end;

function TipcElgamalKeyList.GetIsReadOnly: boolean;
begin
  Result := FReadOnlyProp;
end;

function TipcElgamalKeyList.GetIsFixedSize: boolean;
begin
  Result := false;
end;

function TipcElgamalKeyList.GetSyncRoot: TObject;
begin
  raise Exception.Create('Not implemented');
end;

function TipcElgamalKeyList.GetIsSynchronized: boolean;
begin
  Result := false;
end;

function TipcElgamalKeyList.Add(Value: TipcElgamalKey): Integer;
var
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  InternalSetCount(OldCount + 1);
  InternalSetItem(OldCount, Value);
  Result := OldCount;
end;

function TipcElgamalKeyList.Add(): Integer; 
var
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  InternalSetCount(OldCount + 1);
  Result := OldCount;
end;

procedure TipcElgamalKeyList.Remove(value: TipcElgamalKey);
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  raise Exception.Create('Not implemented');
end;

function TipcElgamalKeyList.Contains(value: TipcElgamalKey): Boolean;
begin
  raise Exception.Create('Not implemented');
end;

function TipcElgamalKeyList.IndexOf(value: TipcElgamalKey): Integer;
begin
  raise Exception.Create('Not implemented');
end;

procedure TipcElgamalKeyList.Insert(Idx: Integer; value: TipcElgamalKey);
var
  OldCount: integer;
  I: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  if (Idx < 0) or (Idx >= OldCount) then
    raise Exception.Create('Index out of bounds');
  InternalSetCount(OldCount + 1);
  for I := OldCount downto Idx + 1 do
    InternalSetItem(I, GetItem(i - 1));
  InternalSetItem(Idx, value);
end;

procedure TipcElgamalKeyList.RemoveAt(idx: Integer);
var
  I: integer;
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  if (Idx < 0) or (Idx >= OldCount) then
    raise Exception.Create('Index out of bounds');
  // Only copying the needed subset of elements, without cleaning them up
  for I := Idx to OldCount - 2 do
    InternalSetItem(I, GetItem(I + 1));
  InternalSetCount(OldCount - 1);
end;


procedure TipcElgamalKeyList.Clear();
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  InternalSetCount(0);
end;

function TipcElgamalKeyList.CtlGetCount: integer;
begin
  ; // to be overridden in derived classes
end;

procedure TipcElgamalKeyList.CtlSetCount(Value: integer);
begin
  ; // to be overridden in derived classes
end;

function TipcElgamalKeyList.CreateElemInstance(Index: integer): TipcElgamalKey; 
begin
  Result := TipcElgamalKey.Create(FOwnerCtl, FReadOnlyProp);
  Result.Index := Index;
end;


//////////////////////////////////////////////////////////////////////////////////////////
// TipcHeader type

constructor TipcHeader.Create();
begin
  inherited Create;
  FIndex := -1;
  FOwnerCtl := nil;
  FReadOnlyProp := false;
end;
constructor TipcHeader.Create(valField: String; valValue: String);
begin
  inherited Create;
  FIndex := -1;
  FOwnerCtl := nil;
  FReadOnlyProp := false;
  FField := valField;
  FValue := valValue;
end;


constructor TipcHeader.Create(Owner: TObject; ReadOnly: boolean);
begin
  inherited Create;
  FOwnerCtl := Owner;
  FReadOnlyProp := ReadOnly;
  FIndex := -1;
end;

destructor TipcHeader.Destroy;
begin
  inherited;
end;

procedure TipcHeader.Assign(Source: TPersistent);
var
  i: integer;
  Src: TipcHeader;
begin
  // Copy contents using setters and getters. No owner or index is copied: this is simply an assignment
  // of a collection of fields to another object, not a creation of a full copy.
    
  if Source is TipcHeader then
  begin


    SetPropField(TipcHeader(Source).GetPropField);
    SetPropValue(TipcHeader(Source).GetPropValue);
  end
  else
    inherited;
end;

function TipcHeader.Clone: TipcHeader;
begin
  // Always clone to a freestanding instance of the base class
  Result := TipcHeader.Create(nil, FReadOnlyProp);
  Result.Assign(Self);
end;


function TipcHeader.GetPropField: String;
begin
  Result := String(FField);
end;

procedure TipcHeader.SetPropField(Value: String);
begin
  FField := Value;
end;


function TipcHeader.GetPropValue: String;
begin
  Result := String(FValue);
end;

procedure TipcHeader.SetPropValue(Value: String);
begin
  FValue := Value;
end;



//////////////////////////////////////////////////////////////////////////////////////////
// TipcHeaderList type
constructor TipcHeaderList.Create();
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := false;
  FCount := 0;
  FOwnerCtl := nil;
end;

constructor TipcHeaderList.Create(ReadOnly: Boolean);
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := ReadOnly;
  FCount := 0;
  FOwnerCtl := nil;
end;

constructor TipcHeaderList.Create(Owner: TObject; ReadOnly: Boolean); 
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := ReadOnly;
  FCount := 0;
  FOwnerCtl := Owner;
end;

destructor TipcHeaderList.Destroy; 
begin
  ClearList;
  FreeAndNil(FItems);
  inherited;
end;

procedure TipcHeaderList.ClearList;
var
  Inst : TipcHeader;
  I: integer;
begin
  try
    for I := 0 to FItems.Count - 1 do
    begin
      Inst := TipcHeader(FItems[I]);
      {$ifndef AUTOREFCOUNT}
      Inst.Free;
      {$else}
      Inst.__ObjRelease;
      Inst.DisposeOf;
      {$endif};
    end;
  finally
    FItems.Clear;
  end;
end;

function TipcHeaderList.IsFree: boolean;
begin
  // This method tells the requestor whether the collection object is freestanding or bound
  Result := FOwnerCtl = nil;
end;

procedure TipcHeaderList.SyncCount;
var
  Inst : TipcHeader;
  I: integer;
begin
  // This method updates the number of objects held by the collection. It is only relevant for bound collections.
  if not IsFree then
  begin
    FCount := CtlGetCount();
    while FItems.Count < FCount do
    begin
      Inst := CreateElemInstance(FItems.Count);
      FItems.Add(Inst);
      {$ifdef AUTOREFCOUNT}
      Inst.__ObjAddRef;
      {$endif}
    end;
  end;
end;

procedure TipcHeaderList.InternalSetCount(Value: integer);
var
  Inst : TipcHeader;
begin
  // This method updates the number of elements in the underlying list. 
  // For both free and bound collections, it will verify that the list has sufficient capacity.
  while FItems.Count < Value do
  begin
    Inst := CreateElemInstance(FItems.Count);
    FItems.Add(Inst);
    {$ifdef AUTOREFCOUNT}
    Inst.__ObjAddRef;
    {$endif}
  end;

  if not IsFree then
    CtlSetCount(Value);
  FCount := Value;
end;

procedure TipcHeaderList.InternalSetItem(Index: integer; Value: TipcHeader);
begin
  // This method assigns (effectively copies) an item to collection.
  // It is expected that the boundaries have been checked before this method was called.
  TipcHeader(FItems[Index]).Assign(Value); // Assign, if needed, will redirect any setters to the underlying control's methods
end;

procedure TipcHeaderList.Assign(Source: TPersistent);
var
  i: integer;
  Src: TipcHeaderList;
begin
  if Source is TipcHeaderList then
  begin
    Src := TipcHeaderList(Source);
    InternalSetCount(Src.GetCount);
    for i := 0 to Src.GetCount - 1 do
      InternalSetItem(i, Src.GetItem(i));
      
  end
  else
    inherited;
end;

function TipcHeaderList.Clone: TipcHeaderList;
begin
  Result := TipcHeaderList.Create(FReadOnlyProp); // When cloning, always creating a freestanding object
  Result.Assign(Self);
  
end;

function TipcHeaderList.GetCount: Integer;
begin
  SyncCount;
  Result := FCount;
end;

function TipcHeaderList.GetItem(Idx: integer): TipcHeader;
begin
  SyncCount;  
  
  Result := TipcHeader(FItems[Idx]); 
end;

procedure TipcHeaderList.SetItem(Idx: integer; Value: TipcHeader);
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  
  if (Idx < 0) or (Idx >= GetCount) then
    raise Exception.Create('Index out of bounds');


  InternalSetItem(Idx, Value);
end;

function TipcHeaderList.GetIsReadOnly: boolean;
begin
  Result := FReadOnlyProp;
end;

function TipcHeaderList.GetIsFixedSize: boolean;
begin
  Result := false;
end;

function TipcHeaderList.GetSyncRoot: TObject;
begin
  raise Exception.Create('Not implemented');
end;

function TipcHeaderList.GetIsSynchronized: boolean;
begin
  Result := false;
end;

function TipcHeaderList.Add(Value: TipcHeader): Integer;
var
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  InternalSetCount(OldCount + 1);
  InternalSetItem(OldCount, Value);
  Result := OldCount;
end;

function TipcHeaderList.Add(): Integer; 
var
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  InternalSetCount(OldCount + 1);
  Result := OldCount;
end;

procedure TipcHeaderList.Remove(value: TipcHeader);
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  raise Exception.Create('Not implemented');
end;

function TipcHeaderList.Contains(value: TipcHeader): Boolean;
begin
  raise Exception.Create('Not implemented');
end;

function TipcHeaderList.IndexOf(value: TipcHeader): Integer;
begin
  raise Exception.Create('Not implemented');
end;

procedure TipcHeaderList.Insert(Idx: Integer; value: TipcHeader);
var
  OldCount: integer;
  I: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  if (Idx < 0) or (Idx >= OldCount) then
    raise Exception.Create('Index out of bounds');
  InternalSetCount(OldCount + 1);
  for I := OldCount downto Idx + 1 do
    InternalSetItem(I, GetItem(i - 1));
  InternalSetItem(Idx, value);
end;

procedure TipcHeaderList.RemoveAt(idx: Integer);
var
  I: integer;
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  if (Idx < 0) or (Idx >= OldCount) then
    raise Exception.Create('Index out of bounds');
  // Only copying the needed subset of elements, without cleaning them up
  for I := Idx to OldCount - 2 do
    InternalSetItem(I, GetItem(I + 1));
  InternalSetCount(OldCount - 1);
end;


procedure TipcHeaderList.Clear();
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  InternalSetCount(0);
end;

function TipcHeaderList.CtlGetCount: integer;
begin
  ; // to be overridden in derived classes
end;

procedure TipcHeaderList.CtlSetCount(Value: integer);
begin
  ; // to be overridden in derived classes
end;

function TipcHeaderList.CreateElemInstance(Index: integer): TipcHeader; 
begin
  Result := TipcHeader.Create(FOwnerCtl, FReadOnlyProp);
  Result.Index := Index;
end;


//////////////////////////////////////////////////////////////////////////////////////////
// TipcHeaderParam type

constructor TipcHeaderParam.Create();
begin
  inherited Create;
  FIndex := -1;
  FOwnerCtl := nil;
  FReadOnlyProp := false;
end;
constructor TipcHeaderParam.Create(valName: String; valValue: String);
begin
  inherited Create;
  FIndex := -1;
  FOwnerCtl := nil;
  FReadOnlyProp := false;
  FName := valName;
  FValue := valValue;
end;


constructor TipcHeaderParam.Create(Owner: TObject; ReadOnly: boolean);
begin
  inherited Create;
  FOwnerCtl := Owner;
  FReadOnlyProp := ReadOnly;
  FIndex := -1;
end;

destructor TipcHeaderParam.Destroy;
begin
  inherited;
end;

procedure TipcHeaderParam.Assign(Source: TPersistent);
var
  i: integer;
  Src: TipcHeaderParam;
begin
  // Copy contents using setters and getters. No owner or index is copied: this is simply an assignment
  // of a collection of fields to another object, not a creation of a full copy.
      
  if Source is TipcHeaderParam then
  begin


    SetPropDataType(TipcHeaderParam(Source).GetPropDataType);
    SetPropName(TipcHeaderParam(Source).GetPropName);
    SetPropValue(TipcHeaderParam(Source).GetPropValue);
  end
  else
    inherited;
end;

function TipcHeaderParam.Clone: TipcHeaderParam;
begin
  // Always clone to a freestanding instance of the base class
  Result := TipcHeaderParam.Create(nil, FReadOnlyProp);
  Result.Assign(Self);
end;


function TipcHeaderParam.GetPropDataType: TipcTDataTypes;
begin
  Result := {T}(FDataType);
end;

procedure TipcHeaderParam.SetPropDataType(Value: TipcTDataTypes);
begin
  FDataType := Value;
end;


function TipcHeaderParam.GetPropName: String;
begin
  Result := String(FName);
end;

procedure TipcHeaderParam.SetPropName(Value: String);
begin
  FName := Value;
end;


function TipcHeaderParam.GetPropValue: String;
begin
  Result := String(FValue);
end;

procedure TipcHeaderParam.SetPropValue(Value: String);
begin
  FValue := Value;
end;



//////////////////////////////////////////////////////////////////////////////////////////
// TipcHeaderParamList type
constructor TipcHeaderParamList.Create();
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := false;
  FCount := 0;
  FOwnerCtl := nil;
end;

constructor TipcHeaderParamList.Create(ReadOnly: Boolean);
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := ReadOnly;
  FCount := 0;
  FOwnerCtl := nil;
end;

constructor TipcHeaderParamList.Create(Owner: TObject; ReadOnly: Boolean); 
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := ReadOnly;
  FCount := 0;
  FOwnerCtl := Owner;
end;

destructor TipcHeaderParamList.Destroy; 
begin
  ClearList;
  FreeAndNil(FItems);
  inherited;
end;

procedure TipcHeaderParamList.ClearList;
var
  Inst : TipcHeaderParam;
  I: integer;
begin
  try
    for I := 0 to FItems.Count - 1 do
    begin
      Inst := TipcHeaderParam(FItems[I]);
      {$ifndef AUTOREFCOUNT}
      Inst.Free;
      {$else}
      Inst.__ObjRelease;
      Inst.DisposeOf;
      {$endif};
    end;
  finally
    FItems.Clear;
  end;
end;

function TipcHeaderParamList.IsFree: boolean;
begin
  // This method tells the requestor whether the collection object is freestanding or bound
  Result := FOwnerCtl = nil;
end;

procedure TipcHeaderParamList.SyncCount;
var
  Inst : TipcHeaderParam;
  I: integer;
begin
  // This method updates the number of objects held by the collection. It is only relevant for bound collections.
  if not IsFree then
  begin
    FCount := CtlGetCount();
    while FItems.Count < FCount do
    begin
      Inst := CreateElemInstance(FItems.Count);
      FItems.Add(Inst);
      {$ifdef AUTOREFCOUNT}
      Inst.__ObjAddRef;
      {$endif}
    end;
  end;
end;

procedure TipcHeaderParamList.InternalSetCount(Value: integer);
var
  Inst : TipcHeaderParam;
begin
  // This method updates the number of elements in the underlying list. 
  // For both free and bound collections, it will verify that the list has sufficient capacity.
  while FItems.Count < Value do
  begin
    Inst := CreateElemInstance(FItems.Count);
    FItems.Add(Inst);
    {$ifdef AUTOREFCOUNT}
    Inst.__ObjAddRef;
    {$endif}
  end;

  if not IsFree then
    CtlSetCount(Value);
  FCount := Value;
end;

procedure TipcHeaderParamList.InternalSetItem(Index: integer; Value: TipcHeaderParam);
begin
  // This method assigns (effectively copies) an item to collection.
  // It is expected that the boundaries have been checked before this method was called.
  TipcHeaderParam(FItems[Index]).Assign(Value); // Assign, if needed, will redirect any setters to the underlying control's methods
end;

procedure TipcHeaderParamList.Assign(Source: TPersistent);
var
  i: integer;
  Src: TipcHeaderParamList;
begin
  if Source is TipcHeaderParamList then
  begin
    Src := TipcHeaderParamList(Source);
    InternalSetCount(Src.GetCount);
    for i := 0 to Src.GetCount - 1 do
      InternalSetItem(i, Src.GetItem(i));
      
  end
  else
    inherited;
end;

function TipcHeaderParamList.Clone: TipcHeaderParamList;
begin
  Result := TipcHeaderParamList.Create(FReadOnlyProp); // When cloning, always creating a freestanding object
  Result.Assign(Self);
  
end;

function TipcHeaderParamList.GetCount: Integer;
begin
  SyncCount;
  Result := FCount;
end;

function TipcHeaderParamList.GetItem(Idx: integer): TipcHeaderParam;
begin
  SyncCount;  
  
  Result := TipcHeaderParam(FItems[Idx]); 
end;

procedure TipcHeaderParamList.SetItem(Idx: integer; Value: TipcHeaderParam);
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  
  if (Idx < 0) or (Idx >= GetCount) then
    raise Exception.Create('Index out of bounds');


  InternalSetItem(Idx, Value);
end;

function TipcHeaderParamList.GetIsReadOnly: boolean;
begin
  Result := FReadOnlyProp;
end;

function TipcHeaderParamList.GetIsFixedSize: boolean;
begin
  Result := false;
end;

function TipcHeaderParamList.GetSyncRoot: TObject;
begin
  raise Exception.Create('Not implemented');
end;

function TipcHeaderParamList.GetIsSynchronized: boolean;
begin
  Result := false;
end;

function TipcHeaderParamList.Add(Value: TipcHeaderParam): Integer;
var
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  InternalSetCount(OldCount + 1);
  InternalSetItem(OldCount, Value);
  Result := OldCount;
end;

function TipcHeaderParamList.Add(): Integer; 
var
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  InternalSetCount(OldCount + 1);
  Result := OldCount;
end;

procedure TipcHeaderParamList.Remove(value: TipcHeaderParam);
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  raise Exception.Create('Not implemented');
end;

function TipcHeaderParamList.Contains(value: TipcHeaderParam): Boolean;
begin
  raise Exception.Create('Not implemented');
end;

function TipcHeaderParamList.IndexOf(value: TipcHeaderParam): Integer;
begin
  raise Exception.Create('Not implemented');
end;

procedure TipcHeaderParamList.Insert(Idx: Integer; value: TipcHeaderParam);
var
  OldCount: integer;
  I: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  if (Idx < 0) or (Idx >= OldCount) then
    raise Exception.Create('Index out of bounds');
  InternalSetCount(OldCount + 1);
  for I := OldCount downto Idx + 1 do
    InternalSetItem(I, GetItem(i - 1));
  InternalSetItem(Idx, value);
end;

procedure TipcHeaderParamList.RemoveAt(idx: Integer);
var
  I: integer;
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  if (Idx < 0) or (Idx >= OldCount) then
    raise Exception.Create('Index out of bounds');
  // Only copying the needed subset of elements, without cleaning them up
  for I := Idx to OldCount - 2 do
    InternalSetItem(I, GetItem(I + 1));
  InternalSetCount(OldCount - 1);
end;


procedure TipcHeaderParamList.Clear();
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  InternalSetCount(0);
end;

function TipcHeaderParamList.CtlGetCount: integer;
begin
  ; // to be overridden in derived classes
end;

procedure TipcHeaderParamList.CtlSetCount(Value: integer);
begin
  ; // to be overridden in derived classes
end;

function TipcHeaderParamList.CreateElemInstance(Index: integer): TipcHeaderParam; 
begin
  Result := TipcHeaderParam.Create(FOwnerCtl, FReadOnlyProp);
  Result.Index := Index;
end;


//////////////////////////////////////////////////////////////////////////////////////////
// TipcKey type



constructor TipcKey.Create(Owner: TObject; ReadOnly: boolean);
begin
  inherited Create;
  FOwnerCtl := Owner;
  FReadOnlyProp := ReadOnly;
  FIndex := -1;
end;

destructor TipcKey.Destroy;
begin
  inherited;
end;

procedure TipcKey.Assign(Source: TPersistent);
var
  i: integer;
  Src: TipcKey;
begin
  // Copy contents using setters and getters. No owner or index is copied: this is simply an assignment
  // of a collection of fields to another object, not a creation of a full copy.
                                    
  if Source is TipcKey then
  begin


    SetPropCurve(TipcKey(Source).GetPropCurve);
    SetPropEffectiveDate(TipcKey(Source).GetPropEffectiveDate);
    SetPropEncoded(TipcKey(Source).GetPropEncoded);
    SetPropExpirationDate(TipcKey(Source).GetPropExpirationDate);
    SetPropFingerprint(TipcKey(Source).GetPropFingerprint);
    SetPropId(TipcKey(Source).GetPropId);
    SetPropKeyring(TipcKey(Source).GetPropKeyring);
    SetPropOtherUserIds(TipcKey(Source).GetPropOtherUserIds);
    SetPropPassphrase(TipcKey(Source).GetPropPassphrase);
    SetPropPublicKey(TipcKey(Source).GetPropPublicKey);
    SetPropPublicKeyAlgorithm(TipcKey(Source).GetPropPublicKeyAlgorithm);
    SetPropPublicKeyLength(TipcKey(Source).GetPropPublicKeyLength);
    SetPropRevoked(TipcKey(Source).GetPropRevoked);
    SetPropSecretKey(TipcKey(Source).GetPropSecretKey);
    SetPropSecretKeyAvailable(TipcKey(Source).GetPropSecretKeyAvailable);
    SetPropUsage(TipcKey(Source).GetPropUsage);
    SetPropUsageFlags(TipcKey(Source).GetPropUsageFlags);
    SetPropUserId(TipcKey(Source).GetPropUserId);
  end
  else
    inherited;
end;

function TipcKey.Clone: TipcKey;
begin
  // Always clone to a freestanding instance of the base class
  Result := TipcKey.Create(nil, FReadOnlyProp);
  Result.Assign(Self);
end;


function TipcKey.GetPropCurve: String;
begin
  Result := String(FCurve);
end;

procedure TipcKey.SetPropCurve(Value: String);
begin
  FCurve := Value;
end;


function TipcKey.GetPropEffectiveDate: String;
begin
  Result := String(FEffectiveDate);
end;

procedure TipcKey.SetPropEffectiveDate(Value: String);
begin
  FEffectiveDate := Value;
end;


function TipcKey.GetPropEncoded: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FEncoded);
end;

procedure TipcKey.SetPropEncoded(Value: String);
begin
  FEncoded := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcKey.GetPropEncodedB : TBytes; 
begin
  Result := FEncoded;
end;

procedure TipcKey.SetPropEncodedB(Value: TBytes); 
begin
  FEncoded := Value;
end;

function TipcKey.GetPropExpirationDate: String;
begin
  Result := String(FExpirationDate);
end;

procedure TipcKey.SetPropExpirationDate(Value: String);
begin
  FExpirationDate := Value;
end;


function TipcKey.GetPropFingerprint: String;
begin
  Result := String(FFingerprint);
end;

procedure TipcKey.SetPropFingerprint(Value: String);
begin
  FFingerprint := Value;
end;


function TipcKey.GetPropId: String;
begin
  Result := String(FId);
end;

procedure TipcKey.SetPropId(Value: String);
begin
  FId := Value;
end;


function TipcKey.GetPropKeyring: String;
begin
  Result := String(FKeyring);
end;

procedure TipcKey.SetPropKeyring(Value: String);
begin
  FKeyring := Value;
end;


function TipcKey.GetPropOtherUserIds: String;
begin
  Result := String(FOtherUserIds);
end;

procedure TipcKey.SetPropOtherUserIds(Value: String);
begin
  FOtherUserIds := Value;
end;


function TipcKey.GetPropPassphrase: String;
begin
  Result := String(FPassphrase);
end;

procedure TipcKey.SetPropPassphrase(Value: String);
begin
  FPassphrase := Value;
end;


function TipcKey.GetPropPublicKey: String;
begin
  Result := String(FPublicKey);
end;

procedure TipcKey.SetPropPublicKey(Value: String);
begin
  FPublicKey := Value;
end;


function TipcKey.GetPropPublicKeyAlgorithm: String;
begin
  Result := String(FPublicKeyAlgorithm);
end;

procedure TipcKey.SetPropPublicKeyAlgorithm(Value: String);
begin
  FPublicKeyAlgorithm := Value;
end;


function TipcKey.GetPropPublicKeyLength: Integer;
begin
  Result := Integer(FPublicKeyLength);
end;

procedure TipcKey.SetPropPublicKeyLength(Value: Integer);
begin
  FPublicKeyLength := Value;
end;


function TipcKey.GetPropRevoked: Boolean;
begin
  Result := Boolean(FRevoked);
end;

procedure TipcKey.SetPropRevoked(Value: Boolean);
begin
  FRevoked := Value;
end;


function TipcKey.GetPropSecretKey: String;
begin
  Result := String(FSecretKey);
end;

procedure TipcKey.SetPropSecretKey(Value: String);
begin
  FSecretKey := Value;
end;


function TipcKey.GetPropSecretKeyAvailable: Boolean;
begin
  Result := Boolean(FSecretKeyAvailable);
end;

procedure TipcKey.SetPropSecretKeyAvailable(Value: Boolean);
begin
  FSecretKeyAvailable := Value;
end;


function TipcKey.GetPropUsage: String;
begin
  Result := String(FUsage);
end;

procedure TipcKey.SetPropUsage(Value: String);
begin
  FUsage := Value;
end;


function TipcKey.GetPropUsageFlags: Integer;
begin
  Result := Integer(FUsageFlags);
end;

procedure TipcKey.SetPropUsageFlags(Value: Integer);
begin
  FUsageFlags := Value;
end;


function TipcKey.GetPropUserId: String;
begin
  Result := String(FUserId);
end;

procedure TipcKey.SetPropUserId(Value: String);
begin
  FUserId := Value;
end;



//////////////////////////////////////////////////////////////////////////////////////////
// TipcKeyList type
constructor TipcKeyList.Create();
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := false;
  FCount := 0;
  FOwnerCtl := nil;
end;

constructor TipcKeyList.Create(ReadOnly: Boolean);
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := ReadOnly;
  FCount := 0;
  FOwnerCtl := nil;
end;

constructor TipcKeyList.Create(Owner: TObject; ReadOnly: Boolean); 
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := ReadOnly;
  FCount := 0;
  FOwnerCtl := Owner;
end;

destructor TipcKeyList.Destroy; 
begin
  ClearList;
  FreeAndNil(FItems);
  inherited;
end;

procedure TipcKeyList.ClearList;
var
  Inst : TipcKey;
  I: integer;
begin
  try
    for I := 0 to FItems.Count - 1 do
    begin
      Inst := TipcKey(FItems[I]);
      {$ifndef AUTOREFCOUNT}
      Inst.Free;
      {$else}
      Inst.__ObjRelease;
      Inst.DisposeOf;
      {$endif};
    end;
  finally
    FItems.Clear;
  end;
end;

function TipcKeyList.IsFree: boolean;
begin
  // This method tells the requestor whether the collection object is freestanding or bound
  Result := FOwnerCtl = nil;
end;

procedure TipcKeyList.SyncCount;
var
  Inst : TipcKey;
  I: integer;
begin
  // This method updates the number of objects held by the collection. It is only relevant for bound collections.
  if not IsFree then
  begin
    FCount := CtlGetCount();
    while FItems.Count < FCount do
    begin
      Inst := CreateElemInstance(FItems.Count);
      FItems.Add(Inst);
      {$ifdef AUTOREFCOUNT}
      Inst.__ObjAddRef;
      {$endif}
    end;
  end;
end;

procedure TipcKeyList.InternalSetCount(Value: integer);
var
  Inst : TipcKey;
begin
  // This method updates the number of elements in the underlying list. 
  // For both free and bound collections, it will verify that the list has sufficient capacity.
  while FItems.Count < Value do
  begin
    Inst := CreateElemInstance(FItems.Count);
    FItems.Add(Inst);
    {$ifdef AUTOREFCOUNT}
    Inst.__ObjAddRef;
    {$endif}
  end;

  if not IsFree then
    CtlSetCount(Value);
  FCount := Value;
end;

procedure TipcKeyList.InternalSetItem(Index: integer; Value: TipcKey);
begin
  // This method assigns (effectively copies) an item to collection.
  // It is expected that the boundaries have been checked before this method was called.
  TipcKey(FItems[Index]).Assign(Value); // Assign, if needed, will redirect any setters to the underlying control's methods
end;

procedure TipcKeyList.Assign(Source: TPersistent);
var
  i: integer;
  Src: TipcKeyList;
begin
  if Source is TipcKeyList then
  begin
    Src := TipcKeyList(Source);
    InternalSetCount(Src.GetCount);
    for i := 0 to Src.GetCount - 1 do
      InternalSetItem(i, Src.GetItem(i));
      
  end
  else
    inherited;
end;

function TipcKeyList.Clone: TipcKeyList;
begin
  Result := TipcKeyList.Create(FReadOnlyProp); // When cloning, always creating a freestanding object
  Result.Assign(Self);
  
end;

function TipcKeyList.GetCount: Integer;
begin
  SyncCount;
  Result := FCount;
end;

function TipcKeyList.GetItem(Idx: integer): TipcKey;
begin
  SyncCount;  
  
  Result := TipcKey(FItems[Idx]); 
end;

procedure TipcKeyList.SetItem(Idx: integer; Value: TipcKey);
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  
  if (Idx < 0) or (Idx >= GetCount) then
    raise Exception.Create('Index out of bounds');


  InternalSetItem(Idx, Value);
end;

function TipcKeyList.GetIsReadOnly: boolean;
begin
  Result := FReadOnlyProp;
end;

function TipcKeyList.GetIsFixedSize: boolean;
begin
  Result := false;
end;

function TipcKeyList.GetSyncRoot: TObject;
begin
  raise Exception.Create('Not implemented');
end;

function TipcKeyList.GetIsSynchronized: boolean;
begin
  Result := false;
end;

function TipcKeyList.Add(Value: TipcKey): Integer;
var
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  InternalSetCount(OldCount + 1);
  InternalSetItem(OldCount, Value);
  Result := OldCount;
end;

function TipcKeyList.Add(): Integer; 
var
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  InternalSetCount(OldCount + 1);
  Result := OldCount;
end;

procedure TipcKeyList.Remove(value: TipcKey);
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  raise Exception.Create('Not implemented');
end;

function TipcKeyList.Contains(value: TipcKey): Boolean;
begin
  raise Exception.Create('Not implemented');
end;

function TipcKeyList.IndexOf(value: TipcKey): Integer;
begin
  raise Exception.Create('Not implemented');
end;

procedure TipcKeyList.Insert(Idx: Integer; value: TipcKey);
var
  OldCount: integer;
  I: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  if (Idx < 0) or (Idx >= OldCount) then
    raise Exception.Create('Index out of bounds');
  InternalSetCount(OldCount + 1);
  for I := OldCount downto Idx + 1 do
    InternalSetItem(I, GetItem(i - 1));
  InternalSetItem(Idx, value);
end;

procedure TipcKeyList.RemoveAt(idx: Integer);
var
  I: integer;
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  if (Idx < 0) or (Idx >= OldCount) then
    raise Exception.Create('Index out of bounds');
  // Only copying the needed subset of elements, without cleaning them up
  for I := Idx to OldCount - 2 do
    InternalSetItem(I, GetItem(I + 1));
  InternalSetCount(OldCount - 1);
end;


procedure TipcKeyList.Clear();
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  InternalSetCount(0);
end;

function TipcKeyList.CtlGetCount: integer;
begin
  ; // to be overridden in derived classes
end;

procedure TipcKeyList.CtlSetCount(Value: integer);
begin
  ; // to be overridden in derived classes
end;

function TipcKeyList.CreateElemInstance(Index: integer): TipcKey; 
begin
  Result := TipcKey.Create(FOwnerCtl, FReadOnlyProp);
  Result.Index := Index;
end;


//////////////////////////////////////////////////////////////////////////////////////////
// TipcRSAKey type

constructor TipcRSAKey.Create();
begin
  inherited Create;
  FIndex := -1;
  FOwnerCtl := nil;
  FReadOnlyProp := false;
end;
constructor TipcRSAKey.Create(valModulus: TBytes; valExponent: TBytes);
begin
  inherited Create;
  FIndex := -1;
  FOwnerCtl := nil;
  FReadOnlyProp := false;
  FModulus := valModulus;
  FExponent := valExponent;
end;
constructor TipcRSAKey.Create(valModulus: TBytes; valD: TBytes; valP: TBytes; valQ: TBytes; valDP: TBytes; valDQ: TBytes);
begin
  inherited Create;
  FIndex := -1;
  FOwnerCtl := nil;
  FReadOnlyProp := false;
  FModulus := valModulus;
  FD := valD;
  FP := valP;
  FQ := valQ;
  FDP := valDP;
  FDQ := valDQ;
end;


constructor TipcRSAKey.Create(Owner: TObject; ReadOnly: boolean);
begin
  inherited Create;
  FOwnerCtl := Owner;
  FReadOnlyProp := ReadOnly;
  FIndex := -1;
end;

destructor TipcRSAKey.Destroy;
begin
  inherited;
end;

procedure TipcRSAKey.Assign(Source: TPersistent);
var
  i: integer;
  Src: TipcRSAKey;
begin
  // Copy contents using setters and getters. No owner or index is copied: this is simply an assignment
  // of a collection of fields to another object, not a creation of a full copy.
                    
  if Source is TipcRSAKey then
  begin


    SetPropD(TipcRSAKey(Source).GetPropD);
    SetPropDP(TipcRSAKey(Source).GetPropDP);
    SetPropDQ(TipcRSAKey(Source).GetPropDQ);
    SetPropExponent(TipcRSAKey(Source).GetPropExponent);
    SetPropInverseQ(TipcRSAKey(Source).GetPropInverseQ);
    SetPropModulus(TipcRSAKey(Source).GetPropModulus);
    SetPropP(TipcRSAKey(Source).GetPropP);
    SetPropPrivateKey(TipcRSAKey(Source).GetPropPrivateKey);
    SetPropPublicKey(TipcRSAKey(Source).GetPropPublicKey);
    SetPropQ(TipcRSAKey(Source).GetPropQ);
  end
  else
    inherited;
end;

function TipcRSAKey.Clone: TipcRSAKey;
begin
  // Always clone to a freestanding instance of the base class
  Result := TipcRSAKey.Create(nil, FReadOnlyProp);
  Result.Assign(Self);
end;


function TipcRSAKey.GetPropD: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FD);
end;

procedure TipcRSAKey.SetPropD(Value: String);
begin
  FD := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcRSAKey.GetPropDB : TBytes; 
begin
  Result := FD;
end;

procedure TipcRSAKey.SetPropDB(Value: TBytes); 
begin
  FD := Value;
end;

function TipcRSAKey.GetPropDP: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FDP);
end;

procedure TipcRSAKey.SetPropDP(Value: String);
begin
  FDP := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcRSAKey.GetPropDPB : TBytes; 
begin
  Result := FDP;
end;

procedure TipcRSAKey.SetPropDPB(Value: TBytes); 
begin
  FDP := Value;
end;

function TipcRSAKey.GetPropDQ: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FDQ);
end;

procedure TipcRSAKey.SetPropDQ(Value: String);
begin
  FDQ := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcRSAKey.GetPropDQB : TBytes; 
begin
  Result := FDQ;
end;

procedure TipcRSAKey.SetPropDQB(Value: TBytes); 
begin
  FDQ := Value;
end;

function TipcRSAKey.GetPropExponent: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FExponent);
end;

procedure TipcRSAKey.SetPropExponent(Value: String);
begin
  FExponent := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcRSAKey.GetPropExponentB : TBytes; 
begin
  Result := FExponent;
end;

procedure TipcRSAKey.SetPropExponentB(Value: TBytes); 
begin
  FExponent := Value;
end;

function TipcRSAKey.GetPropInverseQ: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FInverseQ);
end;

procedure TipcRSAKey.SetPropInverseQ(Value: String);
begin
  FInverseQ := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcRSAKey.GetPropInverseQB : TBytes; 
begin
  Result := FInverseQ;
end;

procedure TipcRSAKey.SetPropInverseQB(Value: TBytes); 
begin
  FInverseQ := Value;
end;

function TipcRSAKey.GetPropModulus: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FModulus);
end;

procedure TipcRSAKey.SetPropModulus(Value: String);
begin
  FModulus := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcRSAKey.GetPropModulusB : TBytes; 
begin
  Result := FModulus;
end;

procedure TipcRSAKey.SetPropModulusB(Value: TBytes); 
begin
  FModulus := Value;
end;

function TipcRSAKey.GetPropP: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FP);
end;

procedure TipcRSAKey.SetPropP(Value: String);
begin
  FP := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcRSAKey.GetPropPB : TBytes; 
begin
  Result := FP;
end;

procedure TipcRSAKey.SetPropPB(Value: TBytes); 
begin
  FP := Value;
end;

function TipcRSAKey.GetPropPrivateKey: String;
begin
  Result := String(FPrivateKey);
end;

procedure TipcRSAKey.SetPropPrivateKey(Value: String);
begin
  FPrivateKey := Value;
end;


function TipcRSAKey.GetPropPublicKey: String;
begin
  Result := String(FPublicKey);
end;

procedure TipcRSAKey.SetPropPublicKey(Value: String);
begin
  FPublicKey := Value;
end;


function TipcRSAKey.GetPropQ: String;
begin
  Result := {$IFDEF UNICODE}TEncoding.UTF8.GetString{$else}string{$endif}(FQ);
end;

procedure TipcRSAKey.SetPropQ(Value: String);
begin
  FQ := {$IFDEF UNICODE}TEncoding.UTF8.GetBytes{$else}TBytes{$endif}(Value);
end;

function  TipcRSAKey.GetPropQB : TBytes; 
begin
  Result := FQ;
end;

procedure TipcRSAKey.SetPropQB(Value: TBytes); 
begin
  FQ := Value;
end;


//////////////////////////////////////////////////////////////////////////////////////////
// TipcRSAKeyList type
constructor TipcRSAKeyList.Create();
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := false;
  FCount := 0;
  FOwnerCtl := nil;
end;

constructor TipcRSAKeyList.Create(ReadOnly: Boolean);
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := ReadOnly;
  FCount := 0;
  FOwnerCtl := nil;
end;

constructor TipcRSAKeyList.Create(Owner: TObject; ReadOnly: Boolean); 
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := ReadOnly;
  FCount := 0;
  FOwnerCtl := Owner;
end;

destructor TipcRSAKeyList.Destroy; 
begin
  ClearList;
  FreeAndNil(FItems);
  inherited;
end;

procedure TipcRSAKeyList.ClearList;
var
  Inst : TipcRSAKey;
  I: integer;
begin
  try
    for I := 0 to FItems.Count - 1 do
    begin
      Inst := TipcRSAKey(FItems[I]);
      {$ifndef AUTOREFCOUNT}
      Inst.Free;
      {$else}
      Inst.__ObjRelease;
      Inst.DisposeOf;
      {$endif};
    end;
  finally
    FItems.Clear;
  end;
end;

function TipcRSAKeyList.IsFree: boolean;
begin
  // This method tells the requestor whether the collection object is freestanding or bound
  Result := FOwnerCtl = nil;
end;

procedure TipcRSAKeyList.SyncCount;
var
  Inst : TipcRSAKey;
  I: integer;
begin
  // This method updates the number of objects held by the collection. It is only relevant for bound collections.
  if not IsFree then
  begin
    FCount := CtlGetCount();
    while FItems.Count < FCount do
    begin
      Inst := CreateElemInstance(FItems.Count);
      FItems.Add(Inst);
      {$ifdef AUTOREFCOUNT}
      Inst.__ObjAddRef;
      {$endif}
    end;
  end;
end;

procedure TipcRSAKeyList.InternalSetCount(Value: integer);
var
  Inst : TipcRSAKey;
begin
  // This method updates the number of elements in the underlying list. 
  // For both free and bound collections, it will verify that the list has sufficient capacity.
  while FItems.Count < Value do
  begin
    Inst := CreateElemInstance(FItems.Count);
    FItems.Add(Inst);
    {$ifdef AUTOREFCOUNT}
    Inst.__ObjAddRef;
    {$endif}
  end;

  if not IsFree then
    CtlSetCount(Value);
  FCount := Value;
end;

procedure TipcRSAKeyList.InternalSetItem(Index: integer; Value: TipcRSAKey);
begin
  // This method assigns (effectively copies) an item to collection.
  // It is expected that the boundaries have been checked before this method was called.
  TipcRSAKey(FItems[Index]).Assign(Value); // Assign, if needed, will redirect any setters to the underlying control's methods
end;

procedure TipcRSAKeyList.Assign(Source: TPersistent);
var
  i: integer;
  Src: TipcRSAKeyList;
begin
  if Source is TipcRSAKeyList then
  begin
    Src := TipcRSAKeyList(Source);
    InternalSetCount(Src.GetCount);
    for i := 0 to Src.GetCount - 1 do
      InternalSetItem(i, Src.GetItem(i));
      
  end
  else
    inherited;
end;

function TipcRSAKeyList.Clone: TipcRSAKeyList;
begin
  Result := TipcRSAKeyList.Create(FReadOnlyProp); // When cloning, always creating a freestanding object
  Result.Assign(Self);
  
end;

function TipcRSAKeyList.GetCount: Integer;
begin
  SyncCount;
  Result := FCount;
end;

function TipcRSAKeyList.GetItem(Idx: integer): TipcRSAKey;
begin
  SyncCount;  
  
  Result := TipcRSAKey(FItems[Idx]); 
end;

procedure TipcRSAKeyList.SetItem(Idx: integer; Value: TipcRSAKey);
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  
  if (Idx < 0) or (Idx >= GetCount) then
    raise Exception.Create('Index out of bounds');


  InternalSetItem(Idx, Value);
end;

function TipcRSAKeyList.GetIsReadOnly: boolean;
begin
  Result := FReadOnlyProp;
end;

function TipcRSAKeyList.GetIsFixedSize: boolean;
begin
  Result := false;
end;

function TipcRSAKeyList.GetSyncRoot: TObject;
begin
  raise Exception.Create('Not implemented');
end;

function TipcRSAKeyList.GetIsSynchronized: boolean;
begin
  Result := false;
end;

function TipcRSAKeyList.Add(Value: TipcRSAKey): Integer;
var
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  InternalSetCount(OldCount + 1);
  InternalSetItem(OldCount, Value);
  Result := OldCount;
end;

function TipcRSAKeyList.Add(): Integer; 
var
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  InternalSetCount(OldCount + 1);
  Result := OldCount;
end;

procedure TipcRSAKeyList.Remove(value: TipcRSAKey);
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  raise Exception.Create('Not implemented');
end;

function TipcRSAKeyList.Contains(value: TipcRSAKey): Boolean;
begin
  raise Exception.Create('Not implemented');
end;

function TipcRSAKeyList.IndexOf(value: TipcRSAKey): Integer;
begin
  raise Exception.Create('Not implemented');
end;

procedure TipcRSAKeyList.Insert(Idx: Integer; value: TipcRSAKey);
var
  OldCount: integer;
  I: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  if (Idx < 0) or (Idx >= OldCount) then
    raise Exception.Create('Index out of bounds');
  InternalSetCount(OldCount + 1);
  for I := OldCount downto Idx + 1 do
    InternalSetItem(I, GetItem(i - 1));
  InternalSetItem(Idx, value);
end;

procedure TipcRSAKeyList.RemoveAt(idx: Integer);
var
  I: integer;
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  if (Idx < 0) or (Idx >= OldCount) then
    raise Exception.Create('Index out of bounds');
  // Only copying the needed subset of elements, without cleaning them up
  for I := Idx to OldCount - 2 do
    InternalSetItem(I, GetItem(I + 1));
  InternalSetCount(OldCount - 1);
end;


procedure TipcRSAKeyList.Clear();
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  InternalSetCount(0);
end;

function TipcRSAKeyList.CtlGetCount: integer;
begin
  ; // to be overridden in derived classes
end;

procedure TipcRSAKeyList.CtlSetCount(Value: integer);
begin
  ; // to be overridden in derived classes
end;

function TipcRSAKeyList.CreateElemInstance(Index: integer): TipcRSAKey; 
begin
  Result := TipcRSAKey.Create(FOwnerCtl, FReadOnlyProp);
  Result.Index := Index;
end;


//////////////////////////////////////////////////////////////////////////////////////////
// TipcXMLEncryptedDataDetail type

constructor TipcXMLEncryptedDataDetail.Create();
begin
  inherited Create;
  FIndex := -1;
  FOwnerCtl := nil;
  FReadOnlyProp := false;
end;


constructor TipcXMLEncryptedDataDetail.Create(Owner: TObject; ReadOnly: boolean);
begin
  inherited Create;
  FOwnerCtl := Owner;
  FReadOnlyProp := ReadOnly;
  FIndex := -1;
end;

destructor TipcXMLEncryptedDataDetail.Destroy;
begin
  inherited;
end;

procedure TipcXMLEncryptedDataDetail.Assign(Source: TPersistent);
var
  i: integer;
  Src: TipcXMLEncryptedDataDetail;
begin
  // Copy contents using setters and getters. No owner or index is copied: this is simply an assignment
  // of a collection of fields to another object, not a creation of a full copy.
        
  if Source is TipcXMLEncryptedDataDetail then
  begin


    SetPropId(TipcXMLEncryptedDataDetail(Source).GetPropId);
    SetPropMIMEType(TipcXMLEncryptedDataDetail(Source).GetPropMIMEType);
    SetPropScope(TipcXMLEncryptedDataDetail(Source).GetPropScope);
    SetPropXMLElement(TipcXMLEncryptedDataDetail(Source).GetPropXMLElement);
  end
  else
    inherited;
end;

function TipcXMLEncryptedDataDetail.Clone: TipcXMLEncryptedDataDetail;
begin
  // Always clone to a freestanding instance of the base class
  Result := TipcXMLEncryptedDataDetail.Create(nil, FReadOnlyProp);
  Result.Assign(Self);
end;


function TipcXMLEncryptedDataDetail.GetPropId: String;
begin
  Result := String(FId);
end;

procedure TipcXMLEncryptedDataDetail.SetPropId(Value: String);
begin
  FId := Value;
end;


function TipcXMLEncryptedDataDetail.GetPropMIMEType: String;
begin
  Result := String(FMIMEType);
end;

procedure TipcXMLEncryptedDataDetail.SetPropMIMEType(Value: String);
begin
  FMIMEType := Value;
end;


function TipcXMLEncryptedDataDetail.GetPropScope: TipcScopes;
begin
  Result := {T}(FScope);
end;

procedure TipcXMLEncryptedDataDetail.SetPropScope(Value: TipcScopes);
begin
  FScope := Value;
end;


function TipcXMLEncryptedDataDetail.GetPropXMLElement: String;
begin
  Result := String(FXMLElement);
end;

procedure TipcXMLEncryptedDataDetail.SetPropXMLElement(Value: String);
begin
  FXMLElement := Value;
end;



//////////////////////////////////////////////////////////////////////////////////////////
// TipcXMLEncryptedDataDetailList type
constructor TipcXMLEncryptedDataDetailList.Create();
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := false;
  FCount := 0;
  FOwnerCtl := nil;
end;

constructor TipcXMLEncryptedDataDetailList.Create(ReadOnly: Boolean);
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := ReadOnly;
  FCount := 0;
  FOwnerCtl := nil;
end;

constructor TipcXMLEncryptedDataDetailList.Create(Owner: TObject; ReadOnly: Boolean); 
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := ReadOnly;
  FCount := 0;
  FOwnerCtl := Owner;
end;

destructor TipcXMLEncryptedDataDetailList.Destroy; 
begin
  ClearList;
  FreeAndNil(FItems);
  inherited;
end;

procedure TipcXMLEncryptedDataDetailList.ClearList;
var
  Inst : TipcXMLEncryptedDataDetail;
  I: integer;
begin
  try
    for I := 0 to FItems.Count - 1 do
    begin
      Inst := TipcXMLEncryptedDataDetail(FItems[I]);
      {$ifndef AUTOREFCOUNT}
      Inst.Free;
      {$else}
      Inst.__ObjRelease;
      Inst.DisposeOf;
      {$endif};
    end;
  finally
    FItems.Clear;
  end;
end;

function TipcXMLEncryptedDataDetailList.IsFree: boolean;
begin
  // This method tells the requestor whether the collection object is freestanding or bound
  Result := FOwnerCtl = nil;
end;

procedure TipcXMLEncryptedDataDetailList.SyncCount;
var
  Inst : TipcXMLEncryptedDataDetail;
  I: integer;
begin
  // This method updates the number of objects held by the collection. It is only relevant for bound collections.
  if not IsFree then
  begin
    FCount := CtlGetCount();
    while FItems.Count < FCount do
    begin
      Inst := CreateElemInstance(FItems.Count);
      FItems.Add(Inst);
      {$ifdef AUTOREFCOUNT}
      Inst.__ObjAddRef;
      {$endif}
    end;
  end;
end;

procedure TipcXMLEncryptedDataDetailList.InternalSetCount(Value: integer);
var
  Inst : TipcXMLEncryptedDataDetail;
begin
  // This method updates the number of elements in the underlying list. 
  // For both free and bound collections, it will verify that the list has sufficient capacity.
  while FItems.Count < Value do
  begin
    Inst := CreateElemInstance(FItems.Count);
    FItems.Add(Inst);
    {$ifdef AUTOREFCOUNT}
    Inst.__ObjAddRef;
    {$endif}
  end;

  if not IsFree then
    CtlSetCount(Value);
  FCount := Value;
end;

procedure TipcXMLEncryptedDataDetailList.InternalSetItem(Index: integer; Value: TipcXMLEncryptedDataDetail);
begin
  // This method assigns (effectively copies) an item to collection.
  // It is expected that the boundaries have been checked before this method was called.
  TipcXMLEncryptedDataDetail(FItems[Index]).Assign(Value); // Assign, if needed, will redirect any setters to the underlying control's methods
end;

procedure TipcXMLEncryptedDataDetailList.Assign(Source: TPersistent);
var
  i: integer;
  Src: TipcXMLEncryptedDataDetailList;
begin
  if Source is TipcXMLEncryptedDataDetailList then
  begin
    Src := TipcXMLEncryptedDataDetailList(Source);
    InternalSetCount(Src.GetCount);
    for i := 0 to Src.GetCount - 1 do
      InternalSetItem(i, Src.GetItem(i));
      
  end
  else
    inherited;
end;

function TipcXMLEncryptedDataDetailList.Clone: TipcXMLEncryptedDataDetailList;
begin
  Result := TipcXMLEncryptedDataDetailList.Create(FReadOnlyProp); // When cloning, always creating a freestanding object
  Result.Assign(Self);
  
end;

function TipcXMLEncryptedDataDetailList.GetCount: Integer;
begin
  SyncCount;
  Result := FCount;
end;

function TipcXMLEncryptedDataDetailList.GetItem(Idx: integer): TipcXMLEncryptedDataDetail;
begin
  SyncCount;  
  
  Result := TipcXMLEncryptedDataDetail(FItems[Idx]); 
end;

procedure TipcXMLEncryptedDataDetailList.SetItem(Idx: integer; Value: TipcXMLEncryptedDataDetail);
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  
  if (Idx < 0) or (Idx >= GetCount) then
    raise Exception.Create('Index out of bounds');


  InternalSetItem(Idx, Value);
end;

function TipcXMLEncryptedDataDetailList.GetIsReadOnly: boolean;
begin
  Result := FReadOnlyProp;
end;

function TipcXMLEncryptedDataDetailList.GetIsFixedSize: boolean;
begin
  Result := false;
end;

function TipcXMLEncryptedDataDetailList.GetSyncRoot: TObject;
begin
  raise Exception.Create('Not implemented');
end;

function TipcXMLEncryptedDataDetailList.GetIsSynchronized: boolean;
begin
  Result := false;
end;

function TipcXMLEncryptedDataDetailList.Add(Value: TipcXMLEncryptedDataDetail): Integer;
var
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  InternalSetCount(OldCount + 1);
  InternalSetItem(OldCount, Value);
  Result := OldCount;
end;

function TipcXMLEncryptedDataDetailList.Add(): Integer; 
var
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  InternalSetCount(OldCount + 1);
  Result := OldCount;
end;

procedure TipcXMLEncryptedDataDetailList.Remove(value: TipcXMLEncryptedDataDetail);
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  raise Exception.Create('Not implemented');
end;

function TipcXMLEncryptedDataDetailList.Contains(value: TipcXMLEncryptedDataDetail): Boolean;
begin
  raise Exception.Create('Not implemented');
end;

function TipcXMLEncryptedDataDetailList.IndexOf(value: TipcXMLEncryptedDataDetail): Integer;
begin
  raise Exception.Create('Not implemented');
end;

procedure TipcXMLEncryptedDataDetailList.Insert(Idx: Integer; value: TipcXMLEncryptedDataDetail);
var
  OldCount: integer;
  I: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  if (Idx < 0) or (Idx >= OldCount) then
    raise Exception.Create('Index out of bounds');
  InternalSetCount(OldCount + 1);
  for I := OldCount downto Idx + 1 do
    InternalSetItem(I, GetItem(i - 1));
  InternalSetItem(Idx, value);
end;

procedure TipcXMLEncryptedDataDetailList.RemoveAt(idx: Integer);
var
  I: integer;
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  if (Idx < 0) or (Idx >= OldCount) then
    raise Exception.Create('Index out of bounds');
  // Only copying the needed subset of elements, without cleaning them up
  for I := Idx to OldCount - 2 do
    InternalSetItem(I, GetItem(I + 1));
  InternalSetCount(OldCount - 1);
end;


procedure TipcXMLEncryptedDataDetailList.Clear();
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  InternalSetCount(0);
end;

function TipcXMLEncryptedDataDetailList.CtlGetCount: integer;
begin
  ; // to be overridden in derived classes
end;

procedure TipcXMLEncryptedDataDetailList.CtlSetCount(Value: integer);
begin
  ; // to be overridden in derived classes
end;

function TipcXMLEncryptedDataDetailList.CreateElemInstance(Index: integer): TipcXMLEncryptedDataDetail; 
begin
  Result := TipcXMLEncryptedDataDetail.Create(FOwnerCtl, FReadOnlyProp);
  Result.Index := Index;
end;


//////////////////////////////////////////////////////////////////////////////////////////
// TipcXMLSigReference type

constructor TipcXMLSigReference.Create();
begin
  inherited Create;
  FIndex := -1;
  FOwnerCtl := nil;
  FReadOnlyProp := false;
end;
constructor TipcXMLSigReference.Create(valXMLElement: String; valURI: String; valHashAlgorithm: String; valTransformAlgorithms: String; valHashValue: String);
begin
  inherited Create;
  FIndex := -1;
  FOwnerCtl := nil;
  FReadOnlyProp := false;
  FXMLElement := valXMLElement;
  FURI := valURI;
  FHashAlgorithm := valHashAlgorithm;
  FTransformAlgorithms := valTransformAlgorithms;
  FHashValue := valHashValue;
end;


constructor TipcXMLSigReference.Create(Owner: TObject; ReadOnly: boolean);
begin
  inherited Create;
  FOwnerCtl := Owner;
  FReadOnlyProp := ReadOnly;
  FIndex := -1;
end;

destructor TipcXMLSigReference.Destroy;
begin
  inherited;
end;

procedure TipcXMLSigReference.Assign(Source: TPersistent);
var
  i: integer;
  Src: TipcXMLSigReference;
begin
  // Copy contents using setters and getters. No owner or index is copied: this is simply an assignment
  // of a collection of fields to another object, not a creation of a full copy.
          
  if Source is TipcXMLSigReference then
  begin


    SetPropHashAlgorithm(TipcXMLSigReference(Source).GetPropHashAlgorithm);
    SetPropHashValue(TipcXMLSigReference(Source).GetPropHashValue);
    SetPropTransformAlgorithms(TipcXMLSigReference(Source).GetPropTransformAlgorithms);
    SetPropURI(TipcXMLSigReference(Source).GetPropURI);
    SetPropXMLElement(TipcXMLSigReference(Source).GetPropXMLElement);
  end
  else
    inherited;
end;

function TipcXMLSigReference.Clone: TipcXMLSigReference;
begin
  // Always clone to a freestanding instance of the base class
  Result := TipcXMLSigReference.Create(nil, FReadOnlyProp);
  Result.Assign(Self);
end;


function TipcXMLSigReference.GetPropHashAlgorithm: String;
begin
  Result := String(FHashAlgorithm);
end;

procedure TipcXMLSigReference.SetPropHashAlgorithm(Value: String);
begin
  FHashAlgorithm := Value;
end;


function TipcXMLSigReference.GetPropHashValue: String;
begin
  Result := String(FHashValue);
end;

procedure TipcXMLSigReference.SetPropHashValue(Value: String);
begin
  FHashValue := Value;
end;


function TipcXMLSigReference.GetPropTransformAlgorithms: String;
begin
  Result := String(FTransformAlgorithms);
end;

procedure TipcXMLSigReference.SetPropTransformAlgorithms(Value: String);
begin
  FTransformAlgorithms := Value;
end;


function TipcXMLSigReference.GetPropURI: String;
begin
  Result := String(FURI);
end;

procedure TipcXMLSigReference.SetPropURI(Value: String);
begin
  FURI := Value;
end;


function TipcXMLSigReference.GetPropXMLElement: String;
begin
  Result := String(FXMLElement);
end;

procedure TipcXMLSigReference.SetPropXMLElement(Value: String);
begin
  FXMLElement := Value;
end;



//////////////////////////////////////////////////////////////////////////////////////////
// TipcXMLSigReferenceList type
constructor TipcXMLSigReferenceList.Create();
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := false;
  FCount := 0;
  FOwnerCtl := nil;
end;

constructor TipcXMLSigReferenceList.Create(ReadOnly: Boolean);
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := ReadOnly;
  FCount := 0;
  FOwnerCtl := nil;
end;

constructor TipcXMLSigReferenceList.Create(Owner: TObject; ReadOnly: Boolean); 
begin
  inherited Create;
  FItems := TList.Create;
  FReadOnlyProp := ReadOnly;
  FCount := 0;
  FOwnerCtl := Owner;
end;

destructor TipcXMLSigReferenceList.Destroy; 
begin
  ClearList;
  FreeAndNil(FItems);
  inherited;
end;

procedure TipcXMLSigReferenceList.ClearList;
var
  Inst : TipcXMLSigReference;
  I: integer;
begin
  try
    for I := 0 to FItems.Count - 1 do
    begin
      Inst := TipcXMLSigReference(FItems[I]);
      {$ifndef AUTOREFCOUNT}
      Inst.Free;
      {$else}
      Inst.__ObjRelease;
      Inst.DisposeOf;
      {$endif};
    end;
  finally
    FItems.Clear;
  end;
end;

function TipcXMLSigReferenceList.IsFree: boolean;
begin
  // This method tells the requestor whether the collection object is freestanding or bound
  Result := FOwnerCtl = nil;
end;

procedure TipcXMLSigReferenceList.SyncCount;
var
  Inst : TipcXMLSigReference;
  I: integer;
begin
  // This method updates the number of objects held by the collection. It is only relevant for bound collections.
  if not IsFree then
  begin
    FCount := CtlGetCount();
    while FItems.Count < FCount do
    begin
      Inst := CreateElemInstance(FItems.Count);
      FItems.Add(Inst);
      {$ifdef AUTOREFCOUNT}
      Inst.__ObjAddRef;
      {$endif}
    end;
  end;
end;

procedure TipcXMLSigReferenceList.InternalSetCount(Value: integer);
var
  Inst : TipcXMLSigReference;
begin
  // This method updates the number of elements in the underlying list. 
  // For both free and bound collections, it will verify that the list has sufficient capacity.
  while FItems.Count < Value do
  begin
    Inst := CreateElemInstance(FItems.Count);
    FItems.Add(Inst);
    {$ifdef AUTOREFCOUNT}
    Inst.__ObjAddRef;
    {$endif}
  end;

  if not IsFree then
    CtlSetCount(Value);
  FCount := Value;
end;

procedure TipcXMLSigReferenceList.InternalSetItem(Index: integer; Value: TipcXMLSigReference);
begin
  // This method assigns (effectively copies) an item to collection.
  // It is expected that the boundaries have been checked before this method was called.
  TipcXMLSigReference(FItems[Index]).Assign(Value); // Assign, if needed, will redirect any setters to the underlying control's methods
end;

procedure TipcXMLSigReferenceList.Assign(Source: TPersistent);
var
  i: integer;
  Src: TipcXMLSigReferenceList;
begin
  if Source is TipcXMLSigReferenceList then
  begin
    Src := TipcXMLSigReferenceList(Source);
    InternalSetCount(Src.GetCount);
    for i := 0 to Src.GetCount - 1 do
      InternalSetItem(i, Src.GetItem(i));
      
  end
  else
    inherited;
end;

function TipcXMLSigReferenceList.Clone: TipcXMLSigReferenceList;
begin
  Result := TipcXMLSigReferenceList.Create(FReadOnlyProp); // When cloning, always creating a freestanding object
  Result.Assign(Self);
  
end;

function TipcXMLSigReferenceList.GetCount: Integer;
begin
  SyncCount;
  Result := FCount;
end;

function TipcXMLSigReferenceList.GetItem(Idx: integer): TipcXMLSigReference;
begin
  SyncCount;  
  
  Result := TipcXMLSigReference(FItems[Idx]); 
end;

procedure TipcXMLSigReferenceList.SetItem(Idx: integer; Value: TipcXMLSigReference);
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  
  if (Idx < 0) or (Idx >= GetCount) then
    raise Exception.Create('Index out of bounds');


  InternalSetItem(Idx, Value);
end;

function TipcXMLSigReferenceList.GetIsReadOnly: boolean;
begin
  Result := FReadOnlyProp;
end;

function TipcXMLSigReferenceList.GetIsFixedSize: boolean;
begin
  Result := false;
end;

function TipcXMLSigReferenceList.GetSyncRoot: TObject;
begin
  raise Exception.Create('Not implemented');
end;

function TipcXMLSigReferenceList.GetIsSynchronized: boolean;
begin
  Result := false;
end;

function TipcXMLSigReferenceList.Add(Value: TipcXMLSigReference): Integer;
var
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  InternalSetCount(OldCount + 1);
  InternalSetItem(OldCount, Value);
  Result := OldCount;
end;

function TipcXMLSigReferenceList.Add(): Integer; 
var
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  InternalSetCount(OldCount + 1);
  Result := OldCount;
end;

procedure TipcXMLSigReferenceList.Remove(value: TipcXMLSigReference);
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  raise Exception.Create('Not implemented');
end;

function TipcXMLSigReferenceList.Contains(value: TipcXMLSigReference): Boolean;
begin
  raise Exception.Create('Not implemented');
end;

function TipcXMLSigReferenceList.IndexOf(value: TipcXMLSigReference): Integer;
begin
  raise Exception.Create('Not implemented');
end;

procedure TipcXMLSigReferenceList.Insert(Idx: Integer; value: TipcXMLSigReference);
var
  OldCount: integer;
  I: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  if (Idx < 0) or (Idx >= OldCount) then
    raise Exception.Create('Index out of bounds');
  InternalSetCount(OldCount + 1);
  for I := OldCount downto Idx + 1 do
    InternalSetItem(I, GetItem(i - 1));
  InternalSetItem(Idx, value);
end;

procedure TipcXMLSigReferenceList.RemoveAt(idx: Integer);
var
  I: integer;
  OldCount: integer;
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  SyncCount;
  OldCount := GetCount();
  if (Idx < 0) or (Idx >= OldCount) then
    raise Exception.Create('Index out of bounds');
  // Only copying the needed subset of elements, without cleaning them up
  for I := Idx to OldCount - 2 do
    InternalSetItem(I, GetItem(I + 1));
  InternalSetCount(OldCount - 1);
end;


procedure TipcXMLSigReferenceList.Clear();
begin
  if FReadOnlyProp then
    raise Exception.Create('Operation prohibited: list is read-only.');
  InternalSetCount(0);
end;

function TipcXMLSigReferenceList.CtlGetCount: integer;
begin
  ; // to be overridden in derived classes
end;

procedure TipcXMLSigReferenceList.CtlSetCount(Value: integer);
begin
  ; // to be overridden in derived classes
end;

function TipcXMLSigReferenceList.CreateElemInstance(Index: integer): TipcXMLSigReference; 
begin
  Result := TipcXMLSigReference.Create(FOwnerCtl, FReadOnlyProp);
  Result.Index := Index;
end;




end.