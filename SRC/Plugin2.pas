////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//                        OLLYDBG 2 PLUGIN HEADER FILE                        //
//                                                                            //
//                                Version 2.01h                               //
//                                                                            //
//               Written by Oleh Yuschuk (ollydbg@t-online.de)                //
//                                                                            //
//                          Internet: www.ollydbg.de                          //
//                                                                            //
// This code is distributed "as is", without warranty of any kind, expressed  //
// or implied, including, but not limited to warranty of fitness for any      //
// particular purpose. In no event will Oleh Yuschuk be liable to you for any //
// special, incidental, indirect, consequential or any other damages caused   //
// by the use, misuse, or the inability to use of this code, including any    //
// lost profits or lost savings, even if Oleh Yuschuk has been advised of the //
// possibility of such damages.                                               //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////
//////////////////////////// IMPORTANT INFORMATION /////////////////////////////
//                                                                            //
// 1. Plugins are UNICODE libraries!                                          //
// 2. Export all callback functions by name, NOT by ordinal!                  //
// 3. Force byte alignment of OllyDbg structures!                             //
// 4. Set default char type to unsigned!                                      //
// 5. Most API functions are NOT thread-safe!                                 //
// 6. Read documentation!                                                     //
////////////////////////////////////////////////////////////////////////////////

{$IFNDEF WIN32}
  Error: Only support Win32
{$ENDIF}

unit Plugin2;

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Porting from Cplus header to unit delphi by quygia128                      //
// Email: quygia128@gmail.com                                                 //
// Home: http://cin1team.biz                                                  //
// Last edit on: 04.23.2014 by TQN(ThangCuAnh)                                //
// Special thanks & Credits go to TQN ~ phpbb3 ~ BOB                          //
// Greetz to all my friends                                                   //
// -----                                                                      //
// For plugin power by Delphi (Test IDE: Delphi 7 & Delphi 2010)              //
// Check for update: https://github.com/quygia128                             //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

interface

uses
  Windows;

{$ALIGN 1}                                  // Struct byte alignment
{$MINENUMSIZE 4}                            // Size of enumerated types are 4 bytes

{$WARN UNSAFE_CODE OFF}
{$WARN UNSAFE_TYPE OFF}
{$WARN UNSAFE_CAST OFF}

const
  PLUGIN_VERSION = $02010001;               // Version 2.01.0001 of plugin interface
  TEXTLEN        = 256;                     // Max length of text string incl. '\0'
  DATALEN        = 4096;                    // Max length of data record (max 65535)
  ARGLEN         = 1024;                    // Max length of argument string
  MAXMULTIPATH   = 8192;                    // Max length of multiple selection
  SHORTNAME      = 32;                      // Max length of short or module name
  MAXPATH        = MAX_PATH;
  OLLYDBG        = 'ollydbg.exe';

type
{$IFDEF UNICODE}
  AChar          = AnsiChar;                // Delphi 6,7 SRC Work With Delphi 2009, 2010, XE.x
  PAChar         = PAnsiChar;               // Delphi 6,7 SRC Work With Delphi 2009, 2010, XE.x
{$ELSE}
  AChar          = type Char;
  PAChar         = type PChar;
{$ENDIF}
  UShort         = Word;
  PUShort        = ^UShort;


////////////////////////////////////////////////////////////////////////////////
////////////////////////////// SERVICE FUNCTIONS ///////////////////////////////
const
  // Flags returned by functions Istext.../Israre...
  PLAINASCII     = $01;                     // Plain ASCII character
  DIACRITICAL    = $02;                     // Diacritical character
  RAREASCII      = $10;                     // Rare ASCII character

  // Flags used by Memalloc() and Virtalloc(). Note that Virtalloc() alwyas
  // initializes memory to zero.
  REPORT         = $0000;                   // Report memory allocation errors
  SILENT         = $0001;                   // Don't report allocation errors
  ZEROINIT       = $0002;                   // Initialize memory to 0

  CONT_BROADCAST = $0000;                   // Continue sending msg to MDI windows
  STOP_BROADCAST = $1234;                   // Stop sending message to MDI windows

  // Symbol decoding mode, used by Decodethreadname(), Decodeaddress() and
  // Decoderelativeoffset().
  // Bits that determine when to decode and comment name at all.
  DM_VALID       = $00000001;               // Only decode if memory exists
  DM_INMOD       = $00000002;               // Only decode if in module
  DM_SAMEMOD     = $00000004;               // Only decode if in same module
  DM_SYMBOL      = $00000008;               // Only decode if direct symbolic name
  DM_NONTRIVIAL  = $00000010;               // Only decode if nontrivial form
  // Bits that control name format.
  DM_BINARY      = $00000100;               // Don't use symbolic form
  DM_DIFBIN      = $00000200;               // No symbolic form if different module
  DM_WIDEFORM    = $00000400;               // Extended form (8 digits by hex)
  DM_CAPITAL     = $00000800;               // First letter in uppercase if possible
  DM_OFFSET      = $00001000;               // Add 'OFFSET' if data
  DM_JUMPIMP     = $00002000;               // Check if points to JMP to import
  DM_DYNAMIC     = $00004000;               // Check if points to JMP to DLL
  DM_ORDINAL     = $00008000;               // Add ordinal to thread's name
  // Bits that control whether address is preceded with module name.
  DM_NOMODNAME   = $00000000;               // Never add module name
  DM_DIFFMODNAME = $00010000;               // Add name only if different module
  DM_MODNAME     = $00020000;               // Always add module name
  // Bits that control comments.
  DM_STRING      = $00100000;               // Check if pointer to ASCII or UNICODE
  DM_STRPTR      = $00200000;               // Check if points to pointer to text
  DM_FOLLOW      = $00400000;               // Check if follows to different symbol
  DM_ENTRY       = $00800000;               // Check if unnamed entry to subroutine
  DM_EFORCE      = $01000000;               // Check if named entry, too
  DM_DIFFMOD     = $02000000;               // Check if points to different module
  DM_RELOFFS     = $04000000;               // Check if points inside subroutine
  DM_ANALYSED    = $08000000;               // Check if points to decoded data

  // Standard commenting mode. Note: DM_DIFFMOD and DM_RELOFFS are not included.
  DM_COMMENT     = DM_STRING or DM_STRPTR or DM_FOLLOW or DM_ENTRY or DM_ANALYSED;

  // Address decoding mode, used by Labeladdress().
  ADDR_SYMMASK   = $00000003;               // Mask to extract sym presentation mode
    ADDR_HEXSYM  = $00000000;               // Hex, followed by symbolic name
    ADDR_SYMHEX  = $00000001;               // Symbolic name, followed by hex
    ADDR_SINGLE  = $00000002;               // Symbolic name, or hex if none
    ADDR_HEXONLY = $00000003;               // Only hexadecimal address
  ADDR_MODNAME   = $00000004;               // Add module name to symbol
  ADDR_FORCEMOD  = $00000008;               // (ADDR_SINGLE) Always add module name
  ADDR_GRAYHEX   = $00000010;               // Gray hex
  ADDR_HILSYM    = $00000020;               // Highlight symbolic name
  ADDR_NODEFMEP  = $00000100;               // Do not show <ModuleEntryPoint>
  ADDR_BREAK     = $00000200;               // Mark as unconditional breakpoint
  ADDR_CONDBRK   = $00000400;               // Mark as conditional breakpoint
  ADDR_DISBRK    = $00000800;               // Mark as disabled breakpoint
  ADDR_EIP       = $00001000;               // Mark as actual EIP
  ADDR_CHECKEIP  = $00002000;               // Mark as EIP if EIP of CPU thread
  ADDR_SHOWNULL  = $00004000;               // Display address 0

  // Mode bits and return value of Browsefilename().
  BRO_MODEMASK   = $F0000000;               // Mask to extract browsing mode
    BRO_FILE     = $00000000;               // Get file name
    BRO_EXE      = $10000000;               // Get name of executable
    BRO_TEXT     = $20000000;               // Get name of text log
    BRO_GROUP    = $30000000;               // Get one or several obj or lib files
    BRO_MULTI    = $40000000;               // Get one or several files
  BRO_SAVE       = $08000000;               // Get name in save mode
  BRO_SINGLE     = $00800000;               // Single file selected
  BRO_MULTIPLE   = $00400000;               // Multiple files selected
  BRO_APPEND     = $00080000;               // Append to existing file
  BRO_ACTUAL     = $00040000;               // Add actual contents
  BRO_TABS       = $00020000;               // Separate columns with tabs
  BRO_GROUPMASK  = $000000FF;               // Mask to extract groups
    BRO_GROUP1   = $00000001;               // Belongs to group 1
    BRO_GROUP2   = $00000002;               // Belongs to group 2
    BRO_GROUP3   = $00000004;               // Belongs to group 3
    BRO_GROUP4   = $00000008;               // Belongs to group 4

  // String decoding modes.
  DS_DIR         = 0;                       // Direct quote
  DS_ASM         = 1;                       // Assembler style
  DS_C           = 2;                       // C style

type
  TCompare   = function(p1: Pointer; p2: Pointer): Integer; cdecl;
  TCompareex = function(p1: Pointer; p2: Pointer; n: ULong): Integer; cdecl;

procedure Error(format: PWChar); cdecl; varargs; external OLLYDBG name 'Error';
procedure Conderror(cond: PInteger; title: PWChar; format: PWChar); cdecl; varargs; external OLLYDBG name 'Conderror';
function  Condyesno(cond: PInteger; title: PWChar; format: PWChar): Integer; cdecl; varargs; external OLLYDBG name 'Condyesno';
function  Stringfromini(section: PWChar; key: PWChar; s: PWChar;
            length: Integer): Integer; cdecl; external OLLYDBG name 'Stringfromini';
function  Filefromini(key: PWChar; name: PWChar; defname: PWChar): Integer; cdecl; external OLLYDBG name 'Filefromini';
function  Getfromini(pfile: PWChar; section: PWChar; key: PWChar;
            format: PWChar): Integer; cdecl; varargs; external OLLYDBG name 'Getfromini';
function  Writetoini(pfile: PWChar; section: PWChar; key: PWChar;
            format: PWChar): Integer; cdecl; varargs; external OLLYDBG name 'Writetoini';
function  Filetoini(key: PWChar; name: PWChar): Integer; cdecl; external OLLYDBG name 'Filetoini';
procedure Deleteinisection(ifile: PWChar; section: PWChar); cdecl; external OLLYDBG name 'Deleteinisection';
function  Getfromsettings(key: PWChar; defvalue: Integer): Integer; cdecl; external OLLYDBG name 'Getfromsettings';
procedure Addtosettings(key: PWChar; value: Integer); cdecl; external OLLYDBG name 'Addtosettings';
procedure Replacegraphs(mode: Integer; s: PWChar; mask: PUChar;
            select: Integer; n: Integer); cdecl; external OLLYDBG name 'Replacegraphs';
function  Unicodetoascii(const w: PWChar; nw: Integer; s: PAChar; ns: Integer): Integer; cdecl; external OLLYDBG name 'Unicodetoascii';
function  Asciitounicode(const s: PAChar; ns: Integer; w: PWChar; nw: Integer): Integer; cdecl; external OLLYDBG name 'Asciitounicode';
function  Unicodetoutf(const  w: PWChar; nw: Integer; t: PAChar; nt: Integer): Integer; cdecl; external OLLYDBG name 'Unicodetoutf';
function  Utftounicode(const t: PAChar; nt: Integer; w: PWChar; nw: Integer): Integer; cdecl; external OLLYDBG name 'Utftounicode';
function  Unicodebuffertoascii(hunicode: HGLOBAL): HGLOBAL; cdecl; external OLLYDBG name 'Unicodebuffertoascii';
function  Iszero(data: Pointer; n: Integer): Integer; cdecl; external OLLYDBG name 'Iszero';
function  Guidtotext(guid: PUChar; s: PWChar): Integer; cdecl; external OLLYDBG name 'Guidtotext';
function  Swprintf(s: PWChar; format: PWChar): Integer; cdecl; varargs; external OLLYDBG name 'Swprintf';
function  Memalloc(size: ULong; flags: Integer): Pointer; cdecl; external OLLYDBG name 'Memalloc';
procedure Memfree(data: Pointer); cdecl; external OLLYDBG name 'Memfree';
function  Mempurge(data: Pointer; count: Integer; itemsize: ULong; newcount: PInteger): Pointer; cdecl; external OLLYDBG name 'Mempurge';
function  Memdouble(data: Pointer; pcount: PInteger; itemsize: ULong;
            failed: PInteger; flags: Integer): Pointer; cdecl; external OLLYDBG name 'Memdouble';
function  Virtalloc(size: ULong; flags: Integer): Pointer; cdecl; external OLLYDBG name 'Virtalloc';
procedure Virtfree(data: Pointer); cdecl; external OLLYDBG name 'Virtfree';
function  Broadcast(msg: UINT; wp: WPARAM; lp: LPARAM): Integer; cdecl; external OLLYDBG name 'Broadcast';
function  Browsefilename(title: PWChar; name: PWChar; args: PWChar;
            currdir: PWChar; defext: PWChar; hwnd: HWND; mode: Integer): Integer; cdecl; external OLLYDBG name 'Browsefilename';
function  Browsedirectory(hw: HWND; comment: PWChar; dir: PWChar):  Integer; cdecl; external OLLYDBG name 'Browsedirectory';
procedure Relativizepath(path: PWChar); cdecl; external OLLYDBG name 'Relativizepath';
procedure Absolutizepath(path: PWChar); cdecl; external OLLYDBG name 'Absolutizepath';
function  Confirmoverwrite(path: PWChar): Integer; cdecl; external OLLYDBG name 'Confirmoverwrite';
function  Labeladdress(text: PWChar; addr: ULong; reladdr: ULong; relreg: Integer;
            index: Integer; mask: PUChar; select: PInteger; mode: ULong): Integer; cdecl; external OLLYDBG name 'Labeladdress';
function  Simpleaddress(text: PWChar; addr: ULong;
            mask: PUChar; select: PInteger): Integer; cdecl; external OLLYDBG name 'Simpleaddress';
procedure Heapsort(data: Pointer; const count: Integer; const size: Integer;
            compare: TCompare); cdecl; external OLLYDBG name 'Heapsort';
procedure Heapsortex(data: Pointer; const count: Integer; const size: Integer;
            compareex: TCompareex; lp: ULong); cdecl; external OLLYDBG name 'Heapsortex';
function  Readfile(path: PWChar; fixsize: ULong; psize: PULong): PUChar; cdecl; external OLLYDBG name 'Readfile';
function  Devicenametodosname(devname: PWChar; dosname: PWChar): Integer; cdecl; external OLLYDBG name 'Devicenametodosname';
function  Filenamefromhandle(hfile: THandle; path: PWChar): Integer; cdecl; external OLLYDBG name 'Filenamefromhandle';
procedure Quicktimerstart(timer: Integer); cdecl; external OLLYDBG name 'Quicktimerstart';
procedure Quicktimerstop(timer: Integer); cdecl; external OLLYDBG name 'Quicktimerstop';
procedure Quicktimerflush(timer: Integer); cdecl; external OLLYDBG name 'Quicktimerflush';


////////////////////////////////////////////////////////////////////////////////
////////////////// FAST SERVICE ROUTINES WRITTEN IN ASSEMBLER //////////////////

function  StrcopyA(dest: PAChar; n: Integer; const src: PAChar): Integer; cdecl; external OLLYDBG name 'StrcopyA';
function  StrcopyW(dest: PWChar; n: Integer; const src: PWChar): Integer; cdecl; external OLLYDBG name 'StrcopyW';
function  StrlenA(const src: PAChar; n: Integer): Integer; cdecl; external OLLYDBG name 'StrlenA';
function  StrlenW(const src: PWChar; n: Integer ): Integer; cdecl; external OLLYDBG name 'StrlenW';
function  HexprintA(s: PAChar; u: ULong): Integer; cdecl; external OLLYDBG name 'HexprintA';
function  HexprintW(s: PWChar; u: ULong): Integer; cdecl; external OLLYDBG name 'HexprintW';
function  Hexprint4A(s: PAChar; u: ULong): Integer; cdecl; external OLLYDBG name 'Hexprint4A';
function  Hexprint4W(s: PWChar; u: ULong): Integer; cdecl; external OLLYDBG name 'Hexprint4W';
function  Hexprint8A(s: PAChar; u: ULong): Integer; cdecl; external OLLYDBG name 'Hexprint8A';
function  Hexprint8W(s: PWChar; u: ULong): Integer; cdecl; external OLLYDBG name 'Hexprint8W';
function  SignedhexA(s: PAChar; u: ULong): Integer; cdecl; external OLLYDBG name 'SignedhexA';
function  SignedhexW(s: PWChar; u: ULong): Integer; cdecl; external OLLYDBG name 'SignedhexW';
procedure Swapmem(base: Pointer; size: Integer; i1: Integer; i2: Integer); cdecl; external OLLYDBG name 'Swapmem';
function  HexdumpA(s: PAChar; code: PUChar; n: Integer): Integer; cdecl; external OLLYDBG name 'HexdumpA';
function  HexdumpW(s: PWChar; code: PUChar; n: Integer): Integer; cdecl; external OLLYDBG name 'HexdumpW';
function  Bitcount(u: ULong): Integer; cdecl; external OLLYDBG name 'Bitcount';

function  SetcaseA(s: PAChar): PAChar; cdecl; external OLLYDBG name 'SetcaseA';
function  SetcaseW(s: PWChar): PWChar; cdecl; external OLLYDBG name 'SetcaseW';
function  StrcopycaseA(dest: PAChar; n: Integer; const src: PAChar): Integer; cdecl; external OLLYDBG name 'StrcopycaseA';
function  StrcopycaseW(dest: PWChar; n: Integer; const src: PWChar): Integer; cdecl; external OLLYDBG name 'StrcopycaseW';
function  StrnstrA(data: PAChar; ndata: Integer;
            pat: PAChar; npat: Integer; ignorecase: Integer): Integer; cdecl; external OLLYDBG name 'StrnstrA';
function  StrnstrW(data: PWChar; ndata: Integer;
            pat: PWChar; npat: Integer; ignorecase: Integer): Integer; cdecl; external OLLYDBG name 'StrnstrW';
function  StrcmpW(const s1: PWChar; const s2: PWChar): Integer; stdcall; external 'kernel32.dll' name 'lstrcmpW'; // OllyDbg v2 not export this function
function  Div64by32(low: ULong; hi: ULong; zdiv: ULong): ULong; cdecl; external OLLYDBG name 'Div64by32';
function  CRCcalc(datacopy: PUChar; datasize: ULong): ULong; cdecl; external OLLYDBG name 'CRCcalc';
function  Getcpuidfeatures: Integer; cdecl; external OLLYDBG name 'Getcpuidfeatures';
procedure Maskfpu; cdecl; external OLLYDBG name 'Maskfpu';
procedure Clearfpu; cdecl; external OLLYDBG name 'Clearfpu';


////////////////////////////////////////////////////////////////////////////////
////////////////////// DATA COMPRESSION AND DECOMPRESSION //////////////////////

function  Compress(bufin: PUChar; nbufin: ULong;
            bufout: PUChar; nbufout: ULong): ULong; cdecl; external OLLYDBG name 'Compress';
function  Getoriginaldatasize(bufin: PUChar; nbufin: ULong): ULong; cdecl; external OLLYDBG name 'Getoriginaldatasize';
function  Decompress(bufin: PUChar; nbufin: ULong;
            bufout: PUChar; nbufout: ULong): ULong; cdecl; external OLLYDBG name 'Decompress';


////////////////////////////////////////////////////////////////////////////////
/////////////////////// TAGGED DATA FILES AND RESOURCES ////////////////////////

const
  MI_SIGNATURE    = $00646F4D;              // Signature of tagged file
  MI_VERSION      = $7265560A;              // File version
  MI_FILENAME     = $6C69460A;              // Record with full name of executable
  MI_FILEINFO     = $7263460A;              // Length, date, CRC (t_fileinfo)
  MI_DATA         = $7461440A;              // Name or data (t_nameinfo)
  MI_CALLBRA      = $7262430A;              // Call brackets
  MI_LOOPBRA      = $72624C0A;              // Loop brackets
  MI_PROCDATA     = $6372500A;              // Procedure data (set of t_procdata)
  MI_INT3BREAK    = $336E490A;              // INT3 breakpoint (t_bpoint)
  MI_MEMBREAK     = $6D70420A;              // Memory breakpoint (t_bpmem)
  MI_HWBREAK      = $6870420A;              // Hardware breakpoint (t_bphard)
  MI_ANALYSIS     = $616E410A;              // Record with analysis data
  MI_SWITCH       = $6977530A;              // Switch (addr+dt_switch)
  MI_CASE         = $7361430A;              // Case (addr+dt_case)
  MI_MNEMO        = $656E4D0A;              // Decoding of mnemonics (addr+dt_mnemo)
  MI_JMPDATA      = $74644A0A;              // Jump data
  MI_NETSTREAM    = $74734E0A;              // .NET streams (t_netstream)
  MI_METADATA     = $74644D0A;              // .NET MetaData tables (t_metadata)
  MI_BINSAV       = $7673420A;              // Last entered binary search patterns
  MI_MODDATA      = $61624D0A;              // Module base, size and path
  MI_PREDICT      = $6472500A;              // Predicted command execution results
  MI_LASTSAV      = $61734C0A;              // Last entered strings (t_nameinfo)
  MI_SAVEAREA     = $7661530A;              // Save area (t_savearea)
  MI_RTCOND       = $6374520A;              // Run trace pause condition
  MI_RTPROT       = $7074520A;              // Run trace protocol condition
  MI_WATCH        = $6374570A;              // Watch in watch window
  MI_LOADDLL      = $64644C0A;              // Packed loaddll.exe
  MI_PATCH        = $7461500A;              // Patch data (compressed t_patch)
  MI_PLUGIN       = $676C500A;              // Plugin prefix descriptor
  MI_END          = $646E450A;              // End of tagged file

type
  p_file = ^t_file;
  t_file = packed record                    // This is the FILE object
    curp: PByte;                            // Current active pointer
    buffer: PByte;                          // Data transfer buffer
    level: Integer;                         // fill/empty level of buffer
    bsize: Integer;                         // Buffer size
    istemp: Word;                           // Temporary file indicator
    flags: Word;                            // File status flags
    hold: PWChar;                           // Ungetc char if no buffer
    fd: UChar;                              // File descriptor
    token: Byte;                            // Used for validity checking
  end;

  p_fileinfo  = ^t_fileinfo;                // Length, date, CRC (MI_FILEINFO)
  t_fileinfo = packed record
    size: ULong;                            // Length of executable file
    filetime: FILETIME;                     // Time of last modification
    crc: ULong;                             // CRC of executable file
    issfx: Integer;                         // Whether self-extractable
    sfxentry: ULong;                        // Offset of original entry after SFX
  end;

  p_tagfile= ^t_tagfile;                    // Descriptor of tagged file (reading)
  t_tagfile = packed record
    F: p_file;                              // File descriptor
    filesize: ULong;                        // File size
    offset: ULong;                          // Actual offset
    tag: ULong;                             // Tag of next accessed record
    recsize: ULong;                         // Size of next accessed record
  end;

function  Createtaggedfile(name: PWChar; signature: PAChar; version: ULong): p_file; cdecl; external OLLYDBG name 'Createtaggedfile';
function  Savetaggedrecord(f: p_file; tag: ULong; size: ULong; data: Pointer): Integer; cdecl; external OLLYDBG name 'Savetaggedrecord';
function  Savepackedrecord(f: p_file; tag: ULong; size: ULong; data: Pointer): Integer; cdecl; external OLLYDBG name 'Savepackedrecord';
procedure Finalizetaggedfile(f: p_file); cdecl; external OLLYDBG name 'Finalizetaggedfile';
function  Opentaggedfile(tf: p_tagfile; name: PWChar; signature: PAChar): Integer; cdecl; external OLLYDBG name 'Opentaggedfile';
function  Gettaggedrecordsize(tf: p_tagfile; tag: PULong; size: PULong): Integer; cdecl; external OLLYDBG name 'Gettaggedrecordsize';
function  Gettaggedfiledata(tf: p_tagfile; buf: Pointer; bufsize: ULong): ULong; cdecl; external OLLYDBG name 'Gettaggedfiledata';
procedure Closetaggedfile(tf: p_tagfile); cdecl; external OLLYDBG name 'Closetaggedfile';

type
  p_control = ^t_control;                   // Descriptor of dialog control
  t_control = packed record
    _type: ULong;                           // type of control, CA_xxx
    id: Integer;                            // Control's ID or -1 if unimportant
    x: Integer;                             // X coordinate, chars/4
    y: Integer;                             // Y coordinate, chars/8
    dx: Integer;                            // X size, chars/4
    dy: Integer;                            // Y size, chars/8
    pvar: PInteger;                         // Pointer to control variable or NULL
    text: PWChar;                           // Name or contents of the control
    help: PWChar;                           // Tooltip or NULL
    oldvar: Integer;                        // Copy of control variable, internal
  end;

  p_nameinfo = ^t_nameinfo;                 // Header of name/data record (MI_NAME)
  t_nameinfo = packed record
    offs: ULong;                            // Offset in module
    _type: UChar;                           // Name/data type, one of NM_xxx/DT_xxx
  end;

  p_uddsave= ^t_uddsave;                    // .udd file descriptor used by plugins
  t_uddsave = packed record
    pfile: Pointer;                         // .udd file
    uddprefix: ULong;                       // .udd tag prefix
  end;

function  Pluginsaverecord(psave: p_uddsave; tag: ULong;
            size: ULong; data: Pointer): Integer; cdecl; external OLLYDBG name 'Pluginsaverecord';
function  Pluginpackedrecord(psave: p_uddsave; tag: ULong;
            size: ULong; data: Pointer): Integer; cdecl; external OLLYDBG name 'Pluginpackedrecord';
procedure Pluginmodulechanged(addr: ULong); cdecl; external OLLYDBG name 'Pluginmodulechanged';
function  Plugingetuniquedatatype: Integer; cdecl; external OLLYDBG name 'Plugingetuniquedatatype';
function  Plugintempbreakpoint(addr: ULong; bptype: ULong; forceint3: Integer): Integer; cdecl; external OLLYDBG name 'Plugintempbreakpoint';
procedure Pluginshowoptions(options: p_control); cdecl; external OLLYDBG name 'Pluginshowoptions';


////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// LEXICAL SCANNER ////////////////////////////////

const
  SMODE_UPCASE   = $00000001;               // Convert keywords to uppercase
  SMODE_NOEOL    = $00000010;               // Don't report SCAN_EOL, just skip it
  SMODE_NOSPEC   = $00000020;               // Don't translate specsymbols
  SMODE_EXTKEY   = $00000040;               // Allow &# and .!?%~ inside keywords
  SMODE_NOUSKEY  = $00000080;               // Underscore (_) is not part of keyword
  SMODE_NODEC    = $00000100;               // nn. is not decimal, but nn and '.'
  SMODE_NOFLOAT  = $00000200;               // nn.mm is not float, but nn, '.', mm
  SMODE_RADIX10  = $00000400;               // Default base is 10, not 16
  SMODE_ANGLES   = $00000800;               // Use angular brackets (<>) for text
  SMODE_MASK     = $00001000;               // Allow masked nibbles in SCAN_INT

  SCAN_EOF       = 0;                       // End of data
  SCAN_EOL       = 1;                       // End of line
  SCAN_KEY       = 2;                       // Keyword in text
  SCAN_TEXT      = 3;                       // Text string (without quotes) in text
  SCAN_INT       = 4;                       // Integer in ival or uval
  SCAN_FLOAT     = 5;                       // Floating-point number in fval
  SCAN_OP        = 6;                       // Operator or punctuator in ival
  SCAN_INVALID   = 7;                       // Invalid character in ival
  SCAN_SYNTAX    = 8;                       // Syntactical error in errmsg
  SCAN_USER      = 10;                      // Base for user-defined types

type
  t_scan_union = record
    case BYTE of
      0: (ival: Integer);                   // Scanned item as integer number
      1: (uval: ULong);                     // Scanned item as unsigned number
  end;

  p_scan = ^t_scan;
  t_scan = packed record                    // Scan descriptor
    // Fill these fields before the first scan. Set line to 1 for 1-based numbers.
    mode: ULong;                            // Scanning mode, set of SMODE_xxx
    src: PWChar;                            // Pointer to UNICODE source data
    length: ULong;                          // Length of source data, characters
    caret: ULong;                           // Next processed symbol, characters
    line: Integer;                          // Number of encountered EOLs
    // Call to Scan() fills some of these fields with scan data.
    scanType: t_scan_union;
    mask: ULong;                            // Binary mask for uval, SCAN_INT only
    fval: Extended;                         // Scanned item as floating number
    text: array[0..TEXTLEN-1] of WChar;     // Scanned item as a text string
    ntext: Integer;                         // Length of text, characters
    errmsg: array[0..TEXTLEN-1] of WChar;   // Error message
    _type: Integer;                         // type of last scanned item, SCAN_xxx
  end;

function  Skipspaces(ps: p_scan): Integer; cdecl; external OLLYDBG name 'Skipspaces';
procedure Scan(ps: p_scan); cdecl; external OLLYDBG name 'Scan';
function  Optostring(s: PWChar; op: Integer): Integer; cdecl; external OLLYDBG name 'Optostring';


////////////////////////////////////////////////////////////////////////////////
///////////////////////// SHORTCUTS, MENUS AND TOOLBAR /////////////////////////

const
  // Input modes of menu functions.
  MENU_VERIFY    = 0;                       // Check if menu item applies
  MENU_EXECUTE   = 1;                       // Execute menu item
  // Values returned by menu functions on MENU_VERIFY.
  MENU_ABSENT    = 0;                       // Item doesn't appear in menu
  MENU_NORMAL    = 1;                       // Ordinary menu item
  MENU_CHECKED   = 2;                       // Checked menu item
  MENU_CHKPARENT = 3;                       // Checked menu item + checked parent
  MENU_GRAYED    = 4;                       // Inactive menu item
  MENU_SHORTCUT  = 5;                       // Shortcut only, not in menu
  // Values returned by menu functions on MENU_EXECUTE.
  MENU_NOREDRAW  = 0;                       // Do not redraw owning window
  MENU_REDRAW    = 1;                       // Redraw owning window

  // Shortcut descriptions.
  KK_KEYMASK     = $0000FFFF;               // Mask to extract key
  KK_CHAR        = $00010000;               // Process as WM_CHAR
  KK_SHIFT       = $00020000;               // Shortcut includes Shift key
  KK_CTRL        = $00040000;               // Shortcut includes Ctrl key
  KK_ALT         = $00080000;               // Shortcut includes Alt key
  KK_WIN         = $00100000;               // Shortcut includes WIN key
  KK_NOSH        = $00200000;               // Shortcut ignores Shift in main menu
  KK_UNUSED      = $7FC00000;               // Unused shortcut data bits
  KK_DIRECT      = $80000000;               // Direct shortcut in menu

  // Global shortcuts. They may be re-used by plugins.
  K_NONE         = 0;                       // No shortcut
  // Global shortcuts: File functions.
  K_OPENNEW      = 100;                     // Open new executable to debug
  K_SETARGS      = 101;                     // Set command line args for next run
  K_ATTACH       = 102;                     // Attach to the running process
  K_DETACH       = 103;                     // Detach from the debugged process
  K_EXIT         = 104;                     // Close OllyDbg
  // Global shortcuts: View functions.
  K_LOGWINDOW    = 110;                     // Open Log window
  K_MODULES      = 111;                     // Open Executable modules window
  K_MEMORY       = 112;                     // Open Memory map window
  K_WINDOWS      = 113;                     // Open list of windows
  K_THREADS      = 114;                     // Open Threads window
  K_CPU          = 115;                     // Open CPU window
  K_WATCHES      = 116;                     // Open Watches window
  K_SEARCHES     = 117;                     // Open Search results window
  K_RTRACE       = 118;                     // Open Run trace window
  K_PATCHES      = 119;                     // Open Patches window
  K_BPOINTS      = 120;                     // Open INT3 breakpoints window
  K_BPMEM        = 121;                     // Open Memory breakpoints window
  K_BPHARD       = 122;                     // Open Hardware breakpoints window
  K_SOURCES      = 123;                     // Open list of source files
  K_FILE         = 124;                     // Open file
  // Global shortcuts: Debug functions.
  K_RUN          = 130;                     // Run debugged application
  K_RUNTHREAD    = 131;                     // Run only actual thread
  K_PAUSE        = 132;                     // Pause debugged application
  K_STEPIN       = 133;                     // Step into
  K_STEPOVER     = 134;                     // Step over
  K_TILLRET      = 135;                     // Execute till return
  K_TILLUSER     = 136;                     // Execute till user code
  K_CALLDLL      = 137;                     // Call DLL export
  K_RESTART      = 138;                     // Restart last debugged executable
  K_CLOSE        = 139;                     // Close debuggee
  K_AFFINITY     = 140;                     // Set affinity
  // Global shortcuts: Trace functions.
  K_OPENTRACE    = 150;                     // Open Run trace
  K_CLOSETRACE   = 151;                     // Close Run trace
  K_ANIMIN       = 152;                     // Animate into
  K_ANIMOVER     = 153;                     // Animate over
  K_TRACEIN      = 154;                     // Trace into
  K_TRACEOVER    = 155;                     // Trace over
  K_RUNHIT       = 156;                     // Run hit trace
  K_STOPHIT      = 157;                     // Stop hit trace
  K_RTCOND       = 158;                     // Set run trace break condition
  K_RTLOG        = 159;                     // Set run trace log condition
  // Global shortcuts: Options.
  K_OPTIONS      = 170;                     // Open Options dialog
  K_PLUGOPTIONS  = 171;                     // Open Plugin options dialog
  K_SHORTCUTS    = 172;                     // Open Shortcut editor
  // Global shortcuts: Windows functions.
  K_TOPMOST      = 180;                     // Toggle topmost status of main window
  K_CASCADE      = 181;                     // Cascade MDI windows
  K_TILEHOR      = 182;                     // Tile MDI windows horizontally
  K_TILEVER      = 183;                     // Tile MDI windows vertically
  K_ICONS        = 184;                     // Arrange icons
  K_CLOSEMDI     = 185;                     // Close all MDI windows
  K_RESTORE      = 186;                     // Maximize or restore active MDI window
  K_PREVMDI      = 187;                     // Go to previous MDI window
  K_NEXTMDI      = 188;                     // Go to next MDI window
  // Global shortcuts: Help functions.
  K_ABOUT        = 190;                     // Open About dialog
  // Generic table shortcuts.
  K_PREVFRAME    = 200;                     // Go to previous frame in table
  K_NEXTFRAME    = 201;                     // Go to next frame in table
  K_UPDATE       = 202;                     // Update table
  K_COPY         = 203;                     // Copy to clipboard
  K_COPYALL      = 204;                     // Copy whole table to clipboard
  K_CUT          = 205;                     // Cut to clipboard
  K_PASTE        = 206;                     // Paste
  K_TOPMOSTMDI   = 207;                     // Make MDI window topmost
  K_AUTOUPDATE   = 208;                     // Periodically update contents of window
  K_SHOWBAR      = 209;                     // Show/hide bar
  K_HSCROLL      = 210;                     // Show/hide horizontal scroll
  K_DEFCOLUMNS   = 211;                     // Resize all columns to default width
  // Shortcuts used by different windows.
  K_SEARCHAGAIN  = 220;                     // Repeat last search
  K_SEARCHREV    = 221;                     // Repeat search in inverse direction
  // Dump: Data backup.
  K_BACKUP       = 240;                     // Create or update backup
  K_SHOWBKUP     = 241;                     // Toggle backup display
  // Dump: Edit.
  K_UNDO         = 250;                     // Undo selection
  K_COPYADDR     = 251;                     // Copy address
  K_COPYHEX      = 252;                     // Copy data in hexadecimal format
  K_PASTEHEX     = 253;                     // Paste data in hexadecimal format
  K_EDITITEM     = 254;                     // Edit first selected item
  K_EDIT         = 255;                     // Edit selection
  K_FILLZERO     = 256;                     // Fill selection with zeros
  K_FILLNOP      = 257;                     // Fill selection with NOPs
  K_FILLFF       = 258;                     // Fill selection with FF code
  K_SELECTALL    = 259;                     // Select all
  K_SELECTPROC   = 260;                     // Select procedure or structure
  K_COPYTOEXE    = 261;                     // Copy selection to executable file
  K_ZERODUMP     = 262;                     // Zero whole dump
  K_LABEL        = 263;                     // Add custom label
  K_ASSEMBLE     = 264;                     // Assemble
  K_COMMENT      = 265;                     // Add custom comment
  K_SAVEFILE     = 266;                     // Save file
  // Dump: Breakpoints.
  K_BREAK        = 280;                     // Toggle simple INT3 breakpoint
  K_CONDBREAK    = 281;                     // Set or edit cond INT3 breakpoint
  K_LOGBREAK     = 282;                     // Set or edit logging INT3 breakpoint
  K_RUNTOSEL     = 283;                     // Run to selection
  K_ENABLEBRK    = 284;                     // Enable or disable INT3 breakpoint
  K_MEMBREAK     = 285;                     // Set or edit memory breakpoint
  K_MEMLOGBREAK  = 286;                     // Set or edit memory log breakpoint
  K_MEMENABLE    = 287;                     // Enable or disable memory breakpoint
  K_MEMDEL       = 288;                     // Delete memory breakpoint
  K_HWBREAK      = 289;                     // Set or edit hardware breakpoint
  K_HWLOGBREAK   = 290;                     // Set or edit hardware log breakpoint
  K_HWENABLE     = 291;                     // Enable or disable hardware breakpoint
  K_HWDEL        = 292;                     // Delete hardware breakpoint
  // Dump: Jumps to location.
  K_NEWORIGIN    = 300;                     // Set new origin
  K_FOLLOWDASM   = 301;                     // Follow address in Disassembler
  K_ORIGIN       = 302;                     // Go to origin
  K_GOTO         = 303;                     // Go to expression
  K_JMPTOSEL     = 304;                     // Follow jump or call to selection
  K_SWITCHCASE   = 305;                     // Go to switch case
  K_PREVHIST     = 306;                     // Go to previous history location
  K_NEXTHIST     = 307;                     // Go to next history location
  K_PREVTRACE    = 308;                     // Go to previous run trace record
  K_NEXTTRACE    = 309;                     // Go to next run trace record
  K_PREVPROC     = 310;                     // Go to previous procedure
  K_NEXTPROC     = 311;                     // Go to next procedure
  K_PREVREF      = 312;                     // Go to previous found item
  K_NEXTREF      = 313;                     // Go to next found item
  K_FOLLOWEXE    = 314;                     // Follow selection in executable file
  // Dump: Structures.
  K_DECODESTR    = 330;                     // Decode as structure
  K_DECODESPTR   = 331;                     // Decode as pointer to structure
  // Dump: Search.
  K_NAMES        = 380;                     // Show list of names
  K_FINDCMD      = 381;                     // Find command
  K_FINDCMDSEQ   = 382;                     // Find sequence of commands
  K_FINDCONST    = 383;                     // Find constant
  K_FINDBIN      = 384;                     // Find binary string
  K_FINDMOD      = 385;                     // Find modification
  K_ALLCALLS     = 386;                     // Search for all intermodular calls
  K_ALLCMDS      = 387;                     // Search for all commands
  K_ALLCMDSEQ    = 388;                     // Search for all command sequences
  K_ALLCONST     = 389;                     // Search for all constants
  K_ALLMODS      = 390;                     // Search for all modifications
  K_ALLSTRS      = 391;                     // Search for all referenced strings
  K_ALLGUIDS     = 392;                     // Search for all referenced GUIDs
  K_ALLCOMMENTS  = 393;                     // Search for all user-defined comments
  K_ALLSWITCHES  = 394;                     // Search for all switches
  K_ALLFLOATS    = 395;                     // Search for all floating constants
  K_LASTRTREC    = 396;                     // Find last record in run trace
  // Dump: References.
  K_REFERENCES   = 410;                     // Find all references
  // Dump: Addressing.
  K_ABSADDR      = 420;                     // Show absolute addresses
  K_RELADDR      = 421;                     // Show offsets from current selection
  K_BASEADDR     = 422;                     // Show offsets relative to module base
  // Dump: Comments.
  K_COMMSRC      = 430;                     // Toggle between comments and source
  K_SHOWPROF     = 431;                     // Show or hide run trace profile
  // Dump: Analysis.
  K_ANALYSE      = 440;                     // Analyse module
  K_REMANAL      = 441;                     // Remove analysis from selection
  K_REMANMOD     = 442;                     // Remove analysis from the module
  // Dump: Help.
  K_HELPCMD      = 450;                     // Help on command
  K_HELPAPI      = 451;                     // Help on Windows API function
  // Dump: Data presentation.
  K_DUMPHA16     = 460;                     // Dump as 16 hex bytes and ASCII text
  K_DUMPHA8      = 461;                     // Dump as 8 hex bytes and ASCII text
  K_DUMPHU16     = 462;                     // Dump as 16 hex bytes and UNICODE text
  K_DUMPHU8      = 463;                     // Dump as 8 hex bytes and UNICODE text
  K_DUMPA64      = 464;                     // Dump as 64 ASCII characters
  K_DUMPA32      = 465;                     // Dump as 32 ASCII characters
  K_DUMPU64      = 466;                     // Dump as 64 UNICODE characters
  K_DUMPU32      = 467;                     // Dump as 32 UNICODE characters
  K_DUMPU16      = 468;                     // Dump as 16 UNICODE characters
  K_DUMPISHORT   = 469;                     // Dump as 16-bit signed numbers
  K_DUMPUSHORT   = 470;                     // Dump as 16-bit unsigned numbers
  K_DUMPXSHORT   = 471;                     // Dump as 16-bit hexadecimal numbers
  K_DUMPILONG    = 472;                     // Dump as 32-bit signed numbers
  K_DUMPULONG    = 473;                     // Dump as 32-bit unsigned numbers
  K_DUMPXLONG    = 474;                     // Dump as 32-bit hexadecimal numbers
  K_DUMPADR      = 475;                     // Dump as address with comments
  K_DUMPADRA     = 476;                     // Dump as address with ASCII & comments
  K_DUMPADRU     = 477;                     // Dump as address with UNICODE & comms
  K_DUMPF32      = 478;                     // Dump as 32-bit floats
  K_DUMPF64      = 479;                     // Dump as 64-bit floats
  K_DUMPF80      = 480;                     // Dump as 80-bit floats
  K_DUMPDA       = 481;                     // Dump as disassembly
  K_DUMPSTRUCT   = 482;                     // Dump as known structure
  // Stack-specific shortcuts.
  K_LOCKSTK      = 490;                     // Toggle stack lock
  K_PUSH         = 491;                     // Push doubleword
  K_POP          = 492;                     // Pop doubleword
  K_STACKINDASM  = 493;                     // Follow stack doubleword in CPU
  K_GOTOESP      = 494;                     // Go to ESP
  K_GOTOEBP      = 495;                     // Go to EBP
  K_ESPADDR      = 496;                     // Show offsets relative to ESP
  K_EBPADDR      = 497;                     // Show offsets relative to EBP
  // Shortcuts of Register pane.
  K_INCREMENT    = 500;                     // Increment register
  K_DECREMENT    = 501;                     // Decrement register
  K_ZERO         = 502;                     // Zero selected register
  K_SET1         = 503;                     // Set register to 1
  K_MODIFY       = 504;                     // Modify contents of register
  K_UNDOREG      = 505;
  K_PUSHFPU      = 506;                     // Push FPU stack
  K_POPFPU       = 507;                     // Pop FPU stack
  K_REGINDASM    = 508;                     // Follow register in CPU Disassembler
  K_REGINDUMP    = 509;                     // Follow register in CPU Dump
  K_REGINSTACK   = 510;                     // Follow register in CPU Stack
  K_VIEWFPU      = 511;                     // View FPU registers
  K_VIEWMMX      = 512;                     // View MMX registers
  K_VIEW3DNOW    = 513;                     // View 3DNow! registers
  K_HELPREG      = 514;                     // Help on register
  // Shortcuts of Information pane.
  K_EDITOP       = 520;                     // Edit contents of operand in info pane
  K_INFOINDASM   = 521;                     // Follow information in CPU Disassembler
  K_INFOINDUMP   = 522;                     // Follow information in CPU Dump
  K_INFOINSTACK  = 523;                     // Follow information in CPU Stack
  K_LISTJUMPS    = 524;                     // List jumps and calls to command
  K_LISTCASES    = 525;                     // List switch cases
  K_INFOSRC      = 526;                     // Follow address in Source code
  // Log window.
  K_LOGINDASM    = 530;                     // Follow log address in CPU Disassembler
  K_LOGINDUMP    = 531;                     // Follow log address in CPU Dump
  K_LOGINSTACK   = 532;                     // Follow log address in CPU Stack
  K_LOGCLEAR     = 533;                     // Clear log
  K_LOGTOFILE    = 534;                     // Start logging to file
  K_STOPLOG      = 535;                     // Stop logging to file
  // Executable modules.
  K_MODINDASM    = 540;                     // Follow module entry point in CPU
  K_MODDATA      = 541;                     // View module data section in CPU Dump
  K_MODEXE       = 542;                     // Open executable in standalone Dump
  K_MODNAMES     = 543;                     // Show names declared in the module
  K_GLOBNAMES    = 544;                     // Show global list of names
  K_MODCALLS     = 545;                     // Find intermodular calls in module
  K_MODANALYSE   = 546;                     // Analyse selected module
  K_SAVEUDD      = 547;                     // Save module data to .udd file
  K_LOADUDD      = 548;                     // Load module data from .udd file
  // Memory map.
  K_MEMBACKUP    = 550;                     // Create backup of memory block
  K_MEMINDASM    = 551;                     // Open memory block in CPU Disassembler
  K_MEMINDUMP    = 552;                     // Open memory block in CPU Dump
  K_DUMP         = 553;                     // Dump memory block in separate window
  K_SEARCHMEM    = 554;                     // Search memory block for binary string
  K_MEMBPACCESS  = 555;                     // Toggle break on access
  // List of windows.
  K_WININDASM    = 560;                     // Follow WinProc in CPU Disassembler
  K_CLSINDASM    = 561;                     // Follow ClassProc in CPU Disassembler
  // Threads.
  K_THRINCPU     = 570;                     // Open thread in CPU window
  K_THRTIB       = 571;                     // Dump Thread Information Block
  K_REGISTERS    = 572;                     // Open Registers window
  K_THRSUSPEND   = 573;                     // Suspend selected thread
  K_THRRESUME    = 574;                     // Resume selected thread
  K_THRKILL      = 575;                     // Kill selected thread
  // Watches.
  K_ADDWATCH     = 580;                     // Add watch
  K_EDITWATCH    = 581;                     // Edit existing watch
  K_DELWATCH     = 582;                     // Delete watch
  K_WATCHUP      = 583;                     // Move watch up
  K_WATCHDN      = 584;                     // Move watch down
  K_EDITCONT     = 585;                     // Edit contents of register or memory
  K_WATCHINDASM  = 586;                     // Follow watch value in CPU Disassembler
  K_WATCHINDUMP  = 587;                     // Follow watch value in CPU Dump
  K_WATCHINSTACK = 588;                     // Follow watch value in CPU Stack
  // Search results.
  K_SEARCHINDASM = 600;                     // Follow address of found item in CPU
  K_PREVSEARCH   = 601;                     // Follow previous found item in Disasm
  K_NEXTSEARCH   = 602;                     // Follow next found item in Disasm
  K_FINDTEXT     = 603;                     // Find text substring in search results
  K_BREAKALL     = 604;                     // Set breakpoint on all found commands
  K_CONDBPALL    = 605;                     // Set conditional bp on all commands
  K_LOGBPALL     = 606;                     // Set logging bp on all commands
  K_DELBPALL     = 607;                     // Remove breakpoints from all commands
  K_BREAKCALLS   = 608;                     // Set break on calls to function
  K_CONDBPCALLS  = 609;                     // Set cond break on calls to function
  K_LOGBPCALLS   = 610;                     // Set logging break on calls to function
  K_DELBPCALLS   = 611;                     // Remove breakpoints from calls
  // Run trace.
  K_RTPREV       = 620;                     // Show previous run trace in Disasm
  K_RTNEXT       = 621;                     // Show next run trace in Disasm
  K_TRACEINDASM  = 622;                     // Follow traced command in CPU
  K_CLRTRACE     = 623;                     // Clear run trace
  K_REGMODE      = 624;                     // Toggle register display mode
  K_MARKTRACE    = 625;                     // Mark address in run trace
  K_FINDTRADDR   = 626;                     // Enter address to mark in run trace
  K_PREVMARK     = 627;                     // Find previous marked address
  K_NEXTMARK     = 628;                     // Find next marked address
  K_CLEARMARK    = 629;                     // Clear address marks in run trace
  K_PROFILE      = 630;                     // Profile selected module
  K_GLOBPROFILE  = 631;                     // Profile whole memory
  K_SAVETRACE    = 632;                     // Save run trace data to the file
  K_STOPSAVETR   = 633;                     // Close run trace log file
  // Profile.
  K_PROFINDASM   = 640;                     // Follow profiled command in CPU
  K_PREVPROF     = 641;                     // Follow previous profile item in Disasm
  K_NEXTPROF     = 642;                     // Follow next profile item in Disasm
  K_PROFMARK     = 643;                     // Mark profile address in run trace
  // Patches.
  K_PATCHINDASM  = 650;                     // Follow patch in CPU Disassembler
  K_PREVPATCH    = 651;                     // Go to previous patch
  K_NEXTPATCH    = 652;                     // Go to next patch
  K_APPLYPATCH   = 653;                     // Apply patch
  K_RESTOREPT    = 654;                     // Restore original code
  K_DELPATCH     = 655;                     // Delete patch record
  // Breakpoint lists.
  K_DELETEBP     = 660;                     // Delete breakpoint
  K_ENABLEBP     = 661;                     // Enable or disable breakpoint
  K_BPINDASM     = 662;                     // Follow breakpoint in CPU Disassembler
  K_BPINDUMP     = 663;                     // Follow breakpoint in CPU Dump
  K_DISABLEALLBP = 664;                     // Disable all breakpoints
  K_ENABLEALLBP  = 665;                     // Enable all breakpoints
  // Source.
  K_SOURCEINDASM = 670;                     // Follow source line in CPU Disassembler
  // List of source files.
  K_VIEWSRC      = 680;                     // View source file
  // Names.
  K_FOLLOWIMP    = 690;                     // Follow import in CPU Disassembler
  K_NAMEINDASM   = 691;                     // Follow label in CPU Disassembler
  K_NAMEINDUMP   = 692;                     // Follow label in CPU Dump
  K_NAMEREFS     = 693;                     // Find references to name
  K_NAMEHELPAPI  = 694;                     // Help on selected API function
  // Special non-changeable shortcuts.
  K_0            = 1008;                    // Digit 0
  K_1            = 1009;                    // Digit 1
  K_2            = 1010;                    // Digit 2
  K_3            = 1011;                    // Digit 3
  K_4            = 1012;                    // Digit 4
  K_5            = 1013;                    // Digit 5
  K_6            = 1014;                    // Digit 6
  K_7            = 1015;                    // Digit 7
  K_8            = 1016;                    // Digit 8
  K_9            = 1017;                    // Digit 9
  K_A            = 1018;                    // Hex digit A
  K_B            = 1019;                    // Hex digit B
  K_C            = 1020;                    // Hex digit C
  K_D            = 1021;                    // Hex digit D
  K_E            = 1022;                    // Hex digit E
  K_F            = 1023;                    // Hex digit F

  // Native OllyDbg tables that support emplugin menus:
  PWM_ATTACH: PWChar    = 'ATTACH';         // List of processes in Attach window
  PWM_BPHARD: PWChar    = 'BPHARD';         // Hardware breakpoints
  PWM_BPMEM: PWChar     = 'BPMEM';          // Memory breakpoints
  PWM_BPOINT: PWChar    = 'BPOINT';         // INT3 breakpoints
  PWM_DISASM: PWChar    = 'DISASM';         // CPU Disassembler pane
  PWM_DUMP: PWChar      = 'DUMP';           // All dumps except CPU disasm & stack
  PWM_INFO: PWChar      = 'INFO';           // CPU Info pane
  PWM_LOG: PWChar       = 'LOG';            // Log window
  PWM_MAIN: PWChar      = 'MAIN';           // Main OllyDbg menu
  PWM_MEMORY: PWChar    = 'MEMORY';         // Memory window
  PWM_MODULES: PWChar   = 'MODULES';        // Modules window
  PWM_NAMELIST: PWChar  = 'NAMELIST';       // List of names (labels)
  PWM_PATCHES: PWChar   = 'PATCHES';        // List of patches
  PWM_PROFILE: PWChar   = 'PROFILE';        // Profile window
  PWM_REGISTERS: PWChar = 'REGISTERS';      // Registers, including CPU
  PWM_SEARCH: PWChar    = 'SEARCH';         // Search tabs
  PWM_SOURCE: PWChar    = 'SOURCE';         // Source code window
  PWM_SRCLIST: PWChar   = 'SRCLIST';        // List of source files
  PWM_STACK: PWChar     = 'STACK';          // CPU Stack pane
  PWM_THREADS: PWChar   = 'THREADS';        // Threads window
  PWM_TRACE: PWChar     = 'TRACE';          // Run trace window
  PWM_WATCH: PWChar     = 'WATCH';          // Watches
  PWM_WINDOWS: PWChar   = 'WINDOWS';        // List of windows


////////////////////////////////////////////////////////////////////////////////
///////////////////////////// MAIN OLLYDBG WINDOW //////////////////////////////

type
  t_status = (                              // Thread/process status
    STAT_IDLE,                              // No process to debug
    STAT_LOADING,                           // Loading new process
    STAT_ATTACHING,                         // Attaching to the running process
    STAT_RUNNING,                           // All threads are running
    STAT_RUNTHR,                            // Single thread is running
    STAT_STEPIN,                            // Stepping into, single thread
    STAT_STEPOVER,                          // Stepping over, single thread
    STAT_ANIMIN,                            // Animating into, single thread
    STAT_ANIMOVER,                          // Animating over, single thread
    STAT_TRACEIN,                           // Tracing into, single thread
    STAT_TRACEOVER,                         // Tracing over, single thread
    STAT_SFXRUN,                            // SFX using run trace, single thread
    STAT_SFXHIT,                            // SFX using hit trace, single thread
    STAT_SFXKNOWN,                          // SFX to known entry, single thread
    STAT_TILLRET,                           // Stepping until return, single thread
    STAT_OVERRET,                           // Stepping over return, single thread
    STAT_TILLUSER,                          // Stepping till user code, single thread
    STAT_PAUSING,                           // Process is requested to pause
    STAT_PAUSED,                            // Process paused on debugging event
    STAT_FINISHED,                          // Process is terminated but in memory
    STAT_CLOSING                            // Process is requested to close/detach
    );

procedure Info(format: PWChar); cdecl; varargs; external OLLYDBG name 'Info';
procedure Message(addr: ULong; format: PWChar); cdecl; varargs; external OLLYDBG name 'Message';
procedure Tempinfo(format: PWChar); cdecl; varargs; external OLLYDBG name 'Tempinfo';
procedure Flash(format: PWChar); cdecl; varargs; external OLLYDBG name 'Flash';
procedure Progress(promille: Integer; format: PWChar); cdecl; varargs; external OLLYDBG name 'Progress';
procedure Moveprogress(promille: Integer); cdecl; external OLLYDBG name 'Moveprogress';
procedure Setstatus(newstatus: t_status); cdecl; external OLLYDBG name 'Setstatus';


////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// DATA FUNCTIONS ////////////////////////////////

// Name and data types. Do not change order, it's important! Always keep values
// of demangled names 1 higher than originals, and NM_ALIAS higher than
// NM_EXPORT - name search routines rely on these facts!

const
  NM_NONAME      = $00;                     // Means that name is absent
  DT_NONE        = $00;                     // Ditto
  NM_LABEL       = $21;                     // User-defined label
  NM_EXPORT      = $22;                     // Exported name
  NM_DEEXP       = NM_EXPORT + 1;           // Demangled exported name
  DT_EORD        = NM_EXPORT + 2;           // Exported ordinal (ULong)
  NM_ALIAS       = NM_EXPORT + 3;           // Alias of NM_EXPORT
  NM_IMPORT      = $26;                     // Imported name (module.function)
  NM_DEIMP       = NM_IMPORT + 1;           // Demangled imported name
  DT_IORD        = NM_IMPORT + 2;           // Imported ordinal (struct dt_iord)
  NM_DEBUG       = $29;                     // Name from debug data
  NM_DEDEBUG     = NM_DEBUG + 1;            // Demangled name from debug data
  NM_ANLABEL     = $2B;                     // Name added by Analyser
  NM_COMMENT     = $30;                     // User-defined comment
  NM_ANALYSE     = $31;                     // Comment added by Analyser
  NM_MARK        = $32;                     // Important parameter
  NM_CALLED      = $33;                     // Name of called function
  DT_ARG         = $34;                     // Name and type of argument or data
  DT_NARG        = $35;                     // Guessed number of arguments at CALL
  NM_RETTYPE     = $36;                     // type of data returned in EAX
  NM_MODCOMM     = $37;                     // Automatical module comments
  NM_TRICK       = $38;                     // Parentheses of tricky sequences
  DT_SWITCH      = $40;                     // Switch descriptor (struct dt_switch)
  DT_CASE        = $41;                     // Case descriptor (struct dt_case)
  DT_MNEMO       = $42;                     // Alternative mnemonics data (dt_mnemo)
  NM_DLLPARMS    = $44;                     // Parameters of Call DLL dialog
  DT_DLLDATA     = $45;                     // Parameters of Call DLL dialog

  DT_DBGPROC     = $4A;                     // t_function from debug, don't save!

  NM_INT3BASE    = $51;                     // Base for INT3 breakpoint names
    NM_INT3COND  = NM_INT3BASE + 0;         // INT3 breakpoint condition
    NM_INT3EXPR  = NM_INT3BASE + 1;         // Expression to log at INT3 breakpoint
    NM_INT3TYPE  = NM_INT3BASE + 2;         // type used to decode expression
  NM_MEMBASE     = $54;                     // Base for memory breakpoint names
    NM_MEMCOND   = NM_MEMBASE + 0;          // Memory breakpoint condition
    NM_MEMEXPR   = NM_MEMBASE + 1;          // Expression to log at memory break
    NM_MEMTYPE   = NM_MEMBASE + 2;          // type used to decode expression
  NM_HARDBASE    = $57;                     // Base for hardware breakpoint names
    NM_HARDCOND  = NM_HARDBASE + 0;         // Hardware breakpoint condition
    NM_HARDEXPR  = NM_HARDBASE + 1;         // Expression to log at hardware break
    NM_HARDTYPE  = NM_HARDBASE + 2;         // type used to decode expression

  NM_LABELSAV    = $60;                     // NSTRINGS last user-defined labels
  NM_ASMSAV      = $61;                     // NSTRINGS last assembled commands
  NM_ASRCHSAV    = $62;                     // NSTRINGS last assemby searches
  NM_COMMSAV     = $63;                     // NSTRINGS last user-defined comments
  NM_WATCHSAV    = $64;                     // NSTRINGS last watch expressions
  NM_GOTOSAV     = $65;                     // NSTRINGS last GOTO expressions
  DT_BINSAV      = $66;                     // NSTRINGS last binary search patterns
  NM_CONSTSAV    = $67;                     // NSTRINGS last constants to search
  NM_STRSAV      = $68;                     // NSTRINGS last strings to search
  NM_ARGSAV      = $69;                     // NSTRINGS last arguments (ARGLEN!)
  NM_CURRSAV     = $6A;                     // NSTRINGS last current dirs (MAXPATH!)

  NM_SEQSAV      = $6F;                     // NSTRINGS last sequences (DATALEN!)

  NM_RTCOND1     = $70;                     // First run trace pause condition
  NM_RTCOND2     = $71;                     // Second run trace pause condition
  NM_RTCOND3     = $72;                     // Third run trace pause condition
  NM_RTCOND4     = $73;                     // Fourth run trace pause condition
  NM_RTCMD1      = $74;                     // First run trace match command
  NM_RTCMD2      = $75;                     // Second run trace match command
  NM_RANGE0      = $76;                     // Low range limit
  NM_RANGE1      = $77;                     // High range limit

  DT_ANYDATA     = $FF;                     // Special marker, not a real data

  NMOFS_COND     = 0;                       // Offset to breakpoint condition
  NMOFS_EXPR     = 1;                       // Offset to breakpoint log expression
  NMOFS_TYPE     = 2;                       // Offset to expression decoding type

  NSWEXIT        = 256;                     // Max no. of switch exits, incl. default
  NSWCASE        = 128;                     // Max no. of cases in exit

  // Types of switches and switch exits.
  CASE_CASCADED  = $00000001;               // Cascaded IF
  CASE_HUGE      = $00000002;               // Huge switch, some cases are lost
  CASE_DEFAULT   = $00000004;               // Has default (is default for dt_case)
  CASE_TYPEMASK  = $00000070;               // Mask to extract case type
   CASE_ASCII    = $00000010;               // Intreprete cases as ASCII characters
    CASE_MSG     = $00000020;               // Interprete cases as WM_xxx
    CASE_EXCPTN  = $00000040;               // Interprete cases as exception codes
  CASE_SIGNED    = $00000080;               // Interprete cases as signed

  // Flags indicating alternative forms of assembler mnemonics.
  MF_JZ          = $01;                     // JZ, JNZ instead of JE, JNE
  MF_JC          = $02;                     // JC, JNC instead of JAE, JB

type
  p_dt_iord = ^t_dt_iord;                   // Descriptor of DT_IORD data
  t_dt_iord = packed record
    ord: ULong;                             // Ordinal
    modname: array[0..SHORTNAME-1] of WChar;// Short name of the module
  end;

  p_dt_switch = ^t_dt_switch;               // Switch descriptor DT_SWITCH
  t_dt_switch = packed record
    casemin: ULong;                         // Minimal case
    casemax: ULong;                         // Maximal case
    _type: ULong;                           // Switch type, set of CASE_xxx
    nexit: Integer;                         // Number of exits including default
    exitaddr: array[0..NSWEXIT-1] of ULong; // List of exits (point to dt_case)
  end;

  p_dt_case = ^t_dt_case;                   // Switch exit descriptor DT_CASE
  t_dt_case = packed record
    swbase: ULong;                          // Address of a switch descriptor
    _type: ULong;                           // Switch type, set of CASE_xxx
    ncase: Integer;                         // Number of cases (1..64, 0: default)
    value: array[0..NSWCASE-1] of ULong;    // List of cases for exit
  end;

  p_mnemo = ^t_mnemo;                       // Mnemonics decoding DT_MNEMO
  t_mnemo = packed record
    flags: UChar;                           // Set of MF_xxx
  end;

function  Insertdata(addr: ULong; itype: Integer; data: Pointer; datasize: ULong): Integer; cdecl; external OLLYDBG name 'Insertdata';
function  Finddata(addr: ULong; itype: Integer; data: Pointer; atasize: ULong): ULong; cdecl; external OLLYDBG name 'Finddata';
function  Finddataptr(addr: ULong; itype: Integer; datasize: PULong): Pointer; cdecl; external OLLYDBG name 'Finddataptr';
procedure Startnextdata(addr0: ULong; addr1: ULong; itype: Integer); cdecl; external OLLYDBG name 'Startnextdata';
function  Findnextdata(addr: PULong; data: Pointer; datasize: ULong): ULong; cdecl; external OLLYDBG name 'Findnextdata';
procedure Startnextdatalist(addr0: ULong; addr1: ULong; list: Integer; n: Integer); cdecl; external OLLYDBG name 'Startnextdatalist';
function  Findnextdatalist(addr: ULong; ptype: PInteger;
            data: Pointer; datasize: ULong): Integer; cdecl; external OLLYDBG name 'Findnextdatalist';
function  Isdataavailable(addr: ULong; type1: Integer; type2: Integer; type3: Integer): Integer; cdecl; external OLLYDBG name 'Isdataavailable';
function  Isdatainrange(addr0: ULong; addr1: ULong;
            type1: Integer; type2: Integer; type3: Integer): Integer; cdecl; external OLLYDBG name 'Isdatainrange';
procedure Deletedatarange(addr0: ULong; addr1: ULong;
            type1: Integer; type2: Integer; type3: Integer); cdecl; external OLLYDBG name 'Deletedatarange';
procedure Deletedatarangelist(addr0: ULong; addr1: ULong; list: PInteger; n: Integer); cdecl; external OLLYDBG name 'Deletedatarangelist';
function  Quickinsertdata(addr: ULong; itype: Integer;
            data: Pointer; datasize: ULong): Integer; cdecl; external OLLYDBG name 'Quickinsertdata';
procedure Mergequickdata; cdecl; external OLLYDBG name 'Mergequickdata';
function  DemanglenameW(name: PWChar; undecorated: PWChar; recurs: Integer): Integer; cdecl; external OLLYDBG name 'DemanglenameW';
function  InsertnameW(addr: ULong; itype: Integer; s: PWChar): Integer; cdecl; external OLLYDBG name 'InsertnameW';
function  QuickinsertnameW(addr: ULong; itype: Integer; s: PWChar): Integer; cdecl; external OLLYDBG name 'QuickinsertnameW';
function  FindnameW(addr: ULong; itype: Integer; name: PWChar; nname: Integer): Integer; cdecl; external OLLYDBG name 'FindnameW';
function  FindnextnameW(addr: ULong; name: PWChar; nname: Integer): Integer; cdecl; external OLLYDBG name 'FindnextnameW';
procedure Startnextnamelist(addr0: ULong; addr1: ULong; list: PInteger; n: Integer); cdecl; external OLLYDBG name 'Startnextnamelist';
function  FindnextnamelistW(addr: ULong; ptype: PInteger;
            name: PWChar; nname: Integer): Integer; cdecl; external OLLYDBG name 'FindnextnamelistW';
function  Findlabel(addr: ULong; name: PWChar; firsttype: Integer): Integer; cdecl; external OLLYDBG name 'Findlabel';


////////////////////////////////////////////////////////////////////////////////
///////////////////////////// SIMPLE DATA FUNCTIONS ////////////////////////////

type
  p_simple = ^t_simple;                     // Simple data container
  t_simple = packed record
    heap: PUChar;                           // Data heap
    itemsize: ULong;                        // Size of data element, bytes
    maxitem: Integer;                       // Size of allocated data heap, items
    nitem: Integer;                         // Actual number of data items
    sorted: Integer;                        // Whether data is sorted
  end;

procedure Destroysimpledata(pdat: p_simple); cdecl; external OLLYDBG name 'Destroysimpledata';
function  Createsimpledata(pdat: p_simple; itemsize: ULong): Integer; cdecl; external OLLYDBG name 'Createsimpledata';
function  Addsimpledata(pdat: p_simple; data: Pointer): Integer; cdecl; external OLLYDBG name 'Addsimpledata';
procedure Sortsimpledata(pdat: p_simple); cdecl; external OLLYDBG name 'Sortsimpledata';
function  Findsimpledata(pdat: p_simple; addr: ULong): Pointer; cdecl; external OLLYDBG name 'Findsimpledata';
function  Getsimpledataindexbyaddr(pdat: p_simple; addr: ULong): Integer; cdecl; external OLLYDBG name 'Getsimpledataindexbyaddr';
function  Getsimpledatabyindex(pdat: p_simple; index: Integer): Pointer; cdecl; external OLLYDBG name 'Getsimpledatabyindex';
procedure Deletesimpledatarange(pdat: p_simple; addr0: ULong; addr1: ULong); cdecl; external OLLYDBG name 'Deletesimpledatarange';

const
  // Bits that describe the state of predicted data, similar to PST_xxx.
  PRED_SHORTSP   = $8000;                   // Offset of ESP is 1 byte, .udd only
  PRED_SHORTBP   = $4000;                   // Offset of EBP is 1 byte, .udd only
  PRED_ESPRET    = $0400;                   // Offset of ESP backtraced from return
  PRED_ESPOK     = $0200;                   // Offset of ESP valid
  PRED_EBPOK     = $0100;                   // Offset of EBP valid
  PRED_REL       = $0080;                   // Result constant fixuped or relative
  PRED_RESMASK   = $003F;                   // Mask to extract description of result
    PRED_VALID   = $0020;                   // Result constant valid
    PRED_ADDR    = $0010;                   // Result is address
    PRED_ORIG    = $0008;                   // Result is based on original register
    PRED_OMASK   = $0007;                   // Mask to extract original register

  PRED_ESPKNOWN  = PRED_ESPRET or PRED_ESPOK;

type
  p_sd_pred = ^t_sd_pred;                   // Descriptor of predicted data
  t_sd_pred = packed record
    addr: ULong;                            // Address of predicted command
    mode: UShort;                           // Combination of PRED_xxx
    espconst: LongInt;                      // Offset of ESP to original ESP
    ebpconst: LongInt;                      // Offset of EBP to original ESP
    resconst: ULong;                        // Constant in result of execution
  end;


////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// SORTED DATA //////////////////////////////////
const
  SDM_INDEXED    = $00000001;               // Indexed sorted data
  SDM_EXTADDR    = $00000002;               // Address is extended by TY_AEXTMASK
  SDM_NOSIZE     = $00000004;               // Header without size and type
  SDM_NOEXTEND   = $00000008;               // Don't reallocate memory, fail instead

  // Address extension.
  TY_AEXTMASK    = $000000FF;               // Mask to extract address extension
  // General item types.
  TY_NEW         = $00000100;               // Item is new
  TY_CONFIRMED   = $00000200;               // Item still exists
  TY_EXTADDR     = $00000400;               // Address extension active
  TY_SELECTED    = $00000800;               // Reserved for multiple selection
  // Module-related item types (used in t_module and t_premod).
  MOD_MAIN       = $00010000;               // Main module
  MOD_SFX        = $00020000;               // Self-extractable file
    MOD_SFXDONE  = $00040000;               // SFX file extracted
  MOD_RUNDLL     = $00080000;               // DLL loaded by LOADDLL.EXE
  MOD_SYSTEMDLL  = $00100000;               // System DLL
  MOD_SUPERSYS   = $00200000;               // System DLL that uses special commands
  MOD_DBGDATA    = $00400000;               // Debugging data is available
  MOD_ANALYSED   = $00800000;               // Module is already analysed
  MOD_NODATA     = $01000000;               // Module data is not yet available
  MOD_HIDDEN     = $02000000;               // Module is loaded in stealth mode
  MOD_NETAPP     = $04000000;               // .NET application
  MOD_RESOLVED   = $40000000;               // All static imports are resolved
  // Memory-related item types (used in t_memory), see also t_memory.special.
  MEM_ANYMEM     = $0FFFF000;               // Mask for memory attributes
    MEM_CODE     = $00001000;               // Contains image of code section
    MEM_DATA     = $00002000;               // Contains image of data section
    MEM_SFX      = $00004000;               // Contains self-extractor
    MEM_IMPDATA  = $00008000;               // Contains import data
    MEM_EXPDATA  = $00010000;               // Contains export data
    MEM_RSRC     = $00020000;               // Contains resources
    MEM_RELOC    = $00040000;               // Contains relocation data
    MEM_STACK    = $00080000;               // Contains stack of some thread
    MEM_STKGUARD = $00100000;               // Guarding page of the stack
    MEM_THREAD   = $00200000;               // Contains data block of some thread
    MEM_HEADER   = $00400000;               // Contains COFF header
    MEM_DEFHEAP  = $00800000;               // Contains default heap
    MEM_HEAP     = $01000000;               // Contains non-default heap
    MEM_NATIVE   = $02000000;               // Contains JIT-compiled native code
    MEM_GAP      = $08000000;               // Free or reserved space
  MEM_SECTION    = $10000000;               // Section of the executable file
  MEM_GUARDED    = $40000000;               // NT only: guarded memory block
  MEM_TEMPGUARD  = $80000000;               // NT only: temporarily guarded block
  // Thread-related item types (used in t_thread).
  THR_MAIN       = $00010000;               // Main thread
  THR_NETDBG     = $00020000;               // .NET debug helper thread
  THR_ORGHANDLE  = $00100000;               // Original thread's handle, don't close
  // Window-related item types (used in t_window).
  WN_UNICODE     = $00010000;               // UNICODE window
  // Procedure-related item types (used in t_procdata).
  PD_CALLBACK    = $00001000;               // Used as a callback
  PD_RETSIZE     = $00010000;               // Return size valid
  PD_TAMPERRET   = $00020000;               // Tampers with the return address
  PD_NORETURN    = $00040000;               // Calls function without return
  PD_PURE        = $00080000;               // Doesn't modify memory & make calls
  PD_ESPALIGN    = $00100000;               // Aligns ESP on entry
  PD_ARGMASK     = $07E00000;               // Mask indicating valid narg
    PD_FIXARG    = $00200000;               // narg is fixed number of arguments
    PD_FORMATA   = $00400000;               // narg-1 is ASCII printf format
    PD_FORMATW   = $00800000;               // narg-1 is UNICODE printf format
    PD_SCANA     = $01000000;               // narg-1 is ASCII scanf format
    PD_SCANW     = $02000000;               // narg-1 is UNICODE scanf format
    PD_COUNT     = $04000000;               // narg-1 is count of following args
  PD_GUESSED     = $08000000;               // narg and type are guessed, not known
  PD_NGUESS      = $10000000;               // nguess valid
  PD_VARGUESS    = $20000000;               // nguess variable, set to minimum!= 0
  PD_NPUSH       = $40000000;               // npush valid
  PD_VARPUSH     = $80000000;               // npush valid, set to maximum
  // Argument prediction-related types (used in t_predict).
  PR_PUSHBP      = $00010000;               // PUSH EBP or ENTER executed
  PR_MOVBPSP     = $00020000;               // MOV EBP,ESP or ENTER executed
  PR_SETSEH      = $00040000;               // Structured exception handler set
  PR_RETISJMP    = $00100000;               // Return is (mis)used as a jump
  PR_DIFFRET     = $00200000;               // Return changed, destination unknown
  PR_JMPTORET    = $00400000;               // Jump to original return address
  PR_TAMPERRET   = $00800000;               // Retaddr on stack accessed or modified
  PR_BADESP      = $01000000;               // ESP of actual generation is invalid
  PR_RET         = $02000000;               // Return from subroutine
  PR_STEPINTO    = $10000000;               // Step into CALL command
  // Breakpoint-related types (used in t_bpoint, t_bpmem and t_bphard).
  BP_BASE        = $0000F000;               // Mask to extract basic breakpoint type
    BP_MANUAL    = $00001000;               // Permanent breakpoint
    BP_ONESHOT   = $00002000;               // Stop and reset this bit
    BP_TEMP      = $00004000;               // Reset this bit and continue
    BP_TRACE     = $00008000;               // Used for hit trace
  BP_SET         = $00010000;               // Code INT3 is in memory, cmd is valid
  BP_DISABLED    = $00020000;               // Permanent breakpoint is disabled
  BP_COND        = $00040000;               // Conditional breakpoint
  BP_PERIODICAL  = $00080000;               // Periodical (pauses each passcount)
  BP_ACCESSMASK  = $00E00000;               // Access conditions (memory+hard)
    BP_READ      = $00200000;               // Break on read memory access
    BP_WRITE     = $00400000;               // Break on write memory access
    BP_EXEC      = $00800000;               // Break on code execution
  BP_BREAKMASK   = $03000000;               // When to pause execution
    BP_NOBREAK   = $00000000;               // No pause
    BP_CONDBREAK = $01000000;               // Pause if condition is true
    BP_BREAK     = $03000000;               // Pause always
  BP_LOGMASK     = $0C000000;               // When to log value of expression
    BP_NOLOG     = $00000000;               // Don't log expression
    BP_CONDLOG   = $04000000;               // Log expression if condition is true
    BP_LOG       = $0C000000;               // Log expression always
  BP_ARGMASK     = $30000000;               // When to log arguments of a function
    BP_NOARG     = $00000000;               // Don't log arguments
    BP_CONDARG   = $10000000;               // Log arguments if condition is true
    BP_ARG       = $30000000;               // Log arguments always
  BP_RETMASK     = $C0000000;               // When to log return value of a function
    BP_NORET     = $00000000;               // Don't log return value
    BP_CONDRET   = $40000000;               // Log return value if condition is true
    BP_RET       = $C0000000;               // Log return value always
  BP_MANMASK     = BP_PERIODICAL or BP_BREAKMASK or BP_LOGMASK or BP_ARGMASK or BP_RETMASK;
  BP_CONFIRM     = TY_CONFIRMED;            // Internal OllyDbg use
  // Search-related types (used in t_search).
  SE_ORIGIN      = $00010000;               // Search origin
  SE_STRING      = $00020000;               // Data contains string address
  SE_FLOAT       = $00040000;               // Data contains floating constant
  SE_GUID        = $00080000;               // Data contains GUID
  SE_CONST       = $01000000;               // Constant, not referencing command
  // Source-related types (used in t_source).
  SRC_ABSENT     = $00010000;               // Source file is absent
  // Namelist-related types (used in t_namelist).
  NL_EORD        = $00010000;               // Associated export ordinal available
  NL_IORD        = $00020000;               // Associated import ordinal available

type
  p_sorthdr = ^t_sorthdr;                   // Header of sorted data item
  t_sorthdr = packed record
    addr: ULong;                            // Base address of the entry
    size: ULong;                            // Size of the entry
    _type: ULong;                           // type and address extension, TY_xxx
  end;

  t_sorthdr_nosize = packed record          // Header of SDM_NOSIZE item
    addr: ULong;                            // Base address of the entry
  end;

  SORTFUNC = function(const sd1: p_sorthdr; const sd2: p_sorthdr; const int: Integer): Integer; cdecl;
  DESTFUNC = procedure(sd: p_sorthdr); cdecl;

const
  AUTOARRANGE: SORTFUNC = SORTFUNC(1);      // Autoarrangeable sorted data

  NBLOCK         = 2048;                    // Max number of data blocks
  BLOCKSIZE      = 1048576;                 // Size of single data block, bytes

type
  p_sorted = ^t_sorted;                     // Descriptor of sorted data
  t_sorted = packed record
    n: Integer;                             // Actual number of entries
    nmax: Integer;                          // Maximal number of entries
    itemsize: ULong;                        // Size of single entry
    mode: Integer;                          // Storage mode, set of SDM_xxx
    data: Pointer;                          // Sorted data, NULL if SDM_INDEXED
    block: PPointer;                        // NBLOCK sorted data blocks, or NULL
    nblock: Integer;                        // Number of allocated blocks
    version: ULong;                         // Changes on each modification
    dataptr: PPointer;                      // Pointers to data, sorted by address
    selected: Integer;                      // Index of selected entry
    seladdr: ULong;                         // Base address of selected entry
    selsubaddr: ULong;                      // Subaddress of selected entry
    sortfunc: SORTFUNC;                     // Function which sorts data or NULL
    destfunc: DESTFUNC;                     // Destructor function or NULL
    sort: Integer;                          // Sorting criterium (column)
    sorted: Integer;                        // Whether indexes are sorted
    sortindex: PInteger;                    // Indexes, sorted by criterium
  end;

procedure Destroysorteddata(sd: p_sorted); cdecl; external OLLYDBG name 'Destroysorteddata';
function  Createsorteddata(sd: p_sorted; itemsize: ULong; nexp: Integer;
            sortfunc: SORTFUNC; destfunc: DESTFUNC; mode: Integer): Integer; cdecl; external OLLYDBG name 'Createsorteddata';
procedure Deletesorteddata(sd: p_sorted; addr: ULong; subaddr: ULong); cdecl; external OLLYDBG name 'Deletesorteddata';
function  Deletesorteddatarange(sd: p_sorted; addr0: ULong; addr1: ULong): Integer; cdecl; external OLLYDBG name 'Deletesorteddatarange';
function  Addsorteddata(sd: p_sorted; item: Pointer): Pointer; cdecl; external OLLYDBG name 'Addsorteddata';
function  Replacesorteddatarange(sd: p_sorted; data: Pointer; n: Integer;
            addr0: ULong; addr1: ULong): Integer; cdecl; external OLLYDBG name 'Replacesorteddatarange';
procedure Renumeratesorteddata(sd: p_sorted); cdecl; external OLLYDBG name 'Renumeratesorteddata';
function  Confirmsorteddata(sd: p_sorted; confirm: Integer): Integer; cdecl; external OLLYDBG name 'Confirmsorteddata';
function  Deletenonconfirmedsorteddata(sd: p_sorted): Integer; cdecl; external OLLYDBG name 'Deletenonconfirmedsorteddata';
procedure Unmarknewsorteddata(sd: p_sorted); cdecl; external OLLYDBG name 'Unmarknewsorteddata';
function  Findsorteddata(sd: p_sorted; addr: ULong; subaddr: ULong): Pointer; cdecl; external OLLYDBG name ' Findsorteddata';
function  Findsorteddatarange(sd: p_sorted; addr0: ULong; addr1: ULong): Pointer cdecl; external OLLYDBG name 'Findsorteddatarange';
function  Findsortedindexrange(sd: p_sorted; addr0: ULong; addr1: ULong): Integer; cdecl; external OLLYDBG name 'Findsortedindexrange';
function  Getsortedbyindex(sd: p_sorted; index: Integer): Pointer; cdecl; external OLLYDBG name 'Getsortedbyindex';
function  Sortsorteddata(sd: p_sorted; sort: Integer): Integer; cdecl; external OLLYDBG name 'Sortsorteddata';
function  Getsortedbyselection(sd: p_sorted; index: Integer): Pointer; cdecl; external OLLYDBG name 'Getsortedbyselection';
function  Issortedinit(sd: p_sorted): Integer; cdecl; external OLLYDBG name 'Issortedinit';


////////////////////////////////////////////////////////////////////////////////
///////////////////////// SORTED DATA WINDOWS (TABLES) /////////////////////////
const
  NBAR           = 17;                      // Max allowed number of segments in bar

  BAR_FLAT       = $00000000;               // Flat segment
  BAR_BUTTON     = $00000001;               // Segment sends WM_USER_BAR
  BAR_SORT       = $00000002;               // Segment re-sorts sorted data
  BAR_DISABLED   = $00000004;               // Bar segment disabled
  BAR_NORESIZE   = $00000008;               // Bar column cannot be resized
  BAR_SHIFTSEL   = $00000010;               // Selection shifted 1/2 char to left
  BAR_WIDEFONT   = $00000020;               // Twice as wide characters
  BAR_SEP        = $00000040;               // Treat '|' as separator
  BAR_ARROWS     = $00000080;               // Arrows if segment is shifted
  BAR_PRESSED    = $00000100;               // Bar segment pressed, used internally
  BAR_SPMASK     = $0000F000;               // Mask to extract speech type
    BAR_SPSTD    = $00000000;               // Standard speech with all conversions
    BAR_SPASM    = $00001000;               // Disassembler-oriented speech
    BAR_SPEXPR   = $00002000;               // Expression-oriented speech
    BAR_SPEXACT  = $00003000;               // Pass to speech engine as is
    BAR_SPELL    = $00004000;               // Text, spell symbol by symbol
    BAR_SPHEX    = $00005000;               // Hexadecimal, spell symbol by symbol
    BAR_SPNONE   = $0000F000;               // Column is excluded from speech


type
  p_bar = ^t_bar;                           // Descriptor of columns in table window
  t_bar = packed record
  // These variables must be filled before table window is created.
    nbar: Integer;                          // Number of columns
    visible: Integer;                       // Bar visible
    name: array[0..NBAR-1] of PWChar;       // Column names (may be NULL)
    expl: array[0..NBAR-1] of PWChar;       // Explanations of columns
    mode: array[0..NBAR-1] of Integer;      // Combination of bits BAR_xxx
    defdx: array[0..NBAR-1] of Integer;     // Default widths of columns, chars
    // These variables are initialized by window creation function.
    dx: array[0..NBAR-1] of Integer;        // Actual widths of columns, pixels
    captured: Integer;                      // One of CAPT_xxx
    active: Integer;                        // Info about where mouse was captured
    scrollvx: Integer;                      // X scrolling speed
    scrollvy: Integer;                      // Y scrolling speed
    prevx: Integer;                         // Previous X mouse coordinate
    prevy: Integer;                         // Previous Y mouse coordinate
  end;


///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////
const
  TABLE_USERDEF  = $00000001;               // User-drawn table
  TABLE_STDSCR   = $00000002;               // User-drawn but standard scrolling
  TABLE_SIMPLE   = $00000004;               // Non-sorted, address is line number
  TABLE_DIR      = $00000008;               // Bottom-to-top table
  TABLE_COLSEL   = $00000010;               // Column-wide selection
  TABLE_BYTE     = $00000020;               // Allows for bytewise scrolling
  TABLE_FASTSEL  = $00000040;               // Update when selection changes
  TABLE_RIGHTSEL = $00000080;               // Right click can select items
  TABLE_RFOCUS   = $00000100;               // Right click sets focus
  TABLE_NOHSCR   = $00000200;               // Table contains no horizontal scroll
  TABLE_NOVSCR   = $00000400;               // Table contains no vertical scroll
  TABLE_NOBAR    = $00000800;               // Bar is always hidden
  TABLE_STATUS   = $00001000;               // Table contains status bar
  TABLE_MMOVX    = $00002000;               // Table is moveable by mouse in X
  TABLE_MMOVY    = $00004000;               // Table is moveable by mouse in Y
  TABLE_WANTCHAR = $00008000;               // Table processes characters
  TABLE_SAVEAPP  = $00010000;               // Save appearance to .ini
  TABLE_SAVEPOS  = $00020000;               // Save position to .ini
  TABLE_SAVECOL  = $00040000;               // Save width of columns to .ini
  TABLE_SAVESORT = $00080000;               // Save sort criterium to .ini
  TABLE_SAVECUST = $00100000;               // Save table-specific data to .ini
  TABLE_GRAYTEXT = $00200000;               // Text in table is grayed
  TABLE_NOGRAY   = $00400000;               // Text in pane is never grayed
  TABLE_UPDFOCUS = $00800000;               // Update frame pane on focus change
  TABLE_AUTOUPD  = $01000000;               // Table allows periodical autoupdate
  TABLE_SYNTAX   = $02000000;               // Table allows syntax highlighting
  TABLE_PROPWID  = $04000000;               // Column width means proportional width
  TABLE_INFRAME  = $10000000;               // Table belongs to the frame window
  TABLE_BORDER   = $20000000;               // Table has sunken border
  TABLE_KEEPOFFS = $80000000;               // Keep xshift, offset, colsel

  TABLE_MOUSEMV  = TABLE_MMOVX or TABLE_MMOVY;
  TABLE_SAVEALL  = TABLE_SAVEAPP or TABLE_SAVEPOS or TABLE_SAVECOL or TABLE_SAVESORT;

  DRAW_COLOR     = $0000001F;               // Mask to extract colour/bkgnd index
    // Direct colour/background pairs.
    DRAW_NORMAL  = $00000000;               // Normal text
    DRAW_HILITE  = $00000001;               // Highlighted text
    DRAW_GRAY    = $00000002;               // Grayed text
    DRAW_EIP     = $00000003;               // Actual EIP
    DRAW_BREAK   = $00000004;               // Unconditional breakpoint
    DRAW_COND    = $00000005;               // Conditional breakpoint
    DRAW_BDIS    = $00000006;               // Disabled breakpoint
    DRAW_IPBREAK = $00000007;               // Breakpoint at actual EIP
    DRAW_AUX     = $00000008;               // Auxiliary colours
    DRAW_SELUL   = $00000009;               // Selection and underlining
    // Indirect pairs used to highlight commands.
    DRAW_PLAIN   = $0000000C;               // Plain commands
    DRAW_JUMP    = $0000000D;               // Unconditional jump commands
    DRAW_CJMP    = $0000000E;               // Conditional jump commands
    DRAW_PUSHPOP = $0000000F;               // PUSH/POP commands
    DRAW_CALL    = $00000010;               // CALL commands
    DRAW_RET     = $00000011;               // RET commands
    DRAW_FPU     = $00000012;               // FPU, MMX, 3DNow! and SSE commands
    DRAW_SUSPECT = $00000013;               // Bad, system and privileged commands
    DRAW_FILL    = $00000014;               // Filling commands
    DRAW_MOD       = $00000015;             // Modified commands
    // Indirect pairs used to highlight operands.
    DRAW_IREG    = $00000018;               // General purpose registers
    DRAW_FREG    = $00000019;               // FPU, MMX and SSE registers
    DRAW_SYSREG  = $0000001A;               // Segment and system registers
    DRAW_STKMEM  = $0000001B;               // Memory accessed over ESP or EBP
    DRAW_MEM     = $0000001C;               // Any other memory
    DRAW_MCONST  = $0000001D;               // Constant pointing to memory
    DRAW_CONST   = $0000001E;               // Any other constant
  DRAW_APP       = $00000060;               // Mask to extract appearance
    DRAW_TEXT    = $00000000;               // Plain text
    DRAW_ULTEXT  = $00000020;               // Underlined text
    DRAW_GRAPH   = $00000060;               // Graphics (text consists of G_xxx)
  DRAW_SELECT    = $00000080;               // Use selection background
  DRAW_MASK      = $00000100;               // Mask in use
  DRAW_VARWIDTH  = $00000200;               // Variable width possible
  DRAW_EXTSEL    = $00000800;               // Extend mask till end of column
  DRAW_TOP       = $00001000;               // Draw upper half of the two-line text
  DRAW_BOTTOM    = $00002000;               // Draw lower half of the two-line text
  DRAW_INACTIVE  = $00004000;               // Gray everything except hilited text
  DRAW_RAWDATA   = $00008000;               // Don't convert glyphs and multibytes
  DRAW_NEW       = $00010000;               // Use highlighted foreground

type
  p_drawheader = ^t_drawheader;             // Draw descriptor for TABLE_USERDEF
  t_drawheader = packed record
    line: Integer;                          // Line in window
    n: Integer;                             // Total number of visible lines
    nextaddr: ULong;                        // First address on next line, or 0
    // Following elements can be freely used by drawing routine. They do not
    // change between calls within one table.
    addr: ULong;                            // Custom data
    s: array[0..TEXTLEN-1] of UChar;        // Custom data
  end;

const
  // Constants used for scrolling and selection.
  MOVETOP        = $8000;                   // Move selection to top of table
  MOVEBOTTOM     = $7FFF;                   // Move selection to bottom of table

  DF_CACHESIZE   = -4;                      // Request for draw cache size
  DF_FILLCACHE   = -3;                      // Request to fill draw cache
  DF_FREECACHE   = -2;                      // Request to free cached resources
  DF_NEWROW      = -1;                      // Request to start new row in window

  // Reasons why t_table.tableselfunc() was called.
  TSC_KEY        = 1;                       // Keyboard key pressed
  TSC_MOUSE      = 2;                       // Selection changed by mouse
  TSC_CALL       = 3;                       // Call to selection move function

type
  p_table = ^t_table;

  MENUFUNC   = function(table: p_table; text: PWChar; index: ULong; mode: Integer): Integer; cdecl;
  TABFUNC    = function(pt: p_table; hw: HWND; uMsg: UINT; wp: WPARAM; lp: LPARAM): LongInt; cdecl;
  UPDATEFUNC = function(pt: p_table): Integer; cdecl;
  DRAWFUNC   = function(s: PWChar; mask: PUChar; select: PInteger; pt: p_table; ps: p_sorthdr; column: Integer; cache: Pointer): Integer; cdecl;
  TABSELFUNC = procedure(pt: p_table; selected: Integer; reason: Integer); cdecl;

  t_menu_union = record
    case BYTE of
      0: (index: ULong);                    // Argument passed to menu function
      1: (hsubmenu: HMENU);                 // Handle of pulldown menu
  end;

  p_menu = ^t_menu;
  t_menu = packed record
    name: PWChar;                           // Menu command
    help: PWChar;                           // Explanation of command
    shortcutid: Integer;                    // Shortcut identifier, K_xxx
    menufunc: MENUFUNC;                     // Function that executes menu command
    submenu: p_menu;                        // Pointer to descriptor of popup menu
    menuType: t_menu_union;
  end;

  t_table = packed record
    // These variables must be filled before table window is created.
    name: array[0..SHORTNAME-1] of WChar;   // Name used to save/restore position
    mode: Integer;                          // Combination of bits TABLE_xxx
    sorted: t_sorted;                       // Sorted data
    subtype: Integer;                       // User-defined subtype
    bar: t_bar;                             // Description of bar
    bottomspace: Integer;                   // Height of free space on the bottom
    minwidth: Integer;                      // Minimal width of the table, pixels
    tabfunc: TABFUNC;                       // Custom message function or NULL
    updatefunc: UPDATEFUNC;                 // Data update function or NULL
    drawfunc: DRAWFUNC;                     // Drawing function
    tableselfunc: TABSELFUNC;               // Callback indicating selection change
    menu: p_menu;                           // Menu descriptor
    // Table functions neither initialize nor use these variables.
    custommode: ULong;                      // User-defined custom data
    customdata: Pointer;                    // Pointer to more custom data
    // These variables are initialized and/or used by table functions.
    hparent: HWND;                          // Handle of MDI container or NULL
    hstatus: HWND;                          // Handle of status bar or NULL
    hw: HWND;                               // Handle of child table or NULL
    htooltip: HWND;                         // Handle of tooltip window or NULL
    font: Integer;                          // Index of font used by window
    scheme: Integer;                        // Colour scheme used by window
    hilite: Integer;                        // Highlighting scheme used by window
    hscroll: Integer;                       // Whether horizontal scroll visible
    xshift: Integer;                        // Shift in X direction, pixels
    offset: Integer;                        // First displayed row
    colsel: Integer;                        // Column in TABLE_COLSEL window
    version: ULong;                         // Version of sorted on last update
    timerdraw: ULong;                       // Timer redraw is active (period, ms)
    rcprev: TRect;                          // Temporary storage for old position
    rtback: Integer;                        // Back step in run trace, 0 - actual
  end;

function Callmenufunction(pt: p_table; pm: p_menu; menufunc: MENUFUNC; index: ULong): Integer; cdecl; external OLLYDBG name 'Callmenufunction';


////////////////////////////////////////////////////////////////////////////////
const
  GWL_USR_TABLE  = 0;                       // Offset to pointer to t_table

  // Declared in unit Messages.pas
  WM_USER        = $0400;

  // Custom messages.
  WM_USER_CREATE = WM_USER + 100;           // Table window is created
  WM_USER_HSCR   = WM_USER + 101;           // Update horizontal scroll
  WM_USER_VSCR   = WM_USER + 102;           // Update vertical scroll
  WM_USER_MOUSE  = WM_USER + 103;           // Mouse moves, set custom cursor
  WM_USER_VINC   = WM_USER + 104;           // Scroll contents of window by lines
  WM_USER_VPOS   = WM_USER + 105;           // Scroll contents of window by position
  WM_USER_VBYTE  = WM_USER + 106;           // Scroll contents of window by bytes
  WM_USER_SETS   = WM_USER + 107;           // Start selection in window
  WM_USER_CNTS   = WM_USER + 108;           // Continue selection in window
  WM_USER_MMOV   = WM_USER + 109;           // Move window's contents by mouse
  WM_USER_MOVS   = WM_USER + 110;           // Keyboard scrolling and selection
  WM_USER_KEY    = WM_USER + 111;           // Key pressed
  WM_USER_BAR    = WM_USER + 112;           // Message from bar segment as button
  WM_USER_DBLCLK = WM_USER + 113;           // Doubleclick in column
  WM_USER_SELXY  = WM_USER + 114;           // Get coordinates of selection
  WM_USER_FOCUS  = WM_USER + 115;           // Set focus to child of frame window
  WM_USER_UPD    = WM_USER + 116;           // Autoupdate contents of the window
  WM_USER_MTAB   = WM_USER + 117;           // Middle click on tab in tab parent
  // Custom broadcasts and notifications.
  WM_USER_CHGALL = WM_USER + 132;           // Update all windows
  WM_USER_CHGCPU = WM_USER + 133;           // CPU thread has changed
  WM_USER_CHGMEM = WM_USER + 134;           // List of memory blocks has changed
  WM_USER_BKUP   = WM_USER + 135;           // Global backup is changed
  WM_USER_FILE   = WM_USER + 136;           // Query for file dump
  WM_USER_NAMES  = WM_USER + 137;           // Query for namelist window
  WM_USER_SAVE   = WM_USER + 138;           // Query for unsaved data
  WM_USER_CLEAN  = WM_USER + 139;           // End of process, close related windows
  WM_USER_HERE   = WM_USER + 140;           // Query for windows to restore
  WM_USER_CLOSE  = WM_USER + 141;           // Internal substitute for WM_CLOSE

  KEY_ALT        = $04;                     // Alt key pressed
  KEY_CTRL       = $02;                     // Ctrl key pressed
  KEY_SHIFT      = $01;                     // Shift key pressed

  // Control alignment modes for Createtablechild().
  ALIGN_MASK     = $C000;                   // Mask to extract control alignment
    ALIGN_LEFT   = $0000;                   // Control doesn't move
    ALIGN_RIGHT  = $4000;                   // Control moves with right border
    ALIGN_WIDTH  = $8000;                   // Control resizes with right border
  ALIGN_IDMASK   = $0FFF;                   // Mask to extract control ID

procedure Processwmmousewheel(hw: HWND; wp: WPARAM); cdecl; external OLLYDBG name 'Processwmmousewheel';
function  Getcharacterwidth(pt: p_table; column: Integer): Integer; cdecl; external OLLYDBG name 'Getcharacterwidth';
procedure Defaultbar(pt: p_table); cdecl; external OLLYDBG name 'Defaultbar';
function  Linecount(pt: p_table): Integer; cdecl; external OLLYDBG name 'Linecount';
function  Gettabletext(pt: p_table; row: Integer; column: Integer;
            text: PWChar; tmask: PUChar; tselect: PInteger): Integer; cdecl; external OLLYDBG name 'Gettabletext';
function  Gettableselectionxy(pt: p_table; column: Integer; coord: PPoint): Integer; cdecl; external OLLYDBG name 'Gettableselectionxy';
function  Maketableareavisible(pt: p_table; column: Integer;
            x0: Integer; y0: Integer; x1: Integer; y1: Integer): Integer; cdecl; external OLLYDBG name 'Maketableareavisible';
function  Movetableselection(pt: p_table; n: Integer): Integer; cdecl; external OLLYDBG name 'Movetableselection';
function  Settableselection(pt: p_table; selected: Integer): Integer; cdecl; external OLLYDBG name 'Settableselection';
function  Removetableselection(pt: p_table): Integer; cdecl; external OLLYDBG name 'Removetableselection';
procedure Updatetable(pt: p_table; force: Integer); cdecl; external OLLYDBG name 'Updatetable';
procedure Delayedtableredraw(pt: p_table); cdecl; external OLLYDBG name 'Delayedtableredraw';
procedure Setautoupdate(pt: p_table; autoupdate: Integer); cdecl; external OLLYDBG name 'Setautoupdate';
function  Copytableselection(pt: p_table; column: Integer): HGLOBAL; cdecl; external OLLYDBG name 'Copytableselection';
function  Copywholetable(pt: p_table; compatible: Integer): HGLOBAL; cdecl; external OLLYDBG name 'Copywholetable';
function  Createottablewindow(hparent: HWND; pt: p_table; rpos: PRect): HWND; cdecl; external OLLYDBG name 'Createottablewindow';
function  Createtablewindow(pt: p_table; nrow: Integer; ncolumn: Integer;
            hi: THandle; icon: PWChar; title: PWChar): HWND; cdecl; external OLLYDBG name 'Createtablewindow';
function  Activatetablewindow(pt: p_table): HWND; cdecl; external OLLYDBG name 'Activatetablewindow';
function  Createtablechild(pt: p_table; classname: PWChar; name: PWChar;
            help: PWChar; style: ULong; x: Integer; y: Integer; dx: Integer; dy: Integer;
            idalign: Integer): HWND; cdecl; external OLLYDBG name 'Createtablechild';


////////////////////////////////////////////////////////////////////////////////
//////////////////////////// FRAME AND TAB WINDOWS /////////////////////////////
const
  BLK_NONE       = 0;                       // Mouse outside the dividing line
  BLK_HDIV       = 1;                       // Divide horizontally
  BLK_VDIV       = 2;                       // Divide vertically
  BLK_TABLE      = 3;                       // Leaf that describes table window

type
  p_block = ^t_block;                       // Block descriptor
  t_block = packed record
    index: Integer;                         // Index of pos record in the .ini file
    _type: Integer;                         // One of BLK_xxx
    percent: Integer;                       // Percent of block in left/top subblock
    offset: Integer;                        // Offset of dividing line, pixels
    blk1: p_block;                          // Top/left subblock, NULL if leaf
    minp1: Integer;                         // Min size of 1st subblock, pixels
    maxc1: Integer;                         // Max size of 1st subblock, chars, or 0
    blk2: p_block;                          // Bottom/right subblock, NULL if leaf
    minp2: Integer;                         // Min size of 2nd subblock, pixels
    maxc2: Integer;                         // Max size of 2nd subblock, chars, or 0
    table: p_table;                         // Descriptor of table window
    tabname: array[0..SHORTNAME-1] of WChar;// Tab (tab window only)
    title: array[0..TEXTLEN-1] of WChar;    // Title (tab window) or speech name
    status: array[0..TEXTLEN-1] of WChar;   // Status (tab window only)
  end;

  p_frame = ^t_frame;                       // Descriptor of frame or tab window
  t_frame = packed record
    // These variables must be filled before frame window is created.
    name: array[0..SHORTNAME-1] of WChar;   // Name used to save/restore position
    herebit: Integer;                       // Must be 0 for plugins
    mode: Integer;                          // Combination of bits TABLE_xxx
    block: p_block;                         // Pointer to block tree
    menu: p_menu;                           // Menu descriptor (tab window only)
    scheme: Integer;                        // Colour scheme used by window
    // These variables are initialized by frame creation function.
    hw: HWND;                               // Handle of MDI container or NULL
    htab: HWND;                             // Handle of tab control
    htabwndproc: TFNWndProc;                // Original WndProc of tab control
    capturedtab: Integer;                   // Tab captured on middle mouse click
    hstatus: HWND;                          // Handle of status bar or NULL
    active: p_block;                        // Active table (has focus) or NULL
    captured: p_block;                      // Block that captured mouse or NULL
    captureoffset: Integer;                 // Offset on mouse capture
    capturex: Integer;                      // Mouse screen X coordinate on capture
    capturey: Integer;                      // Mouse screen Y coordinate on capture
    title: array[0..TEXTLEN-1] of WChar;    // Frame or tab window title
  end;

function  Createframewindow(pf: p_frame; icon: PWChar; title: PWChar): HWND; cdecl; external OLLYDBG name 'Createframewindow';
procedure Updateframe(pf: p_frame; redrawnow: Integer); cdecl; external OLLYDBG name 'Updateframe';
function  Getactiveframe(pf: p_frame): p_table; cdecl; external OLLYDBG name 'Getactiveframe';

function  Updatetabs(pf: p_frame): Integer; cdecl; external OLLYDBG name 'Updatetabs';
function  Createtabwindow(pf: p_frame; icon: PWChar; title: PWChar): HWND; cdecl; external OLLYDBG name 'Createtabwindow';
function  Getactivetab(pf: p_frame): p_table; cdecl; external OLLYDBG name 'Getactivetab';
function  Gettabcount(pf: p_frame; index: PInteger): Integer; cdecl; external OLLYDBG name 'Gettabcount';
function  Setactivetab(pf: p_frame; index: Integer): Integer; cdecl; external OLLYDBG name 'Setactivetab';


////////////////////////////////////////////////////////////////////////////////
////////////////////////////// FONTS AND GRAPHICS //////////////////////////////
const
  FIXEDFONT      = 0;                       // Indices of fixed fonts used in tables
  TERMINAL6      = 1;                       // Note: fonts may be changed by user!
  FIXEDSYS       = 2;
  COURIERFONT    = 3;
  LUCIDACONS     = 4;
  FONT5          = 5;
  FONT6          = 6;
  FONT7          = 7;

  NFIXFONTS      = 8;                       // Total number of fixed fonts

  BLACKWHITE     = 0;                       // Colour schemes used by OllyDbg
  BLUEGOLD       = 1;                       // Note: colours may be changed by user!
  SKYWIND        = 2;
  NIGHTSTARS     = 3;
  SCHEME4        = 4;
  SCHEME5        = 5;
  SCHEME6        = 6;
  SCHEME7        = 7;

  NSCHEMES       = 8;                       // Number of predefined colour schemes
  NDRAW          = 32;                      // Number of fg/bg pairs in scheme

  NOHILITE       = 0;                       // Highlighting schemes used by OllyDbg
  XMASHILITE     = 1;                       // Note: colours may be changed by user!
  JUMPHILITE     = 2;
  MEMHILITE      = 3;
  HILITE4        = 4;
  HILITE5        = 5;
  HILITE6        = 6;
  HILITE7        = 7;

  NHILITE        = 8;                       // Number of predefined hilite schemes

  BLACK          = 0;                       // Indexes of colours used by OllyDbg
  BLUE           = 1;
  GREEN          = 2;
  CYAN           = 3;
  RED            = 4;
  MAGENTA        = 5;
  BROWN          = 6;
  LIGHTGRAY      = 7;
  DARKGRAY       = 8;
  LIGHTBLUE      = 9;
  LIGHTGREEN     = 10;
  LIGHTCYAN      = 11;
  LIGHTRED       = 12;
  LIGHTMAGENTA   = 13;
  YELLOW         = 14;
  WHITE          = 15;
  MINT           = 16;
  SKYBLUE        = 17;
  IVORY          = 18;
  GRAY           = 19;

  NFIXCOLORS     = 20;                      // Number of colors fixed in OllyDbg
  NCOLORS        = NFIXCOLORS + 16;         // Number of available colours

  // Symbolic names for graphical characters. Any other graphical symbol is
  // interpreted as a space. Use only symbols in range [0x01..0x3F], high bits
  // are reserved for the future!
  G_SPACE        = $01;                     // Space
  G_SEP          = $02;                     // Thin separating line
  G_POINT        = $03;                     // Point
  G_BIGPOINT     = $04;                     // Big point
  G_JMPDEST      = $05;                     // Jump destination
  G_CALLDEST     = $06;                     // Call destination
  G_QUESTION     = $07;                     // Question mark
  G_JMPUP        = $10;                     // Jump upstairs
  G_JMPOUT       = $11;                     // Jump to same location or outside
  G_JMPDN        = $12;                     // Jump downstairs
  G_SWUP         = $13;                     // Switch upstairs
  G_SWBOTH       = $14;                     // Switch in both directions
  G_SWDOWN       = $15;                     // Switch down
  G_BEGIN        = $18;                     // Begin of procedure or scope
  G_BODY         = $19;                     // Body of procedure or scope
  G_ENTRY        = $1A;                     // Loop entry point
  G_LEAF         = $1B;                     // Intermediate leaf on a tree
  G_END          = $1C;                     // End of procedure or scope
  G_SINGLE       = $1D;                     // Single-line scope
  G_ENDBEG       = $1E;                     // End and begin of stack scope
  G_PATHUP       = $21;                     // Jump path start upstairs
  G_PATH         = $22;                     // Jump path through
  G_PATHDN       = $23;                     // Jump path start downstairs
  G_PATHUPDN     = $24;                     // Two-sided jump path start
  G_THROUGHUP    = $25;                     // Jump entry upstairs
  G_THROUGHDN    = $26;                     // Jump entry downstairs
  G_PATHUPEND    = $27;                     // End of path upstairs
  G_PATHDNEND    = $28;                     // End of path downstairs
  G_PATHBIEND    = $29;                     // Two-sided end of path
  G_THRUUPEND    = $2A;                     // Intermediate end upstairs
  G_THRUDNEND    = $2B;                     // Intermediate end downstairs
  G_ARRLEFT      = $2C;                     // Left arrow
  // Graphical elements used to draw frames in the command help.
  G_HL           = $30;                     // Horizontal line
  G_LT           = $31;                     // Left top corner
  G_CT           = $32;                     // Central top element
  G_RT           = $33;                     // Right top corner
  G_LM           = $34;                     // Left middle element
  G_CM           = $35;                     // Central cross
  G_RM           = $36;                     // Right middle element
  G_LB           = $37;                     // Left bottom corner
  G_CB           = $38;                     // Central bottom element
  G_RB           = $39;                     // Right bottom corner
  G_VL           = $3A;                     // Vertical line
  G_LA           = $3B;                     // Horizontal line with left arrow
  G_RA           = $3C;                     // Horizontal line with right arrow
  G_DA           = $3D;                     // Vertical line with down arrow

type
  p_font = ^t_font;                         // Font descriptor
  t_font = packed record
    logfont: LOGFONTW;                      // System font description
    stockindex: Integer;                    // Index for system stock fonts
    hadjtop: Integer;                       // Height adjustment on top, pixels
    hadjbot: Integer;                       // Height adjustment on bottom, pixels
    name: array[0..TEXTLEN-1] of WChar;     // Internal font name
    hfont: HFONT;                           // Font handle
    isstock: Integer;                       // Don't destroy hfont, taken from stock
    isfullunicode: Integer;                 // Whether UNICODE is fully supported
    width: Integer;                         // Average font width
    height: Integer;                        // Font height
  end;

  p_scheme = ^t_scheme;                     // Descriptor of colour scheme
  t_scheme = packed record
    name: array[0..TEXTLEN-1] of WChar;     // Internal scheme name
    textcolor: array[0..NDRAW-1] of COLORREF; // Foreground colours (in DRAW_COLOR)
    bkcolor: array[0..NDRAW-1] of COLORREF; // Background colours (in DRAW_COLOR)
    hiliteoperands: Integer;                // Used only by highlighting schemes
    hilitemodified: Integer;                // Used only by highlighting schemes
    bkbrush: HBRUSH;                        // Ordinary background brush
    selbkbrush: HBRUSH;                     // Selected background brush
    auxbrush: HBRUSH;                       // Auxiliary brush
    graphpen: HPEN;                         // Pen for normal graphical elements
    lopen: HPEN;                            // Pen for grayed graphical elements
    hipen: HPEN;                            // Pen for hilited graphical elements
    auxpen: HPEN;                           // Pen for auxiliary graphical elements
    ulpen: HPEN;                            // Pen to underline text
  end;

function  Getmonitorrect(x: Integer; y: Integer; rc: PRect): Integer; cdecl; external OLLYDBG name 'Getmonitorrect';
procedure Sunkenframe(dc: HDC; rc: PRect; flags: Integer); cdecl; external OLLYDBG name 'Sunkenframe';
function  Findstockobject(gdihandle: ULong; name: PWChar; nname: Integer): Integer; cdecl; external OLLYDBG name 'Findstockobject';


////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// MEMORY FUNCTIONS ///////////////////////////////
const
  // Mode bits used in calls to Readmemory(), Readmemoryex() and Writememory().
  MM_REPORT      = $0000;                   // Display error message if unreadable
  MM_SILENT      = $0001;                   // Don't display error message
  MM_NORESTORE   = $0002;                   // Don't remove/set INT3 breakpoints
  MM_PARTIAL     = $0004;                   // Allow less data than requested
  MM_WRITETHRU   = $0008;                   // Write immediately to memory
  MM_REMOVEINT3  = $0010;                   // Writememory(): remove INT3 breaks
  MM_ADJUSTINT3  = $0020;                   // Writememory(): adjust INT3 breaks
  MM_FAILGUARD   = $0040;                   // Fail if memory is guarded
  // Mode bits used in calls to Readmemoryex().
  MM_BPMASK      = BP_ACCESSMASK;           // Mask to extract memory breakpoints
    MM_BPREAD    = BP_READ;                 // Fail if memory break on read is set
    MM_BPWRITE   = BP_WRITE;                // Fail if memory break on write is set
    MM_BPEXEC    = BP_EXEC;                 // Fail if memory break on exec is set

  // Special types of memory block.
  MSP_NONE       = 0;                       // Not a special memory block
  MSP_PEB        = 1;                       // Contains Process Environment Block
  MSP_SHDATA     = 2;                       // Contains KUSER_SHARED_DATA
  MSP_PROCPAR    = 3;                       // Contains Process Parameters
  MSP_ENV        = 4;                       // Contains environment

type
  p_memory = ^t_memory;                     // Descriptor of memory block
  t_memory = packed record
    base: ULong;                            // Base address of memory block
    size: ULong;                            // Size of memory block
    _type: ULong;                           // Service information, TY_xxx+MEM_xxx
    special: Integer;                       // Extension of type, one of MSp_xxx
    owner: ULong;                           // Address of owner of the memory
    initaccess: ULong;                      // Initial read/write access
    access: ULong;                          // Actual status and read/write access
    threadid: ULong;                        // Block belongs to this thread or 0
    sectname: array[0..SHORTNAME-1] of WChar; // Null-terminated section name
    copy: PUChar;                           // Copy used in CPU window or NULL
    decode: PUChar;                         // Decoding information or NULL
  end;

procedure Flushmemorycache; cdecl; external OLLYDBG name 'Flushmemorycache';
function  Readmemory(buf: Pointer; addr: ULong; size: ULong; mode: Integer): ULong; cdecl; external OLLYDBG name 'Readmemory';
function  Readmemoryex(buf: Pointer; addr: ULong; size: ULong; mode: Integer;
            threadid: ULong): ULong; cdecl; external OLLYDBG name 'Readmemoryex';
function  Writememory(const buf: Pointer; addr: ULong; size: ULong; mode: Integer): ULong; cdecl; external OLLYDBG name 'Writememory';
function  Findmemory(addr: ULong): p_memory; cdecl; external OLLYDBG name 'Findmemory';
function  Finddecode(addr: ULong; psize: PULong): PUChar; cdecl; external OLLYDBG name 'Finddecode';
function  Guardmemory(base: ULong; size: ULong; guard: Integer): Integer; cdecl; external OLLYDBG name 'Guardmemory';
function  Listmemory: Integer; cdecl; external OLLYDBG name 'Listmemory';
function  Copymemoryhex(addr: ULong; size: ULong): HGLOBAL; cdecl; external OLLYDBG name 'Copymemoryhex';
function  Pastememoryhex(addr: ULong; size: ULong;
            ensurebackup: Integer; removeanalysis: Integer): Integer; cdecl; external OLLYDBG name 'Pastememoryhex';
function  Editmemory(hparent: HWND; addr: ULong; size: ULong;
            ensurebackup: Integer; removeanalysis: Integer; x: Integer; y: Integer; font: Integer): Integer; cdecl; external OLLYDBG name 'Editmemory';



////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// JUMP DATA ///////////////////////////////////
const
  // Types of recognized jumps and calls.
  JT_TYPE        = $000F;                   // Mask to extract data type
    JT_UNDEF     = $0000;                   // End of jump table
    JT_JUMP      = $0001;                   // Unconditional jump
    JT_COND      = $0002;                   // Conditional jump
    JT_SWITCH    = $0003;                   // Jump via switch table
    JT_RET       = $0004;                   // RET misused as jump
    JT_CALL      = $0005;                   // Call
    JT_SWCALL    = $0006;                   // Call via switch table
    JT_NETJUMP   = $0008;                   // Unconditional jump in CIL code
    JT_NETCOND   = $0009;                   // Conditional jump in CIL code
    JT_NETSW     = $000A;                   // Switch jump in CIL code
  // Used as flag to Addjump, absent in the jump table.
  JT_NOSORT      = $8000;                   // Do not sort data implicitly

type
  p_jmp = ^t_jmp;                           // Descriptor of recognized jump or call
  t_jmp = packed record
    from: ULong;                            // Address of jump/call command
    dest: ULong;                            // Adress of jump/call destination
    _type: UChar                            // Jump/call type, one of JT_xxx
  end;

// Note that these macros work both with t_jmp and t_jmpcall.
{
Isjump(jmp)    = (((jmp)->type >= JT_JUMP && (jmp)->type <= JT_RET) ||       \
                       ((jmp)->type >= JT_NETJUMP && (jmp)->type <= JT_NETSW));
Iscall(jmp)    = ((jmp)->type == JT_CALL || (jmp)->type == JT_SWCALL);
}
function Isjump(jmp: p_jmp): LongBool;
function Iscall(jmp: p_jmp): LongBool;

type
  p_exe = ^t_exe;
  t_exe = packed record                     // Description of executable module
    base: ULong;                            // Module base
    size: ULong;                            // Module size
    adjusted: Integer;                      // Whether base is already adjusted
    path: array[0..MAXPATH-1] of WChar;     // Full module path
  end;

  p_jmpdata = ^t_jmpdata;                   // Jump table
  t_jmpdata = packed record
    modbase: ULong;                         // Base of module owning jump table
    modsize: ULong;                         // Size of module owning jump table
    jmpdata: p_jmp;                         // Jump data, sorted by source
    jmpindex: PInteger;                     // Indices to jmpdata, sorted by dest
    maxjmp: Integer;                        // Total number of elements in arrays
    njmp: Integer;                          // Number of used elements in arrays
    nsorted: Integer;                       // Number of sorted elements in arrays
    dontsort: Integer;                      // Do not sort data implicitly
    exe: p_exe;                             // Pointed modules, unsorted
    maxexe: Integer;                        // Allocated number of elements in exe
    nexe: Integer;                          // Number of used elements in exe
  end;

  t_jmpcall_union = record
    case BYTE of
      0: (_type: Integer);                  // Jump/call type, one of JT_xxx
      1: (swcase: ULong);                   // First switch case
  end;

  p_jmpcall = ^t_jmpcall;                   // Descriptor of found jump or call
  t_jmpcall = packed record
    addr: ULong;                            // Source or destination address
    jmpType: t_jmpcall_union;
  end;

function  Addjump(pdat: p_jmpdata; from: ULong; dest: ULong; jtype: Integer): Integer; cdecl; external OLLYDBG name 'Addjump';
procedure Sortjumpdata(pdat: p_jmpdata); cdecl; external OLLYDBG name 'Sortjumpdata';
function  Findjumpfrom(from: ULong): p_jmp; cdecl; external OLLYDBG name 'Findjumpfrom';
function  Findlocaljumpsto(dest: ULong; buf: PULong; nbuf: Integer): Integer; cdecl; external OLLYDBG name 'Findlocaljumpsto';
function  Findlocaljumpscallsto(dest: ULong; jmpcall: p_jmpcall;
            njmpcall: Integer) : Integer; cdecl; external OLLYDBG name 'Findlocaljumpscallsto';
function  Arelocaljumpscallstorange(addr0: ULong; addr1: ULong): Integer; cdecl; external OLLYDBG name 'Arelocaljumpscallstorange';
function  Findglobalcallsto(dest: ULong; buf: PULong; nbuf: Integer): Integer; cdecl; external OLLYDBG name 'Findglobalcallsto';
function  Findglobaljumpscallsto(dest: ULong; jmpcall: p_jmpcall;
            njmpcall: Integer): Integer; cdecl; external OLLYDBG name 'Findglobaljumpscallsto';


////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// SETS OF RANGES ////////////////////////////////

type
  p_range = ^t_range;
  t_range = packed record
    rmin: ULong;                            // Low range limit
    rmax: ULong;                            // High range limit (INCLUDED!)
  end;

function  Initset(zset: p_range; nmax: ULong): Integer; cdecl; external OLLYDBG name 'Initset';
function  Fullrange(rset: p_range): Integer; cdecl; external OLLYDBG name 'Fullrange';
function  Emptyrange(rset: p_range): Integer; cdecl; external OLLYDBG name 'Emptyrange';
function  Getsetcount(const rset: p_range): ULong; cdecl; external OLLYDBG name 'Getsetcount';
function  Getrangecount(const rset: p_range): Integer; cdecl; external OLLYDBG name 'Getrangecount';
function  Isinset(const rset: p_range; value: ULong): Integer; cdecl; external OLLYDBG name 'Isinset';
function  Getrangebymember(const rset: p_range; value: ULong;
            rmin: PULong; rmax: PULong): Integer; cdecl; external OLLYDBG name 'Getrangebymember';
function  Getrangebyindex(const rset: p_range; index: Integer;
            rmin: PULong; rmax: PULong): Integer; cdecl; external OLLYDBG name 'Getrangebyindex';
function  Addrange(rset: p_range; rmin: ULong; rmax: ULong): Integer; cdecl; external OLLYDBG name 'Addrange';
function  Removerange(rset: p_range; rmin: ULong; rmax: ULong): Integer; cdecl; external OLLYDBG name 'Removerange';

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// NESTED DATA //////////////////////////////////
const
  // General item types related to nested data.
  ND_LEVELMASK   = $000000FF;               // Mask to extract nesting level
  ND_OPENTOP     = $00000100;               // Range is open on the top
  ND_OPENBOTTOM  = $00000200;               // Range is open on the bottom
  ND_NESTHILITE  = $00000400;               // Highlighted bracket
  ND_NESTGRAY    = $00000800;               // Grayed bracket
  // Types specific to loop data t_loopnest:
  ND_MOREVARS    = $00010000;               // List of loop variables overflowed

  MAXNEST        = 32;                      // Limit of displayed nesting levels

type
  p_nesthdr = ^t_nesthdr;                   // Header of nested data range
  t_nesthdr = packed record
    addr0: ULong;                           // First address occupied by range
    addr1: ULong;                           // Last occupied address (included!)
    _type: ULong;                           // Level and user-defined type, TY_xxx
    aprev: ULong;                           // First address of previous range
  end;

  NDDEST = procedure(nesthdr: p_nesthdr); cdecl;

  p_nested = ^t_nested;                     // Descriptor of nested data
  t_nested = packed record
    n: Integer;                             // Actual number of elements
    nmax: Integer;                          // Maximal number of elements
    itemsize: ULong;                        // Size of single element
    data: Pointer;                          // Ordered nested data
    version: ULong;                         // Changes on each modification
    destfunc: NDDEST;                       // Destructor function or NULL
  end;

procedure Destroynesteddata(nd: p_nested); cdecl; external OLLYDBG name 'Destroynesteddata';
function  Createnesteddata(nd: p_nested; itemsize: ULong; nexp: Integer;
            destfunc: NDDEST): Integer; cdecl; external OLLYDBG name 'Createnesteddata';
function  Addnesteddata(nd: p_nested; item: Pointer): Pointer; cdecl; external OLLYDBG name 'Addnesteddata';
procedure Deletenestedrange(nd: p_nested; addr0: ULong; addr1: ULong); cdecl; external OLLYDBG name 'Deletenestedrange';
function  Getnestingpattern(nd: p_nested; addr: ULong; pat: PWChar;
            npat: Integer; mask: UChar; showentry: Integer; isend: PInteger): Integer; cdecl; external OLLYDBG name 'Getnestingpattern';
function  Getnestingdepth(nd: p_nested; addr: ULong): Integer; cdecl; external OLLYDBG name 'Getnestingdepth';
function  Findnesteddata(nd: p_nested; addr: ULong; level: Integer): Pointer; cdecl; external OLLYDBG name 'Findnesteddata';

function  Nesteddatatoudd(nd: p_nested; base: ULong; datasize: PULong): Pointer; cdecl; external OLLYDBG name 'Nesteddatatoudd';
function  Uddtonesteddata(nd: p_nested; data: Pointer; base: ULong; size: ULong): Integer; cdecl; external OLLYDBG name 'Uddtonesteddata';


////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// MODULES ////////////////////////////////////
const
  SHT_MERGENEXT  = $00000001;               // Merge section with the next
  NCALLMOD       = 24;                      // Max number of saved called modules

  // .NET stream identifiers. Don't change the order and the values of the
  // first three items (NS_STRINGS, NS_GUID and NS_BLOB)!
  NS_STRINGS     = 0;                       // Stream with ASCII strings
  NS_GUID        = 1;                       // Stream with GUIDs
  NS_BLOB        = 2;                       // Data referenced by MetaData
  NS_US          = 3;                       // Stream with UNICODE strings
  NS_META        = 4;                       // Stream with MetaData tables

  NETSTREAM      = 5;                       // Number of default .NET streams

  // Indices of .NET MetaData tables.
  MDT_MODULE     = 0;                       // Module table
  MDT_TYPEREF    = 1;                       // TypeRef table
  MDT_TYPEDEF    = 2;                       // TypeDef table
  MDT_FIELDPTR   = 3;                       // FieldPtr table
  MDT_FIELD      = 4;                       // Field table
  MDT_METHODPTR  = 5;                       // MethodPtr table
  MDT_METHOD     = 6;                       // MethodDef table
  MDT_PARAMPTR   = 7;                       // ParamPtr table
  MDT_PARAM      = 8;                       // Param table
  MDT_INTERFACE  = 9;                       // InterfaceImpl table
  MDT_MEMBERREF  = 10;                      // MemberRef table
  MDT_CONSTANT   = 11;                      // Constant table
  MDT_CUSTATTR   = 12;                      // CustomAttribute table
  MDT_MARSHAL    = 13;                      // FieldMarshal table
  MDT_DECLSEC    = 14;                      // DeclSecurity table
  MDT_CLASSLAY   = 15;                      // ClassLayout table
  MDT_FIELDLAY   = 16;                      // FieldLayout table
  MDT_SIGNATURE  = 17;                      // StandAloneSig table
  MDT_EVENTMAP   = 18;                      // EventMap table
  MDT_EVENTPTR   = 19;                      // EventPtr table
  MDT_EVENT      = 20;                      // Event table
  MDT_PROPMAP    = 21;                      // PropertyMap table
  MDT_PROPPTR    = 22;                      // PropertyPtr table
  MDT_PROPERTY   = 23;                      // Property table
  MDT_METHSEM    = 24;                      // MethodSemantics table
  MDT_METHIMPL   = 25;                      // MethodImpl table
  MDT_MODREF     = 26;                      // ModuleRef table
  MDT_TYPESPEC   = 27;                      // TypeSpec table
  MDT_IMPLMAP    = 28;                      // ImplMap table
  MDT_RVA        = 29;                      // FieldRVA table
  MDT_ENCLOG     = 30;                      // ENCLog table
  MDT_ENCMAP     = 31;                      // ENCMap table
  MDT_ASSEMBLY   = 32;                      // Assembly table
  MDT_ASMPROC    = 33;                      // AssemblyProcessor table
  MDT_ASMOS      = 34;                      // AssemblyOS table
  MDT_ASMREF     = 35;                      // AssemblyRef table
  MDT_REFPROC    = 36;                      // AssemblyRefProcessor table
  MDT_REFOS      = 37;                      // AssemblyRefOS table
  MDT_FILE       = 38;                      // File table
  MDT_EXPORT     = 39;                      // ExportedType table
  MDT_RESOURCE   = 40;                      // ManifestResource table
  MDT_NESTED     = 41;                      // NestedClass table
  MDT_GENPARM    = 42;                      // GenericParam table
  MDT_METHSPEC   = 43;                      // MethodSpec table
  MDT_CONSTR     = 44;                      // GenericParamConstraint table
  MDT_UNUSED     = 63;                      // Used only in midx[]

  MDTCOUNT       = 64;                      // Number of .NET MetaData tables

type
  p_secthdr = ^t_secthdr;                   // Extract from IMAGE_SECTION_HEADER
  t_secthdr = packed record
    sectname: array[0..11] of WChar;        // Null-terminated section name
    base: ULong;                            // Address of section in memory
    size: ULong;                            // Size of section loaded into memory
    _type: ULong;                           // Set of SHT_xxx
    fileoffset: ULong;                      // Offset of section in file
    rawsize: ULong;                         // Size of section in file
    characteristics: ULong;                 // Set of IMAGE_SCN_xxx
  end;

  p_premod = ^t_premod;                     // Preliminary module descriptor
  t_premod = packed record
    base: ULong;                            // Base address of the module
    size: ULong;                            // Size of module or 1
    _type: ULong;                           // Service information, TY_xxx+MOD_xxx
    entry: ULong;                           // Address of <ModuleEntryPoint> or 0
    path: array[0..MAXPATH-1] of WChar;     // Full name of the module
  end;

  p_netstream = ^t_netstream;               // Location of default .NET stream
  t_netstream = packed record
    base: ULong;                            // Base address in memory
    size: ULong;                            // Stream size, bytes
  end;

  p_metadata = ^t_metadata;                 // Descriptor of .NET MetaData table
  t_metadata = packed record
    base: ULong;                            // Location in memory or NULL if absent
    rowcount: ULong;                        // Number of rows or 0 if absent
    rowsize: ULong;                         // Size of single row, bytes, or 0
    nameoffs: UShort;                       // Offset of name field
    namesize: UShort;                       // Size of name or 0 if absent
  end;

  p_module = ^t_module;                     // Descriptor of executable module
  t_module = packed record
    base: ULong;                            // Base address of module
    size: ULong;                            // Size of memory occupied by module
    _type: ULong;                           // Service information, TY_xxx+MOD_xxx
    modname: array[0..SHORTNAME-1] of WChar;// Short name of the module
    path: array[0..MAXPATH-1] of WChar;     // Full name of the module
    version: array[0..TEXTLEN-1] of WChar;  // Version of executable file
    fixupbase: ULong;                       // Base of image in executable file
    codebase: ULong;                        // Base address of module code block
    codesize: ULong;                        // Size of module code block
    entry: ULong;                           // Address of <ModuleEntryPoint> or 0
    sfxentry: ULong;                        // Address of SFX-packed entry or 0
    winmain: ULong;                         // Address of WinMain or 0
    database: ULong;                        // Base address of module data block
    edatabase: ULong;                       // Base address of export data table
    edatasize: ULong;                       // Size of export data table
    idatatable: ULong;                      // Base address of import data table
    iatbase: ULong;                         // Base of Import Address Table
    iatsize: ULong;                         // Size of IAT
    relocbase: ULong;                       // Base address of relocation table
    relocsize: ULong;                       // Size of relocation table
    resbase: ULong;                         // Base address of resources
    ressize: ULong;                         // Size of resources
    tlsbase: ULong;                         // Base address of TLS directory table
    tlssize: ULong;                         // Size of TLS directory table
    tlscallback: ULong;                     // Address of first TLS callback or 0
    netentry: ULong;                        // .NET entry (MOD_NETAPP only)
    clibase: ULong;                         // .NET CLI header base (MOD_NETAPP)
    clisize: ULong;                         // .NET CLI header base (MOD_NETAPP)
    netstr: array[0..NETSTREAM-1] of t_netstream; // Locations of default .NET streams
    metadata: array[0..MDTCOUNT-1] of t_metadata; // Descriptors of .NET MetaData tables
    sfxbase: ULong;                         // Base of memory block with SFX
    sfxsize: ULong;                         // Size of memory block with SFX
    rawhdrsize: ULong;                      // Size of PE header in file
    memhdrsize: ULong;                      // Size of PE header in memory
    nsect: Integer;                         // Number of sections in the module
    sect: p_secthdr;                        // Extract from section headers
    nfixup: Integer;                        // Number of 32-bit fixups
    fixup: PULong;                          // Array of 32-bit fixups
    jumps: t_jmpdata;                       // Jumps and calls from this module
    loopnest: t_nested;                     // Loop brackets
    argnest: t_nested;                      // Call argument brackets
    predict: t_simple;                      // Predicted ESP, EBP & results (sd_pred)
    strings: t_sorted;                      // Resource strings (t_string)
    saveudd: Integer;                       // UDD-relevant data is changed
    ncallmod: Integer;                      // No. of called modules (max. NCALLMOD)
    callmod: array[0..NCALLMOD-1, 0..SHORTNAME-1] of WChar;// List of called modules
  end;

  // Keep t_aqueue identical with the header of t_module!
  p_aqueue = ^t_aqueue;                     // Descriptor of module to be analysed
  t_aqueue = packed record
    base: ULong;                            // Base address of module
    size: ULong;                            // Size of memory occupied by module
    _type: ULong;                           // Service information, TY_xxx+MOD_xxx
  end;

function  Findmodule(addr: ULong): p_module; cdecl; external OLLYDBG name 'Findmodule';
function  Findmodulebyname(shortname: PWChar): p_module; cdecl; external OLLYDBG name 'Findmodulebyname';
function  Findmainmodule: p_module; cdecl; external OLLYDBG name 'Findmainmodule';
function  Issystem(addr: ULong): Integer; cdecl; external OLLYDBG name 'Issystem';
function  Findfixup(pmod: p_module; addr: ULong): PULong; cdecl; external OLLYDBG name 'Findfixup';
function  Findfileoffset(pmod: p_module; addr: ULong): ULong; cdecl; external OLLYDBG name 'Findfileoffset';
function  Decoderange(s: PWChar; addr: ULong; size: ULong): Integer; cdecl; external OLLYDBG name 'Decoderange';
function  Getexeversion(path: PWChar; version: PWChar): Integer; cdecl; external OLLYDBG name 'Getexeversion';
function  Getexportfrommemory(addr: ULong; s: PWChar): Integer; cdecl; external OLLYDBG name 'Getexportfrommemory';
function  FindaddressW(name: PWChar; pmod: p_module;
            addr: PULong; errtxt: PWChar): Integer; cdecl; external OLLYDBG name 'FindaddressW';


////////////////////////////////////////////////////////////////////////////////
////////////////////////// LIST OF DEBUGGEE'S WINDOWS //////////////////////////

type
  p_window = ^t_window;                     // Description of window
  t_window = packed record
    hwnd: ULong;                            // Window's handle
    dummy: ULong;                           // Must be 1
    _type: ULong;                           // type of window, TY_xxx+WN_xxx
    parenthw: ULong;                        // Handle of parent or 0
    winproc: ULong;                         // Address of WinProc or 0
    threadid: ULong;                        // ID of the owning thread
    exstyle: ULong;                         // Extended style
    style: ULong;                           // Style
    id: ULong;                              // Identifier
    classproc: ULong;                       // Address of default (class) WinProc
    windowrect: TRECT;                      // Window position, screen coordinates
    clientrect: TRECT;                      // Client position, screen coordinates
    child: Integer;                         // Index of next child
    sibling: Integer;                       // Index of next sibling
    byparent: Integer;                      // Index when sorted by parent
    level: Integer;                         // Level in genealogy (0: topmost)
    title: array[0..TEXTLEN-1] of WChar;    // Window's title or text
    classname: array[0..TEXTLEN-1] of WChar;// Class name
    tree: array[0..MAXNEST-1] of WChar;     // Tree display
  end;


////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// NAMELIST WINDOWS ///////////////////////////////
const
  // Types of action in WM_USER_NAMES broadcasts (parameter wp).
  NA_FIND        = 0;                       // Check if namelist is already open
  NA_UPDATE      = 1;                       // Update namelist
  NA_CLOSE       = 2;                       // Close namelist
  NA_CLOSEALL    = 3;                       // Close all namelists

type
  p_namecast = ^t_namecast;                 // Structure passed on broadcast
  t_namecast = packed record
    base: ULong;                            // Module base, 0 - list of all names
    table: p_table;                         // Filled when broadcast stops
  end;

  p_namelist = ^t_namelist;                 // Element of namelist sorted data
  t_namelist = packed record
    addr: ULong;                            // Base address of the entry
    size: ULong;                            // Size of the entry, always 1
    _type: ULong;                           // type & addr extension, TY_xxx+NL_xxx
  end;


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// RESOURCES ///////////////////////////////////

type
  p_string = ^t_string;                     // Descriptor of resource string
  t_string = packed record
    id: ULong;                              // Identifier associated with the string
    dummy: ULong;                           // Always 1
    addr: ULong;                            // Address of string in memory
    count: ULong;                           // String size, UNICODE characters!
    language: Integer;                      // Language, one of LANG_xxx
  end;

function  Getmodulestring(pm: p_module; id: ULong; s: PWChar): Integer; cdecl; external OLLYDBG name 'Getmodulestring';


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// UDD FILES ///////////////////////////////////
const
  SAVEMAGIC      = $FEDCBA98;               // Indicator of savearea validity

// Attention, for the sake of the compatibility between the different OllyDbg
// versions, never, ever change existing elements, only add new!
type
  p_savearea = ^t_savearea;
  t_savearea = packed record
    magic: ULong;                           // Validity marker, must be SAVEMAGIC
    dumpstr: array[0..SHORTNAME-1] of WChar;// Last structure decoding in dump
  end;


////////////////////////////////////////////////////////////////////////////////
//////////////////////////// THREADS AND REGISTERS /////////////////////////////
const
  NREG           = 8;                       // Number of registers (of any type)
  NSEG           = 6;                       // Number of valid segment registers
  NHARD          = 4;                       // Number of hardware breakpoints

  // Event ignoring list.
  IGNO_INT3      = $00000001;               // Ignore INT3 breakpoint
  IGNO_ACCESS    = $00000002;               // Ignore memory access violation
  IGNO_HW        = $00000004;               // Ignore hardware breakpoint

  // Register displaying mode.
  RDM_MODE       = $0000000F;               // Mask to extract display mode
    RDM_FPU      = $00000000;               // Decode FPU registers as floats
    RDM_MMX      = $00000001;               // Decode FPU registers as MMX
    RDM_3DN      = $00000002;               // Decode FPU registers as 3DNow!
    RDM_DBG      = $00000003;               // Decode debug registers instead of FPU
  RDM_SSEMODE    = $000000F0;               // Mask to extract SSE decoding mode
    RDM_SSEI32   = $00000000;               // Decode SSE as 4x32-bit hex numbers
    RDM_SSEF32   = $00000010;               // Decode SSE as 4x32-bit floats
    RDM_SSEF64   = $00000020;               // Decode SSE as 2x64-bit floats

  // Status of registers.
  RV_MODIFIED    = $00000001;               // Update CONTEXT before run
  RV_USERMOD     = $00000002;               // Registers modified by user
  RV_SSEVALID    = $00000004;               // Whether SSE registers are valid
  RV_SSEMOD      = $00000008;               // Update SSE registers before run
  RV_ERRVALID    = $00000010;               // Whether last thread error is valid
  RV_ERRMOD      = $00000020;               // Update last thread error before run
  RV_MEMVALID    = $00000040;               // Whether memory fields are valid
  RV_DBGMOD      = $00000080;               // Update debugging registers before run

  // CPU flags.
  FLAG_C         = $00000001;               // Carry flag
  FLAG_P         = $00000004;               // Parity flag
  FLAG_A         = $00000010;               // Auxiliary carry flag
  FLAG_Z         = $00000040;               // Zero flag
  FLAG_S         = $00000080;               // Sign flag
  FLAG_T         = $00000100;               // Single-step trap flag
  FLAG_D         = $00000400;               // Direction flag
  FLAG_O         = $00000800;               // Overflow flag

  // Attention, number of memory fields is limited by the run trace!
  NMEMFIELD      = 2;                       // Number of memory fields in t_reg

type
  PContext = ^TContext;               // Fix wrong declared of CONTEXT struct in Delphi 7-2010
  _CONTEXT = record
    ContextFlags: DWORD;
    Dr0: DWORD;
    Dr1: DWORD;
    Dr2: DWORD;
    Dr3: DWORD;
    Dr6: DWORD;
    Dr7: DWORD;
    FloatSave: TFloatingSaveArea;
    SegGs: DWORD;
    SegFs: DWORD;
    SegEs: DWORD;
    SegDs: DWORD;
    Edi: DWORD;
    Esi: DWORD;
    Ebx: DWORD;
    Edx: DWORD;
    Ecx: DWORD;
    Eax: DWORD;
    Ebp: DWORD;
    Eip: DWORD;
    SegCs: DWORD;
    EFlags: DWORD;
    Esp: DWORD;
    SegSs: DWORD;
    extRegs: array[0..511] of Byte;
  end;
  TContext = _CONTEXT;
  CONTEXT = _CONTEXT;

  p_memfield = ^t_memfield;                 // Descriptor of memory field
  t_memfield = packed record
    addr: ULong;                            // Address of data in memory
    size: ULong;                            // Data size (0 - no data)
    data: array[0..15] of UChar;            // Data
  end;

  // Thread registers.
  p_reg = ^t_reg;                           // Excerpt from context
  t_reg = packed record
    status: ULong;                          // Status of registers, set of RV_xxx
    threadid: ULong;                        // ID of thread that owns registers
    ip: ULong;                              // Instruction pointer (EIP)
    r: array[0..NREG-1] of ULong;           // EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI     //NREG = 8;
    flags: ULong;                           // Flags
    s: array[0..NSEG-1] of ULong;           // Segment registers ES,CS,SS,DS,FS,GS //NSEG = 6;
    base: array[0..NSEG-1] of ULong;        // Segment bases
    limit: array[0..NSEG-1] of ULong;       // Segment limits
    big: array[0..NSEG-1] of UChar;         // Default size (0-16, 1-32 bit)
    dummy: array[0..1] of UChar;            // Reserved, used for data alignment
    top: Integer;                           // Index of top-of-stack
    f: array[0..NREG-1] of Extended;        // Float registers, f[top] - top of stack
    tag: array[0..NREG-1] of UChar;         // Float tags (0x3 - empty register)
    fst: ULong;                             // FPU status word
    fcw: ULong;                             // FPU control word
    ferrseg: ULong;                         // Selector of last detected FPU error
    feroffs: ULong;                         // Offset of last detected FPU error
    dr: array[0..NREG-1] of ULong;          // Debug registers
    lasterror: ULong;                       // Last thread error or 0xFFFFFFFF
    ssereg: array[0..NREG-1,0..15] of UChar;  // SSE registers
    mxcsr: ULong;                           // SSE control and status register
    mem: array[0..NMEMFIELD-1] of t_memfield; // Known memory fields from run trace
  end;

  p_thread = ^t_thread;                     // Information about active threads
  t_thread = packed record
    threadid: ULong;                        // Thread identifier
    dummy: ULong;                           // Always 1
    _type: ULong;                           // Service information, TY_xxx+THR_xxx
    ordinal: Integer;                       // Thread's ordinal number (1-based)
    name: array[0..SHORTNAME-1] of WChar;   // Short name of the thread
    thread: THandle;                        // Thread handle, for OllyDbg only!
    tib: ULong;                             // Thread Information Block
    entry: ULong;                           // Thread entry point
    context: CONTEXT;                       // Actual context of the thread
    reg: t_reg;                             // Actual contents of registers
    regvalid: Integer;                      // Whether reg and context are valid
    oldreg: t_reg;                          // Previous contents of registers
    oldregvalid: Integer;                   // Whether oldreg is valid
    suspendrun: Integer;                    // Suspended for run (0 or 1)
    suspendcount: Integer;                  // Temporarily suspended (0..inf)
    suspenduser: Integer;                   // Suspended by user (0 or 1)
    trapset: Integer;                       // Single-step trap set by OllyDbg
    trapincontext: Integer;                 // Trap is catched in exception context
    rtprotocoladdr: ULong;                  // Address of destination to protocol
    ignoreonce: Integer;                    // Ignore list, IGNO_xxx
    drvalid: Integer;                       // Contents of dr is valid
    dr: array[0..NREG-1] of ULong;          // Expected state of DR0..3,7
    hwmasked: Integer;                      // Temporarily masked hardware breaks
    hwreported: Integer;                    // Reported breakpoint expressions
    // Thread-related information gathered by Updatethreaddata().
    hw: HWND;                               // One of windows owned by thread
    usertime: ULong;                        // Time in user mode, 100u units or -1
    systime: ULong;                         // Time in system mode, 100u units or -1
    // Thread-related information gathered by Listmemory().
    stacktop: ULong;                        // Top of thread's stack
    stackbottom: ULong;                     // Bottom of thread's stack
  end;

function  Findthread(threadid: ULong): p_thread; cdecl; external OLLYDBG name 'Findthread';
function  Findthreadbyordinal(ordinal: Integer): p_thread; cdecl; external OLLYDBG name 'Findthreadbyordinal';
function  Threadregisters(threadid: ULong): p_reg; cdecl; external OLLYDBG name 'Threadregisters';
function  Decodethreadname(s: PWChar; threadid: ULong; mode: Integer): Integer; cdecl; external OLLYDBG name 'Decodethreadname';
procedure Registermodifiedbyuser(pthr: p_thread); cdecl; external OLLYDBG name 'Registermodifiedbyuser';


////////////////////////////////////////////////////////////////////////////////
////////////////////////// ASSEMBLER AND DISASSEMBLER //////////////////////////
const
  MAXCMDSIZE     = 16;                      // Maximal length of valid 80x86 command
  MAXSEQSIZE     = 256;                     // Maximal length of command sequence
  INT3           = $CC;                     // Code of 1-byte INT3 breakpoint
  NOP            = $90;                     // Code of 1-byte NOP command
  NOPERAND       = 4;                       // Maximal allowed number of operands
  NEGLIMIT       = -16384;                  // Limit to decode offsets as negative
  DECLIMIT       = 65536;                   // Limit to decode Integers as decimal

  // Registers.
  REG_UNDEF      = -1;                      // Codes of general purpose registers
  REG_EAX        = 0;
  REG_ECX        = 1;
  REG_EDX        = 2;
  REG_EBX        = 3;
  REG_ESP        = 4;
  REG_EBP        = 5;
  REG_ESI        = 6;
  REG_EDI        = 7;

  REG_BYTE       = $80;                     // Flag used in switch analysis

  REG_AL         = 0;                       // Symbolic indices of 8-bit registers
  REG_CL         = 1;
  REG_DL         = 2;
  REG_BL         = 3;
  REG_AH         = 4;
  REG_CH         = 5;
  REG_DH         = 6;
  REG_BH         = 7;

  SEG_UNDEF      = -1;                      // Codes of segment/selector registers
  SEG_ES         = 0;
  SEG_CS         = 1;
  SEG_SS         = 2;
  SEG_DS         = 3;
  SEG_FS         = 4;
  SEG_GS         = 5;

  // Pseudoregisters, used in search for assembler commands.
  REG_R8         = NREG;                    // 8-bit pseudoregister R8
  REG_R16        = NREG;                    // 16-bit pseudoregister R16
  REG_R32        = NREG;                    // 32-bit pseudoregister R32
  REG_ANY        = NREG;                    // Pseudoregister FPUREG, MMXREG etc.
  SEG_ANY        = NREG;                    // Segment pseudoregister SEG
  REG_RA         = NREG + 1;                // 32-bit semi-defined pseudoregister RA
  REG_RB         = NREG + 2;                // 32-bit semi-defined pseudoregister RB
  NPSEUDO        = NREG + 3;                // Total count of resisters & pseudoregs

  D_NONE         = $00000000;               // No special features
  // General type of command, only one is allowed.
  D_CMDTYPE      = $0000001F;               // Mask to extract type of command
    D_CMD        = $00000000;               // Ordinary (none of listed below)
    D_MOV        = $00000001;               // Move to or from Integer register
    D_MOVC       = $00000002;               // Conditional move to Integer register
    D_SETC       = $00000003;               // Conditional set Integer register
    D_TEST       = $00000004;               // Used to test data (CMP, TEST, AND...)
    D_STRING     = $00000005;               // String command with REPxxx prefix
    D_JMP        = $00000006;               // Unconditional near jump
    D_JMPFAR     = $00000007;               // Unconditional far jump
    D_JMC        = $00000008;               // Conditional jump on flags
    D_JMCX       = $00000009;               // Conditional jump on (E)CX (and flags)
    D_PUSH       = $0000000A;               // PUSH exactly 1 (d)word of data
    D_POP        = $0000000B;               // POP exactly 1 (d)word of data
    D_CALL       = $0000000C;               // Plain near call
    D_CALLFAR    = $0000000D;               // Far call
    D_INT        = $0000000E;               // Interrupt
    D_RET        = $0000000F;               // Plain near return from call
    D_RETFAR     = $00000010;               // Far return or IRET
    D_FPU        = $00000011;               // FPU command
    D_MMX        = $00000012;               // MMX instruction, incl. SSE extensions
    D_3DNOW      = $00000013;               // 3DNow! instruction
    D_SSE        = $00000014;               // SSE, SSE2, SSE3 etc. instruction
    D_IO         = $00000015;               // Accesses I/O ports
    D_SYS        = $00000016;               // Legal but useful in system code only
    D_PRIVILEGED = $00000017;               // Privileged (non-Ring3) command
    D_DATA       = $0000001C;               // Data recognized by Analyser
    D_PSEUDO     = $0000001D;               // Pseudocommand, for search models only
    D_PREFIX     = $0000001E;               // Standalone prefix
    D_BAD        = $0000001F;               // Bad or unrecognized command
  // Additional parts of the command.
  D_SIZE01       = $00000020;               // Bit 0x01 in last cmd is data size
  D_POSTBYTE     = $00000040;               // Command continues in postbyte
  // For string commands, either Long or short form can be selected.
  D_LONGFORM     = $00000080;               // Long form of string command
  // Decoding of some commands depends on data or address size.
  D_SIZEMASK     = $00000F00;               // Mask for data/address size dependence
    D_DATA16     = $00000100;               // Requires 16-bit data size
    D_DATA32     = $00000200;               // Requires 32-bit data size
    D_ADDR16     = $00000400;               // Requires 16-bit address size
    D_ADDR32     = $00000800;               // Requires 32-bit address size
  // Prefixes that command may, must or must not possess.
  D_MUSTMASK     = $0000F000;               // Mask for fixed set of prefixes
    D_NOMUST     = $00000000;               // No obligatory prefixes (default)
    D_MUST66     = $00001000;               // (SSE) Requires 66, no F2 or F3
    D_MUSTF2     = $00002000;               // (SSE) Requires F2, no 66 or F3
    D_MUSTF3     = $00003000;               // (SSE) Requires F3, no 66 or F2
    D_MUSTNONE   = $00004000;               // (MMX,SSE) Requires no 66, F2 or F3
    D_NEEDF2     = $00005000;               // (SSE) Requires F2, no F3
    D_NEEDF3     = $00006000;               // (SSE) Requires F3, no F2
    D_NOREP      = $00007000;               // Must not include F2 or F3
    D_MUSTREP    = $00008000;               // Must include F3 (REP)
    D_MUSTREPE   = $00009000;               // Must include F3 (REPE)
    D_MUSTREPNE  = $0000A000;               // Must include F2 (REPNE)
  D_LOCKABLE     = $00010000;               // Allows for F0 (LOCK, memory only)
  D_BHINT        = $00020000;               // Allows for branch hints (2E, 3E)
  // Decoding of some commands with ModRM-SIB depends whether register or memory.
  D_MEMORY       = $00040000;               // Mod field must indicate memory
  D_REGISTER     = $00080000;               // Mod field must indicate register
  // Side effects caused by command.
  D_FLAGMASK     = $00700000;               // Mask to extract modified flags
    D_NOFLAGS    = $00000000;               // Flags S,Z,P,O,C remain unchanged
    D_ALLFLAGS   = $00100000;               // Modifies flags S,Z,P,O,C
    D_FLAGZ      = $00200000;               // Modifies flag Z only
    D_FLAGC      = $00300000;               // Modifies flag C only
    D_FLAGSCO    = $00400000;               // Modifies flag C and O only
    D_FLAGD      = $00500000;               // Modifies flag D only
    D_FLAGSZPC   = $00600000;               // Modifies flags Z, P and C only (FPU)
    D_NOCFLAG    = $00700000;               // S,Z,P,O modified, C unaffected
  D_FPUMASK      = $01800000;               // Mask for effects on FPU stack
    D_FPUSAME    = $00000000;               // Doesn't rotate FPU stack (default)
    D_FPUPOP     = $00800000;               // Pops FPU stack
    D_FPUPOP2    = $01000000;               // Pops FPU stack twice
    D_FPUPUSH    = $01800000;               // Pushes FPU stack
  D_CHGESP       = $02000000;               // Command indirectly modifies ESP
  // Command features.
  D_HLADIR       = $04000000;               // Nonstandard order of operands in HLA
  D_WILDCARD     = $08000000;               // Mnemonics contains W/D wildcard ('*')
  D_COND         = $10000000;               // Conditional (action depends on flags)
  D_USESCARRY    = $20000000;               // Uses Carry flag
  D_USEMASK      = $C0000000;               // Mask to detect unusual commands
    D_RARE       = $40000000;               // Rare or obsolete in Win32 apps
    D_SUSPICIOUS = $80000000;               // Suspicious command
    D_UNDOC      = $C0000000;               // Undocumented command

  // Extension of D_xxx.
  DX_ZEROMASK    = $00000003;               // How to decode FLAGS.Z flag
    DX_JE        = $00000001;               // JE, JNE instead of JZ, JNZ
    DX_JZ        = $00000002;               // JZ, JNZ instead of JE, JNE
  DX_CARRYMASK   = $0000000C;               // How to decode FLAGS.C flag
    DX_JB        = $00000004;               // JAE, JB instead of JC, JNC
    DX_JC        = $00000008;               // JC, JNC instead of JAE, JB
  DX_WONKYTRAP   = $00000100;               // Don't single-step this command

  // type of operand, only one isallowed.
  B_ARGMASK      = $000000FF;               // Mask to extract type of argument
    B_NONE       = $00000000;               // Operand absent
    B_AL         = $00000001;               // Register AL
    B_AH         = $00000002;               // Register AH
    B_AX         = $00000003;               // Register AX
    B_CL         = $00000004;               // Register CL
    B_CX         = $00000005;               // Register CX
    B_DX         = $00000006;               // Register DX
    B_DXPORT     = $00000007;               // Register DX as I/O port address
    B_EAX        = $00000008;               // Register EAX
    B_EBX        = $00000009;               // Register EBX
    B_ECX        = $0000000A;               // Register ECX
    B_EDX        = $0000000B;               // Register EDX
    B_ACC        = $0000000C;               // Accumulator (AL/AX/EAX)
    B_STRCNT     = $0000000D;               // Register CX or ECX as REPxx counter
    B_DXEDX      = $0000000E;               // Register DX or EDX in DIV/MUL
    B_BPEBP      = $0000000F;               // Register BP or EBP in ENTER/LEAVE
    B_REG        = $00000010;               // 8/16/32-bit register in Reg
    B_REG16      = $00000011;               // 16-bit register in Reg
    B_REG32      = $00000012;               // 32-bit register in Reg
    B_REGCMD     = $00000013;               // 16/32-bit register in last cmd byte
    B_REGCMD8    = $00000014;               // 8-bit register in last cmd byte
    B_ANYREG     = $00000015;               // Reg field is unused, any allowed
    B_INT        = $00000016;               // 8/16/32-bit register/memory in ModRM
    B_INT8       = $00000017;               // 8-bit register/memory in ModRM
    B_INT16      = $00000018;               // 16-bit register/memory in ModRM
    B_INT32      = $00000019;               // 32-bit register/memory in ModRM
    B_INT1632    = $0000001A;               // 16/32-bit register/memory in ModRM
    B_INT64      = $0000001B;               // 64-bit Integer in ModRM, memory only
    B_INT128     = $0000001C;               // 128-bit Integer in ModRM, memory only
    B_IMMINT     = $0000001D;               // 8/16/32-bit int at immediate addr
    B_INTPAIR    = $0000001E;               // Two signed 16/32 in ModRM, memory only
    B_SEGOFFS    = $0000001F;               // 16:16/16:32 absolute address in memory
    B_STRDEST    = $00000020;               // 8/16/32-bit string dest, [ES:(E)DI]
    B_STRDEST8   = $00000021;               // 8-bit string destination, [ES:(E)DI]
    B_STRSRC     = $00000022;               // 8/16/32-bit string source, [(E)SI]
    B_STRSRC8    = $00000023;               // 8-bit string source, [(E)SI]
    B_XLATMEM    = $00000024;               // 8-bit memory in XLAT, [(E)BX+AL]
    B_EAXMEM     = $00000025;               // Reference to memory addressed by [EAX]
    B_LONGDATA   = $00000026;               // Long data in ModRM, mem only
    B_ANYMEM     = $00000027;               // Reference to memory, data unimportant
    B_STKTOP     = $00000028;               // 16/32-bit int top of stack
    B_STKTOPFAR  = $00000029;               // Top of stack (16:16/16:32 far addr)
    B_STKTOPEFL  = $0000002A;               // 16/32-bit flags on top of stack
    B_STKTOPA    = $0000002B;               // 16/32-bit top of stack all registers
    B_PUSH       = $0000002C;               // 16/32-bit int push to stack
    B_PUSHRET    = $0000002D;               // 16/32-bit push of return address
    B_PUSHRETF   = $0000002E;               // 16:16/16:32-bit push of far retaddr
    B_PUSHA      = $0000002F;               // 16/32-bit push all registers
    B_EBPMEM     = $00000030;               // 16/32-bit int at [EBP]
    B_SEG        = $00000031;               // Segment register in Reg
    B_SEGNOCS    = $00000032;               // Segment register in Reg, but not CS
    B_SEGCS      = $00000033;               // Segment register CS
    B_SEGDS      = $00000034;               // Segment register DS
    B_SEGES      = $00000035;               // Segment register ES
    B_SEGFS      = $00000036;               // Segment register FS
    B_SEGGS      = $00000037;               // Segment register GS
    B_SEGSS      = $00000038;               // Segment register SS
    B_ST         = $00000039;               // 80-bit FPU register in last cmd byte
    B_ST0        = $0000003A;               // 80-bit FPU register ST0
    B_ST1        = $0000003B;               // 80-bit FPU register ST1
    B_FLOAT32    = $0000003C;               // 32-bit float in ModRM, memory only
    B_FLOAT64    = $0000003D;               // 64-bit float in ModRM, memory only
    B_FLOAT80    = $0000003E;               // 80-bit float in ModRM, memory only
    B_BCD        = $0000003F;               // 80-bit BCD in ModRM, memory only
    B_MREG8x8    = $00000040;               // MMX register as 8 8-bit Integers
    B_MMX8x8     = $00000041;               // MMX reg/memory as 8 8-bit Integers
    B_MMX8x8DI   = $00000042;               // MMX 8 8-bit Integers at [DS:(E)DI]
    B_MREG16x4   = $00000043;               // MMX register as 4 16-bit Integers
    B_MMX16x4    = $00000044;               // MMX reg/memory as 4 16-bit Integers
    B_MREG32x2   = $00000045;               // MMX register as 2 32-bit Integers
    B_MMX32x2    = $00000046;               // MMX reg/memory as 2 32-bit Integers
    B_MREG64     = $00000047;               // MMX register as 1 64-bit Integer
    B_MMX64      = $00000048;               // MMX reg/memory as 1 64-bit Integer
    B_3DREG      = $00000049;               // 3DNow! register as 2 32-bit floats
    B_3DNOW      = $0000004A;               // 3DNow! reg/memory as 2 32-bit floats
    B_XMM0I32x4  = $0000004B;               // XMM0 as 4 32-bit Integers
    B_XMM0I64x2  = $0000004C;               // XMM0 as 2 64-bit Integers
    B_XMM0I8x16  = $0000004D;               // XMM0 as 16 8-bit Integers
    B_SREGF32x4  = $0000004E;               // SSE register as 4 32-bit floats
    B_SREGF32L   = $0000004F;               // Low 32-bit float in SSE register
    B_SREGF32x2L = $00000050;               // Low 2 32-bit floats in SSE register
    B_SSEF32x4   = $00000051;               // SSE reg/memory as 4 32-bit floats
    B_SSEF32L    = $00000052;               // Low 32-bit float in SSE reg/memory
    B_SSEF32x2L  = $00000053;               // Low 2 32-bit floats in SSE reg/memory
    B_SREGF64x2  = $00000054;               // SSE register as 2 64-bit floats
    B_SREGF64L   = $00000055;               // Low 64-bit float in SSE register
    B_SSEF64x2   = $00000056;               // SSE reg/memory as 2 64-bit floats
    B_SSEF64L    = $00000057;               // Low 64-bit float in SSE reg/memory
    B_SREGI8x16  = $00000058;               // SSE register as 16 8-bit sigints
    B_SSEI8x16   = $00000059;               // SSE reg/memory as 16 8-bit sigints
    B_SSEI8x16DI = $0000005A;               // SSE 16 8-bit sigints at [DS:(E)DI]
    B_SSEI8x8L   = $0000005B;               // Low 8 8-bit ints in SSE reg/memory
    B_SSEI8x4L   = $0000005C;               // Low 4 8-bit ints in SSE reg/memory
    B_SSEI8x2L   = $0000005D;               // Low 2 8-bit ints in SSE reg/memory
    B_SREGI16x8  = $0000005E;               // SSE register as 8 16-bit sigints
    B_SSEI16x8   = $0000005F;               // SSE reg/memory as 8 16-bit sigints
    B_SSEI16x4L  = $00000060;               // Low 4 16-bit ints in SSE reg/memory
    B_SSEI16x2L  = $00000061;               // Low 2 16-bit ints in SSE reg/memory
    B_SREGI32x4  = $00000062;               // SSE register as 4 32-bit sigints
    B_SREGI32L   = $00000063;               // Low 32-bit sigint in SSE register
    B_SREGI32x2L = $00000064;               // Low 2 32-bit sigints in SSE register
    B_SSEI32x4   = $00000065;               // SSE reg/memory as 4 32-bit sigints
    B_SSEI32x2L  = $00000066;               // Low 2 32-bit sigints in SSE reg/memory
    B_SREGI64x2  = $00000067;               // SSE register as 2 64-bit sigints
    B_SSEI64x2   = $00000068;               // SSE reg/memory as 2 64-bit sigints
    B_SREGI64L   = $00000069;               // Low 64-bit sigint in SSE register
    B_EFL        = $0000006A;               // Flags register EFL
    B_FLAGS8     = $0000006B;               // Flags (low byte)
    B_OFFSET     = $0000006C;               // 16/32 const offset from next command
    B_BYTEOFFS   = $0000006D;               // 8-bit sxt const offset from next cmd
    B_FARCONST   = $0000006E;               // 16:16/16:32 absolute address constant
    B_DESCR      = $0000006F;               // 16:32 descriptor in ModRM
    B_1          = $00000070;               // Immediate constant 1
    B_CONST8     = $00000071;               // Immediate 8-bit constant
    B_CONST8_2   = $00000072;               // Immediate 8-bit const, second in cmd
    B_CONST16    = $00000073;               // Immediate 16-bit constant
    B_CONST      = $00000074;               // Immediate 8/16/32-bit constant
    B_CONSTL     = $00000075;               // Immediate 16/32-bit constant
    B_SXTCONST   = $00000076;               // Immediate 8-bit sign-extended to size
    B_CR         = $00000077;               // Control register in Reg
    B_CR0        = $00000078;               // Control register CR0
    B_DR         = $00000079;               // Debug register in Reg
  // type modifiers, used for interpretation of contents, only one is allowed.
  B_MODMASK      = $000F0000;               // Mask to extract type modifier
    B_NONSPEC    = $00000000;               // Non-specific operand
    B_UNSIGNED   = $00010000;               // Decode as unsigned decimal
    B_SIGNED     = $00020000;               // Decode as signed decimal
    B_BINARY     = $00030000;               // Decode as binary (full hex) data
    B_BITCNT     = $00040000;               // Bit count
    B_SHIFTCNT   = $00050000;               // Shift count
    B_COUNT      = $00060000;               // General-purpose count
    B_NOADDR     = $00070000;               // Not an address
    B_JMPCALL    = $00080000;               // Near jump/call/return destination
    B_JMPCALLFAR = $00090000;               // Far jump/call/return destination
    B_STACKINC   = $000A0000;               // Unsigned stack increment/decrement
    B_PORT       = $000B0000;               // I/O port
  // Validity markers.
  B_MEMORY       = $00100000;               // Memory only, reg version different
  B_REGISTER     = $00200000;               // Register only, mem version different
  B_MEMONLY      = $00400000;               // Warn if operand in register
  B_REGONLY      = $00800000;               // Warn if operand in memory
  B_32BITONLY    = $01000000;               // Warn if 16-bit operand
  B_NOESP        = $02000000;               // ESP is not allowed
  // Miscellaneous options.
  B_SHOWSIZE     = $08000000;               // Always show argument size in disasm
  B_CHG          = $10000000;               // Changed, old contents is not used
  B_UPD          = $20000000;               // Modified using old contents
  B_PSEUDO       = $40000000;               // Pseoudooperand, not in assembler cmd
  B_NOSEG        = $80000000;               // Don't add offset of selector
  // Analysis data. Note that DEC_PBODY== DEC_PROC|DEC_PEND; this allows for
  // automatical merging of overlapping procedures. Also note that DEC_NET is
  // followed, if necessary, by a sequen    ce of DEC_NEXTDATA and not DEC_NEXTCODE!
  DEC_TYPEMASK   = $1F;                     // type of analyzed byte
    DEC_UNKNOWN  = $00;                     // Not analyzed, treat as command
    DEC_NEXTCODE = $01;                     // Next byte of command
    DEC_NEXTDATA = $02;                     // Next byte of data
    DEC_FILLDATA = $03;                     // Not recognized, treat as byte data
    DEC_INT      = $04;                     // First byte of Integer
    DEC_SWITCH   = $05;                     // First byte of switch item or count
    DEC_DATA     = $06;                     // First byte of Integer data
    DEC_DB       = $07;                     // First byte of byte string
    DEC_DUMP     = $08;                     // First byte of byte string with dump
    DEC_ASCII    = $09;                     // First byte of ASCII string
    DEC_ASCCNT   = $0A;                     // Next chunk of ASCII string
    DEC_UNICODE  = $0B;                     // First byte of UNICODE string
    DEC_UNICNT   = $0C;                     // Next chunk of UNICODE string
    DEC_FLOAT    = $0D;                     // First byte of floating number
    DEC_GUID     = $10;                     // First byte of GUID
    DEC_NETCMD   = $18;                     // First byte of .NET (CIL) command
    DEC_JMPNET   = $19;                     // First byte of .NET at jump destination
    DEC_CALLNET  = $1A;                     // First byte of .NET at call destination
    DEC_COMMAND  = $1C;                     // First byte of ordinary command
    DEC_JMPDEST  = $1D;                     // First byte of cmd at jump destination
    DEC_CALLDEST = $1E;                     // First byte of cmd at call destination
    DEC_FILLING  = $1F;                     // Command used to fill gaps
  DEC_PROCMASK   = $60;                     // Procedure analysis
    DEC_NOPROC   = $00;                     // Outside the procedure
    DEC_PROC     = $20;                     // Start of procedure
    DEC_PEND     = $40;                     // End of procedure
    DEC_PBODY    = $60;                     // Body of procedure
  DEC_TRACED     = $80;                     // Hit when traced
  // Full type of predicted data.
  PST_GENMASK    = $FFFFFC00;               // Mask for ESP generation
    PST_GENINC   = $00000400;               // Increment of ESP generation
  PST_UNCERT     = $00000200;               // Uncertain, probably modified by call
  PST_NONSTACK   = $00000100;               // Not a stack, internal use only
  PST_REL        = $00000080;               // Fixup/reladdr counter of constant
  PST_BASE       = $0000007F;               // Mask for basical description
    PST_SPEC     = $00000040;               // Special contents, type in PST_GENMASK
    PST_VALID    = $00000020;               // Contents valid
    PST_ADDR     = $00000010;               // Contents is in memory
    PST_ORIG     = $00000008;               // Based on reg contents at entry point
    PST_OMASK    = $00000007;               // Mask to extract original register

  // Types of special contents when PST_    SPEC is set.
  PSS_SPECMASK   = PST_GENMASK;             // Mask for type of special contents
  PSS_SEHPTR     = $00000400;               // Pointer to SEH chain

  NSTACK         = 12;                      // Number of predicted stack entries
  NSTKMOD        = 24;                      // Max no. of predicted stack mod addr
  NMEM           = 2;                       // Number of predicted memory locations

function IS_REAL(r: Integer): Boolean;      // Checks for real register
function IS_PSEUDO(r: Integer): Boolean;    // Checks for pseudoregister (undefined)
function IS_SEMI(r: Integer): Boolean;      // Checks for semi-defined register

type
  p_modrm = ^t_modrm;                       // ModRM decoding
  t_modrm = packed record
    size: ULong;                            // Total size with SIB and disp, bytes
    psib: p_modrm;                          // Pointer to SIB table or NULL
    dispsize: ULong;                        // Size of displacement or 0 if none
    features: ULong;                        // Operand features, set of OP_xxx
    reg: Integer;                           // Register index or REG_UNDEF
    defseg: Integer;                        // Default selector (SEG_xxx)
    scale: array[0..NREG-1] of UChar;       // Scales of registers in memory address
    aregs: ULong;                           // List of registers used in address
    basereg: Integer;                       // Register used as base or REG_UNDEF
    ardec: array[0..SHORTNAME-1] of WChar;  // Register part of address, INTEL fmt
    aratt: array[0..SHORTNAME-1] of WChar;  // Register part of address, AT&T fmt
  end;

  p_stack = ^t_stack;
  t_stack = record
    soffset: LongInt;                       // Offset of data on stack (signed!)
    sstate: ULong;                          // State of stack data, set of PST_xxx
    sconst: ULong;                          // Constant related to stack data
  end;

  p_mem = ^t_mem;
  t_mem = record
    maddr: ULong;                           // Address of doubleword variable
    mstate: ULong;                          // State of memory, set of PST_xxx
    mconst: ULong;                          // Constant related to memory data
  end;

  p_predict = ^t_predict;                   // Prediction of execution
  t_predict = packed record
    addr: ULong;                            // Predicted EIP or NULL if uncertain
    one: ULong;                             // Must be 1
    _type: ULong;                           // type, TY_xxx/PR_xxx
    flagsmeaning: UShort;                   // Set of DX_ZEROMASK|DX_CARRYMASK
    rstate: array[0..NREG-1] of ULong;      // State of register, set of PST_xxx
    rconst: array[0..NREG-1] of ULong;      // Constant related to register
    jmpstate: ULong;                        // State of EIP after jump or return
    jmpconst: ULong;                        // Constant related to jump or return
    espatpushbp: ULong;                     // Offset of ESP at PUSH EBP
    nstack: Integer;                        // Number of valid stack entries
    stack: array[0..NSTACK-1] of t_stack;
    nstkmod: Integer;                       // Number of valid stkmod addresses
    stkmod: array[0..NSTKMOD-1] of ULong;   // Addresses of stack modifications
    nmem: Integer;                          // Number of valid memory entries
    mem: array[0..NMEM-1] of t_mem;
    resstate: ULong;                        // State of result of command execution
    resconst: ULong;                        // Constant related to result
  end;

  p_callpredict = ^t_callpredict;           // Simplified prediction
  t_callpredict = packed record
    addr: ULong;                            // Predicted EIP or NULL if uncertain
    one: ULong;                             // Must be 1
    _type: ULong;                           // type of prediction, TY_xxx/PR_xxx
    eaxstate: ULong;                        // State of EAX, set of PST_xxx
    eaxconst: ULong;                        // Constant related to EAX
    nstkmod: Integer;                       // Number of valid stkmod addresses
    stkmod: array[0..NSTKMOD-1] of ULong;   // Addresses of stack modifications
    resstate: ULong;                        // State of result of command execution
    resconst: ULong;                        // Constant related to result
  end;

const
  // Location of operand, only one bit i    s allowed.
  OP_SOMEREG     = $000000FF;               // Mask for any kind of register
    OP_REGISTER  = $00000001;               // Operand is a general-purpose register
    OP_SEGREG    = $00000002;               // Operand is a segment register
    OP_FPUREG    = $00000004;               // Operand is a FPU register
    OP_MMXREG    = $00000008;               // Operand is a MMX register
    OP_3DNOWREG  = $00000010;               // Operand is a 3DNow! register
    OP_SSEREG    = $00000020;               // Operand is a SSE register
    OP_CREG      = $00000040;               // Operand is a control register
    OP_DREG      = $00000080;               // Operand is a debug register
  OP_MEMORY      = $00000100;               // Operand is in memory
  OP_CONST       = $00000200;               // Operand is an immediate constant
  OP_PORT        = $00000400;               // Operand is an I/O port
  // Additional operand properties.
  OP_INVALID     = $00001000;               // Invalid operand, like reg in mem-only
  OP_PSEUDO      = $00002000;               // Pseudooperand (not in mnenonics)
  OP_MOD         = $00004000;               // Command may change/update operand
  OP_MODREG      = $00008000;               // Memory, but modifies reg (POP,MOVSD)
  OP_REL         = $00010000;               // Relative or fixuped const or address
  OP_IMPORT      = $00020000;               // Value imported from different module
  OP_SELECTOR    = $00040000;               // Includes immediate selector
  // Additional properties of memory add    ress.
  OP_INDEXED     = $00080000;               // Memory address contains registers
  OP_OPCONST     = $00100000;               // Memory address contains constant
  OP_ADDR16      = $00200000;               // 16-bit memory address
  OP_ADDR32      = $00400000;               // Explicit 32-bit memory address
  // Value of operand.
  OP_OFFSOK      = $00800000;               // Offset to selector valid
  OP_ADDROK      = $01000000;               // Address valid
  OP_VALUEOK     = $02000000;               // Value (max. 16 bytes) valid
  OP_PREDADDR    = $04000000;               // Address predicted, not actual
  OP_PREDVAL     = $08000000;               // Value predicted, not actual
  OP_RTLOGMEM    = $10000000;               // Memory contents got from run trace
    OP_ACTVALID  = $20000000;               // Actual value is valid
  // Pseudooperands, used in assembler s    earch models only.
  OP_ANYMEM      = $40000000;               // Any memory location
  OP_ANY         = $80000000;               // Any operand

type
  t_operand_union = packed record
    case BYTE of
      0: (u: ULong);                        // Value of operand (Integer form)
      1: (s: LongInt);                      // Value of operand (signed form)
      2: (value: array[0..15] of UChar);    // Value of operand (general form)
  end;

  p_operand = ^t_operand;                   // Description of disassembled operand
  t_operand = packed record
    // Description of operand.
    features: ULong;                        // Operand features, set of OP_xxx
    arg: ULong;                             // Operand type, set of B_xxx
    optype: Integer;                        // DEC_INT, DEC_FLOAT or DEC_UNKNOWN
    opsize: Integer;                        // Total size of data, bytes
    granularity: Integer;                   // Size of element (opsize exc. MMX/SSE)
    reg: Integer;                           // REG_xxx (also ESP in POP) or REG_UNDEF
    zuses: ULong;                           // List of used regs (not in address!)
    modifies: ULong;                        // List of modified regs (not in addr!)
    // Description of memory address.
    seg: Integer;                           // Selector (SEG_xxx)
    scale: array[0..NREG-1] of UChar;       // Scales of registers in memory address
    aregs: ULong;                           // List of registers used in address
    opconst: ULong;                         // Constant or const part of address
    // Value of operand.
    offset: ULong;                          // Offset to selector (usually addr)
    selector: ULong;                        // Immediate selector in far jump/call
    addr: ULong;                            // Address of operand in memory
    operandType: t_operand_union;
    actual: array[0..15] of UChar;          // Actual memory (if OP_ACTVALID)
    // Textual decoding.
    text: array[0..TEXTLEN-1] of WChar;     // Operand, decoded to text
    comment: array[0..TEXTLEN-1] of WChar;  // Commented address and contents
  end;

const
  // Prefix list.
  PF_SEGMASK     = $0000003F;               // Mask for segment override prefixes
    PF_ES        = $00000001;               // 0x26, ES segment override
    PF_CS        = $00000002;               // 0x2E, CS segment override
    PF_SS        = $00000004;               // 0x36, SS segment override
    PF_DS        = $00000008;               // 0x3E, DS segment override
    PF_FS        = $00000010;               // 0x64, FS segment override
    PF_GS        = $00000020;               // 0x65, GS segment override
  PF_DSIZE       = $00000040;               // 0x66, data size override
  PF_ASIZE       = $00000080;               // 0x67, address size override
  PF_LOCK        = $00000100;               // 0xF0, bus lock
  PF_REPMASK     = $00000600;               // Mask for repeat prefixes
    PF_REPNE     = $00000200;               // 0xF2, REPNE prefix
    PF_REP       = $00000400;               // 0xF3, REP/REPE prefix
  PF_BYTE        = $00000800;               // Size bit in command, used in cmdexec
  PF_MUSTMASK    = D_MUSTMASK;              // Necessary prefixes, used in t_asmmod
  PF_66          = PF_DSIZE;                // Alternative names for SSE prefixes
  PF_F2          = PF_REPNE;
  PF_F3          = PF_REP;
  PF_HINT        = PF_CS or PF_DS;          // Alternative names for branch hints
    PF_NOTTAKEN  = PF_CS;
    PF_TAKEN     = PF_DS;

  // Disassembling errors.
  DAE_NOERR      = $00000000;               // No error
  DAE_BADCMD     = $00000001;               // Unrecognized command
  DAE_CROSS      = $00000002;               // Command crosses end of memory block
  DAE_MEMORY     = $00000004;               // Register where only memory allowed
  DAE_REGISTER   = $00000008;               // Memory where only register allowed
  DAE_LOCK       = $00000010;               // LOCK prefix is not allowed
  DAE_BADSEG     = $00000020;               // Invalid segment register
  DAE_SAMEPREF   = $00000040;               // Two prefixes from the same group
  DAE_MANYPREF   = $00000080;               // More than 4 prefixes
  DAE_BADCR      = $00000100;               // Invalid CR register
  DAE_INTERN     = $00000200;               // Internal error

  // Disassembling warnings.
  DAW_DATASIZE   = $00000001;               // Superfluous data size prefix
  DAW_ADDRSIZE   = $00000002;               // Superfluous address size prefix
  DAW_SEGPREFIX  = $00000004;               // Superfluous segment override prefix
  DAW_REPPREFIX  = $00000008;               // Superfluous REPxx prefix
  DAW_DEFSEG     = $00000010;               // Segment prefix coincides with default
  DAW_JMP16      = $00000020;               // 16-bit jump, call or return
  DAW_FARADDR    = $00000040;               // Far jump or call
  DAW_SEGMOD     = $00000080;               // Modifies segment register
  DAW_PRIV       = $00000100;               // Privileged command
  DAW_IO         = $00000200;               // I/O command
  DAW_SHIFT      = $00000400;               // Shift out of range 1..31
  DAW_LOCK       = $00000800;               // Command with valid LOCK prefix
  DAW_STACK      = $00001000;               // Unaligned stack operation
  DAW_NOESP      = $00002000;               // Suspicious use of stack pointer
  DAW_RARE       = $00004000;               // Rare, seldom used command
  DAW_NONCLASS   = $00008000;               // Non-standard or non-documented code
  DAW_INTERRUPT  = $00010000;               // Interrupt command

  // Conditions of conditional commands.
  DAF_NOCOND     = $00000000;               // Unconditional command
  DAF_TRUE       = $00000001;               // Condition is true
  DAF_FALSE      = $00000002;               // Condition is false
  DAF_ANYCOND    = $00000003;               // Condition is not predictable

type
  p_disasm = ^t_disasm;                     // Disassembled command
  t_disasm = packed record
    // In the case that DA_HILITE flag is set, fill these members before calling
    // Disasm(). Parameter hilitereg has priority over hiliteindex.
    hilitereg: ULong;                       // One of OP_SOMEREG if reg highlighting
    hiregindex: Integer;                    // Index of register to highlight
    hiliteindex: Integer;                   // Index of highlighting scheme (0: none)
    // Starting from this point, no need to initialize the members of t_disasm.
    ip: ULong;                              // Address of first command byte
    size: ULong;                            // Full length of command, bytes
    cmdtype: ULong;                         // type of command, D_xxx
    exttype: ULong;                         // More features, set of DX_xxx
    prefixes: ULong;                        // List of prefixes, set of PF_xxx
    nprefix: ULong;                         // Number of prefixes, including SSE2
    memfixup: ULong;                        // Offset of first 4-byte fixup or -1
    immfixup: ULong;                        // Offset of second 4-byte fixup or -1
    errors: Integer;                        // Set of DAE_xxx
    warnings: Integer;                      // Set of DAW_xxx
    // Note that used registers are those which contents is necessary to create
    // result. Modified registers are those which value is changed. For example,
    // command MOV EAX,[EBX+ECX] uses EBX and ECX and modifies EAX. Command
    // ADD ESI,EDI uses ESI and EDI and modifies ESI.
    zuses: ULong;                           // List of used registers
    modifies: ULong;                        // List of modified registers
    // Useful shortcuts.
    condition: Integer;                     // Condition, one of DAF_xxx
    jmpaddr: ULong;                         // Jump/call destination or 0
    memconst: ULong;                        // Constant in memory address or 0
    stackinc: ULong;                        // Data size in ENTER/RETN/RETF
    // Operands.
    op: array[0..NOPERAND-1] of t_operand;  // Operands
    // Textual decoding.
    dump: array[0..TEXTLEN-1] of WChar;     // Hex dump of the command
    result: array[0..TEXTLEN-1] of WChar;   // Fully decoded command as text
    mask: array[0..TEXTLEN-1] of UChar;     // Mask to highlight result
    maskvalid: Integer;                     // Mask corresponds to result
    comment: array[0..TEXTLEN-1] of WChar;  // Comment that applies to whole command
  end;

  p_opinfo = ^t_opinfo;                     // Operand in t_cmdinfo
  t_opinfo = packed record
    features: ULong;                        // Operand features, set of OP_xxx
    arg: ULong;                             // Operand type, set of B_xxx
    opsize: Integer;                        // Total size of data, bytes
    reg: Integer;                           // REG_xxx (also ESP in POP) or REG_UNDEF
    seg: Integer;                           // Selector (SEG_xxx)
    scale: array[0..NREG-1] of UChar;       // Scales of registers in memory address
    opconst: ULong;                         // Constant or const part of address
  end;

  p_cmdinfo = ^t_cmdinfo;                   // Information on command
  t_cmdinfo = packed record
    ip: ULong;                              // Address of first command byte
    size: ULong;                            // Full length of command, bytes
    cmdtype: ULong;                         // type of command, D_xxx
    prefixes: ULong;                        // List of prefixes, set of PF_xxx
    nprefix: ULong;                         // Number of prefixes, including SSE2
    memfixup: ULong;                        // Offset of first 4-byte fixup or -1
    immfixup: ULong;                        // Offset of second 4-byte fixup or -1
    errors: Integer;                        // Set of DAE_xxx
    jmpaddr: ULong;                         // Jump/call destination or 0
    stackinc: ULong;                        // Data size in ENTER/RETN/RETF
    op: array[0..NOPERAND-1] of t_opinfo;   // Operands
  end;

  // ATTENTION, when making any changes to this structure, apply them to the
  // file Cmdemul.asm, too!
  p_emu = ^t_emu;                           // Parameters passed to emulation routine
  t_emu = packed record
    operand: array[0..NOPERAND-1] of ULong; // I/O: Operands
    opsize: ULong;                          // IN:  Size of operands
    memaddr: ULong;                         // OUT: Save address, or 0 if none
    memsize: ULong;                         // OUT: Save size (1, 2 or 4 bytes)
    memdata: ULong;                         // OUT: Data to save
  end;

type
  TRACEFUNC = procedure(pul1: PULong; pul2: PULong; predict: p_predict; disasm: p_disasm); cdecl;
  EMUFUNC   = procedure(emu: p_emu; reg: p_reg); cdecl;

  p_bincmd = ^t_bincmd;                     // Description of 80x86 command
  t_bincmd = packed record
    name: PWChar;                           // Symbolic name for this command
    cmdtype: ULong;                         // Command's features, set of D_xxx
    exttype: ULong;                         // More features, set of DX_xxx
    length: ULong;                          // Length of main code (before ModRM/SIB)
    mask: ULong;                            // Mask for first 4 bytes of the command
    code: ULong;                            // Compare masked bytes with this
    postbyte: ULong;                        // Postbyte
    arg: array[0..NOPERAND-1] of ULong;     // Types of arguments, set of B_xxx
    trace: TRACEFUNC;                       // Result prediction function
    emu: EMUFUNC;                           // Command emulation function
  end;

const
  AMF_SAMEORDER  = $01;                     // Same order of index registers in addr
  AMF_ANYSEG     = $02;                     // Command has undefined segment prefix
  AMF_POSTBYTE   = $04;                     // Includes postbyte
  AMF_IMPRECISE  = $08;                     // Command is imprecise (search only)
  AMF_ANYSIZE    = $10;                     // Any operand size is acceptable
  AMF_NOSMALL    = $20;                     // 16-bit address is not allowed
  AMF_UNDOC      = $40;                     // Undocumented command
  AMF_NEWCMD     = $80;                     // Marks new command in multiline

  AMP_REGISTER   = $01;                     // Operand is a register
  AMP_MEMORY     = $02;                     // Operand is a memory location
  AMP_CONST      = $04;                     // Operand is a constant
  AMP_IMPRECISE  = $08;                     // Constant is imprecise
  AMP_ANYMEM     = $10;                     // Any memory operand is acceptable
  AMP_ANYOP      = $20;                     // Any operand is acceptable

type
  p_modop = ^t_modop;                       // Operand in assembler model
  t_modop = packed record
    features: UChar;                        // Operand features, set of AMp_xxx
    reg: UChar;                             // (Pseudo)register operand
    scale: array[0..NPSEUDO-1] of UChar;    // Scales of (pseudo)registers in address
    opconst: ULong;                         // Constant or const part of address
  end;

  // Assembler command model.
  p_asmmod = ^t_asmmod;                     // Description of assembled command
  t_asmmod = packed record
    code: array[0..MAXCMDSIZE-1] of UChar;  // Binary code
    mask: array[0..MAXCMDSIZE-1] of UChar;  // Mask for binary code (0: bit ignored)
    prefixes: ULong;                        // List of prefixes, set of PF_xxx
    ncode: UChar;                           // Length of code w/o prefixes, bytes
    features: UChar;                        // Code features, set of AMF_xxx
    postbyte: UChar;                        // Postbyte (if AMF_POSTBYTE set)
    noperand: UChar;                        // Number of operands (no pseudooperands)
    op: array[0..NOPERAND-1] of t_modop;    // Description of operands
  end;

  p_asmlist = ^t_asmlist;                   // Descriptor of the sequence of models
  t_asmlist = packed record
    pasm: p_asmmod;                         // Pointer to the start of the sequence
    length: Integer;                        // Length of the sequence, models
    comment: array[0..TEXTLEN-1] of WChar;  // Comment to the sequence
  end;

const
  DA_TEXT        = $00000001;               // Decode command to text and comment
  DA_HILITE      = $00000002;               // Use syntax highlighting (set t_disasm)
  DA_OPCOMM      = $00000004;               // Comment operands
  DA_DUMP        = $00000008;               // Dump command to hexadecimal text
  DA_MEMORY      = $00000010;               // OK to read memory and use labels
  DA_NOIMPORT    = $00000020;               // When reading memory, hold the imports
  DA_RTLOGMEM    = $00000040;               // Use memory saved by run trace
  DA_NOSTACKP    = $00000080;               // Hide "Stack" prefix in comments
  DA_STEPINTO    = $00000100;               // Enter CALL when predicting registers
  DA_SHOWARG     = $00000200;               // Use predict if address ESP/EBP-based
  DA_NOPSEUDO    = $00000400;               // Skip pseudooperands
  DA_FORHELP     = $00000800;               // Decode operands for command help

  USEDECODE: PUChar = PUChar(1);            // Request to get decoding automatically

function  Byteregtodwordreg(bytereg: Integer): Integer; cdecl; external OLLYDBG name 'Byteregtodwordreg';
function  Printfloat4(s: PWChar; f: Single): Integer; cdecl; external OLLYDBG name 'Printfloat4';
function  Printfloat8(s: PWChar; d: Double): Integer; cdecl; external OLLYDBG name 'Printfloat8';
function  Printfloat10(s: PWChar; ext: Extended): Integer; cdecl; external OLLYDBG name 'Printfloat10';
function  Printmmx(s: PWChar; data: PUChar): Integer; cdecl; external OLLYDBG name 'Printmmx';
function  Commentcharacter(s: PWChar; c: Integer; mode: Integer): Integer; cdecl; external OLLYDBG name 'Commentcharacter';
function  Nameoffloat(s: PWChar; data: PUChar; size: ULong ): Integer; cdecl; external OLLYDBG name 'Nameoffloat';
function  Disasm(cmd: PUChar; cmdsize: ULong; ip: ULong; dec: PUChar;
            da: p_disasm; mode: Integer; reg: p_reg;
            predict: p_predict): ULong cdecl; external OLLYDBG name 'Disasm';
function  Cmdinfo(cmd: PUChar; cmdsize: ULong; cmdip: ULong;
            ci: p_cmdinfo; cmdmode: Integer; cmdreg: p_reg): ULong; cdecl; external OLLYDBG name 'Cmdinfo';
function  Disassembleforward(copy: PUChar; base: ULong; size: ULong;
            ip: ULong; n: ULong; decode: PUChar): ULong; cdecl; external OLLYDBG name 'Disassembleforward';
function  Disassembleback(copy: PUChar; base: ULong; size: ULong;
            ip: ULong; n: ULong; decode: PUChar): ULong; cdecl; external OLLYDBG name 'Disassembleback';
function  Checkcondition(code: Integer; flags: ULong): Integer; cdecl; external OLLYDBG name 'Checkcondition';
function  Setcondition(code: Integer; flags: ULong): ULong; cdecl; external OLLYDBG name 'Setcondition';

const
  AM_ALLOWBAD    = $00000001;               // Allow bad or undocumented commands
  AM_IMPRECISE   = $00000002;               // Generate imprecise (search) forms
    AM_MULTI     = $00000004;               // Multiple commands are allowed

  AM_SEARCH      = AM_IMPRECISE;

function  Assembleallforms(src: PWChar; ip: ULong; model: p_asmmod;
            maxmodel: Integer; mode: Integer; errtxt: PWChar): Integer; cdecl; external OLLYDBG name 'Assembleallforms';
function  Assemble(src: PWChar; ip: ULong; buf: PUChar; nbuf: ULong; mode: Integer;
            errtxt: PWChar): ULong; cdecl; external OLLYDBG name 'Assemble';


////////////////////////////////////////////////////////////////////////////////
////////////////////////////// .NET DISASSEMBLER ///////////////////////////////
const
  // CIL command types.
  N_CMDTYPE      = $0000001F;               // Mask to extract type of command
    N_CMD        = $00000000;               // Ordinary (none of listed below)
    N_JMP        = $00000001;               // Unconditional jump
    N_JMC        = $00000002;               // Conditional jump
    N_CALL       = $00000003;               // Call
    N_RET        = $00000004;               // Return (also from exception)
    N_SWITCH     = $00000005;               // Switch, followed by N cases
    N_PREFIX     = $00000006;               // Prefix, not a standalone command
    N_DATA       = $0000001E;               // Command is decoded as data
    N_BAD        = $0000001F;               // Bad command
  N_POPMASK      = $00000F00;               // Mask to extract number of pops
    N_POP0       = $00000000;               // Pops no arguments (default)
    N_POP1       = $00000100;               // Pops 1 argument from stack
    N_POP2       = $00000200;               // Pops 2 arguments from stack
    N_POP3       = $00000300;               // Pops 3 arguments from stack
    N_POPX       = $00000F00;               // Pops variable arguments from stack
  N_PUSHMASK     = $0000F000;
    N_PUSH0      = $00000000;               // Pushes no data (default)
    N_PUSH1      = $00001000;               // Pushes 1 argument into stack
    N_PUSH2      = $00002000;               // Pushes 2 arguments into stack
    N_PUSHX      = $0000F000;               // Pushes 0 or 1 argument into stack

  // CIL explicit operand types.
  A_ARGMASK      = $000000FF;               // Mask to extract type of argument
    A_NONE       = $00000000;               // No operand
    A_OFFSET     = $00000001;               // 32-bit offset from next command
    A_BYTEOFFS   = $00000002;               // 8-bit offset from next command
    A_METHOD     = $00000003;               // 32-bit method descriptor
    A_SIGNATURE  = $00000004;               // 32-bit signature of call types
    A_TYPE       = $00000005;               // 32-bit type descriptor
    A_FIELD      = $00000006;               // 32-bit field descriptor
    A_STRING     = $00000007;               // 32-bit string descriptor
    A_TOKEN      = $00000008;               // 32-bit token descriptor
    A_INDEX1     = $00000009;               // 8-bit immediate index constant
    A_INDEX2     = $0000000A;               // 16-bit immediate index constant
    A_SWCOUNT    = $0000000B;               // 32-bit immediate switch count
    A_INT1S      = $0000000C;               // 8-bit immediate signed Integer const
    A_INT4       = $0000000D;               // 32-bit immediate Integer constant
    A_INT8       = $0000000E;               // 64-bit immediate Integer constant
    A_FLOAT4     = $0000000F;               // 32-bit immediate float constant
    A_FLOAT8     = $00000010;               // 64-bit immediate float constant
    A_NOLIST     = $00000011;               // 8-bit list following no. prefix
    A_ALIGN      = $00000012;               // 8-bit alignment following unaligned.

type
  p_netasm = ^t_netasm;                     // Disassembled .NET CIL command
  t_netasm = packed record
    ip: ULong;                              // Address of first command byte
    size: ULong;                            // Full length of command, bytes
    cmdtype: ULong;                         // type of command, N_xxx
    cmdsize: ULong;                         // Size of command, bytes
    opsize: ULong;                          // Size of operand, bytes, or 0 if none
    nswitch: ULong;                         // Size of following switch table, dwords
    jmpaddr: ULong;                         // Single jump/call destination or 0
    descriptor: ULong;                      // Descriptor (xx)xxxxxx or 0
    dataaddr: ULong;                        // Address of pointed object/data or 0
    errors: Integer;                        // Set of DAE_xxx
    // Description of operand.
    optype: ULong;                          // Operand type, set of A_xxx
    optext: array[0..TEXTLEN-1] of WChar;   // Operand, decoded to text
    // Textual decoding.
    dump: array[0..TEXTLEN-1] of WChar;     // Hex dump of the command
    result: array[0..TEXTLEN-1] of WChar;   // Fully decoded command as text
    comment: array[0..TEXTLEN-1] of WChar;  // Comment that applies to whole command
  end;

function  Ndisasm(cmd: PUChar; size: ULong; ip: ULong; da: p_netasm;
            mode: Integer; pmod: p_module): ULong; cdecl; external OLLYDBG name 'Ndisasm';


////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// ANALYSIS ///////////////////////////////////
const
  MAXARG         = 256;                     // Maximal sane number of arguments

  NGUESS         = 7;                       // Max number of args in type analysis

  AA_MANUAL      = 0;                       // No automatical analysis
  AA_MAINONLY    = 1;                       // Automatically analyse main module
  AA_NONSYS      = 2;                       // Automatically analyse non-sys modules
  AA_ALL         = 3;                       // Automatically analyse all modules

  AO_ISFORMATA   = $01;                     // Argument is probable ASCII format
  AO_SIGFORMATA  = $02;                     // Non-trivial ASCII format
  AO_ISFORMATW   = $04;                     // Argument is probable UNICODE format
  AO_SIGFORMATW  = $08;                     // Non-trivial UNICODE format
  AO_NOTFORMAT   = $10;                     // Argument is not a format
  AO_ISCOUNT     = $20;                     // Argument is count of remaining args
  AO_NOTCOUNT    = $40;                     // Argument is not a count

type
  p_procdata = ^t_procdata;                 // Description of procedure
  t_procdata = packed record
    addr: ULong;                            // Address of entry point
    size: ULong;                            // Size of simple procedure or 1
    _type: ULong;                           // type of procedure, TY_xxx/PD_xxx
    retsize: ULong;                         // Size of return (if PD_RETSIZE)
    localsize: ULong;                       // Size of reserved locals, 0 - unknown
    savedebp: ULong;                        // Offset of cmd after PUSH EBP, 0 - none
    features: ULong;                        // type of known code, RAW_xxx
    generic: array[0..11] of AChar;         // Generic name (without _INTERN_)
    narg: Integer;                          // No. of stack DWORDs (PD_NARG/VARARG)
    nguess: Integer;                        // Number of guessed args (if PD_NGUESS)
    npush: Integer;                         // Number of pushed args (if PD_NPUSH)
    usedarg: Integer;                       // Min. number of accessed arguments
    preserved: UChar;                       // Preserved registers
    argopt: array[0..NGUESS-1] of UChar;    // Guessed argument options, AO_xxx
  end;

  p_argnest= ^t_argnest;                    // Header of call arguments bracket
  t_argnest = packed record
    addr0: ULong;                           // First address occupied by range
    addr1: ULong;                           // Last occupied address (included!)
    _type: ULong;                           // Level and user-defined type, TY_xxx
    aprev: ULong;                           // First address of previous range
  end;

const
  NLOOPVAR       = 4;                       // Max number of loop variables

type
  p_loopvar = ^t_loopvar;
  t_loopvar = packed record
    _type: UChar;                           // Combination of PRED_xxx
    espoffset: LongInt;                     // For locals, offset to original ESP
    increment: LongInt;                     // Increment after loop
  end;

  p_loopnest = ^t_loopnest;                 // Header of loop bracket
  t_loopnest = packed record
    addr0: ULong;                           // First address occupied by range
    addr1: ULong;                           // Last occupied address (included!)
    _type: ULong;                           // Level and user-defined type, TY_xxx
    aprev: ULong;                           // First address of previous range
    eoffs: ULong;                           // Offset of entry point from addr0
    loopvar: array[0..NLOOPVAR-1] of t_loopvar;
  end;

function  Getpackednetint(code: PUChar; size: ULong; value: PULong): ULong; cdecl; external OLLYDBG name 'Getpackednetint';
procedure Removeanalysis(base: ULong; size: ULong; keephittrace: Integer); cdecl; external OLLYDBG name 'Removeanalysis';
function  Maybecommand(addr: ULong; requireanalysis: Integer): Integer; cdecl; external OLLYDBG name 'Maybecommand';


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// STACK WALK //////////////////////////////////
const
  SF_FMUNREL     = $00000001;               // Predicted frame is unreliable
  SF_BPUNREL     = $00000002;               // Predicted EBP is unreliable
  SF_VIRTUAL     = $00000004;               // DBGHELP: EBP is undefined

type

  p_sframe = ^t_sframe;                     // Stack frame descriptor
  t_sframe = packed record
    // Input parameters, fill before call to Findretaddrdata().
    eip: ULong;                             // Address of command that owns frame
    esp: ULong;                             // ESP at EIP
    ebp: ULong;                             // EBP at EIP, or 0 if unknown
    // Parameters used by DBGHELP.DLL, initialize only before the first call.
    firstcall: Integer;                     // First call to Findretaddrdata()
    thread: THandle;                        // Thread handle
    context: CONTEXT;                       // Copy of CONTEXT, fill on first call
    contextvalid: Integer;                  // Whether context contains valid data
    // Output parameters.
    status: ULong;                          // Set of SF_xxx
    oldeip: ULong;                          // Address of CALL or 0 if unknown
    oldesp: ULong;                          // ESP at CALL or 0 if unknown
    oldebp: ULong;                          // EBP at CALL or 0 if unknown
    retpos: ULong;                          // Address of return in stack
    procaddr: ULong;                        // Entry of current function or 0
    // Parameters used by DBGHELP.DLL, don't initialize!
  {$IFDEF STACKFRAME64}                     // Requires <dbghelp.h>
    sf: STACKFRAME64;                       // Stack frame for StackWalk64()
  {$ELSE}
    dummy: array[0..263] of UChar;          // Replaces STACKFRAME64
  {$ENDIF}
  end;

function  Isretaddr(retaddr: ULong; procaddr: PULong): ULong; cdecl; external OLLYDBG name 'Isretaddr';
function  Findretaddrdata(pf: p_sframe; base: ULong; size: ULong): Integer; cdecl; external OLLYDBG name 'Findretaddrdata';


////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// KNOWN FUNCTIONS ////////////////////////////////
const
  NARG           = 24;                      // Max number of arguments in a function

  ADEC_VALID     = $00000001;               // Value valid
  ADEC_PREDICTED = $00000002;               // Value predicted
  ADEC_CHGNAME   = $00000004;               // Allow name change of substituted arg
  ADEC_MARK      = $00000008;               // (out) Important parameter

  // type of argument in the description of function or structure. Note that
  // ARG_STRUCT is allowed only in conjunction with ARG_POINTER.
  ARG_POINTER    = $01;                     // Argument is a pointer
  ARG_BASE       = $06;                     // Mask to extract base type of argument
    ARG_TYPE     = $00;                     // Argument is a type
    ARG_STRUCT   = $02;                     // Argument is a structure
    ARG_DIRECT   = $04;                     // Argument is a direct string
  ARG_OUT        = $08;                     // Pointer to data undefined at call
  ARG_MARK       = $10;                     // Important parameter
  ARG_ELLIPSYS   = $20;                     // Followed by ellipsys
  ARG_VALID      = $40;                     // Must always be set to avoid argx= 0

  ARG_TYPEMASK   = ARG_POINTER or ARG_BASE; // Mask to extract full type

  ARG_PTYPE      = ARG_POINTER or ARG_TYPE; // Pointer to type
  ARG_PSTRUCT    = ARG_POINTER or ARG_STRUCT; // Pointer to structure

  // Bits used to define type of function.
  FN_C           = $00000001;               // Does not remove arguments from stack
  FN_PASCAL      = $00000002;               // Removes arguments from stack on return
  FN_NORETURN    = $00000004;               // Does not return, like ExitProcess()
  FN_VARARG      = $00000008;               // Variable number of arguments
  FN_EAX         = $00000100;               // EAX on return is same as on entry
  FN_ECX         = $00000200;               // ECX on return is same as on entry
  FN_EDX         = $00000400;               // EDX on return is same as on entry
  FN_EBX         = $00000800;               // EBX on return is same as on entry
  FN_ESP         = $00001000;               // ESP on return is same as on entry
  FN_EBP         = $00002000;               // EBP on return is same as on entry
  FN_ESI         = $00004000;               // ESI on return is same as on entry
  FN_EDI         = $00008000;               // EDI on return is same as on entry
  FN_USES_EAX    = $00010000;               // EAX is used as register parameter
  FN_USES_ECX    = $00020000;               // ECX is used as register parameter
  FN_USES_EDX    = $00040000;               // EDX is used as register parameter
  FN_USES_EBX    = $00080000;               // EBX is used as register parameter
  FN_USES_ESP    = $00100000;               // ESP is used as register parameter
  FN_USES_EBP    = $00200000;               // EBP is used as register parameter
  FN_USES_ESI    = $00400000;               // ESI is used as register parameter
  FN_USES_EDI    = $00800000;               // EDI on return is same as on entry

  FN_FUNCTION    = 0;
  FN_STDFUNC     = FN_PASCAL or FN_EBX or FN_EBP or FN_ESI or FN_EDI;
  FN_STDC        = FN_C or FN_EBX or FN_EBP or FN_ESI or FN_EDI;

type
  p_argdec  = ^t_argdec;                    // Descriptor of function argument
  t_argdec = packed record
    mode: ULong;                            // Value descriptor, set of ADEC_xxx
    value: ULong;                           // Value on the stack
    pushaddr: ULong;                        // Address of command that pushed data
    prtype: array[0..SHORTNAME-1] of WChar; // type of argument with ARG_xxx prefix
    name: array[0..TEXTLEN-1] of WChar;     // Decoded name of argument
    text: array[0..TEXTLEN-1] of WChar;     // Decoded value (if valid or predicted)
  end;

  p_strdec = ^t_strdec;                     // Decoded structure item
  t_strdec = packed record
    size: ULong;                            // Item size, bytes
    addr: ULong;                            // Address of the first byte
    value: ULong;                           // Item value, only if size<= 4!
    valuevalid: UChar;                      // Whether value is valid
    dec: UChar;                             // One of DEC_TYPEMASK subfields
    decsize: UChar;                         // Size of decoding element
    reserved: UChar;                        // Reserved for the future
    prtype: array[0..SHORTNAME-1] of WChar; // type of item with ARG_xxx prefix
    name: array[0..TEXTLEN-1] of WChar;     // Name of item
    text: array[0..TEXTLEN-1] of WChar;     // Decoded value
  end;

  p_rawdata = ^t_rawdata;                   // Header of raw data block
  t_rawdata = packed record
    size: ULong;                            // Data size, bytes
    hasmask: ULong;                         // Data is followed by mask
    ufeatures: ULong;                       // Data features
  end;                                      // Data & mask immediately follow header

  t_arg = packed record                     // List of arguments
    features: Integer;                      // Argument features, set of ARG_xxx
    size: Integer;                          // Size of argument on the stack
    name: array[0..TEXTLEN-1] of WChar;     // Name of the argument
    atype: array[0..SHORTNAME-1] of WChar;  // type of the argument
  end;

  p_argloc = ^t_argloc;                      // Information about stack args & locals
  t_argloc = packed record
    fntype: ULong;                          // Calling convention, set of FN_xxx
    retfeatures: Integer;                   // Return features, set of ARG_xxx
    retsize: Integer;                       // Size of returned value
    rettype: array[0..SHORTNAME-1] of WChar;// type of the returned value
    argvalid: Integer;                      // Whether arg[] below is valid
    arg: array[0..NARG-1] of t_arg;
  end;

function  Getconstantbyname(name: PWChar; value: PULong): Integer; cdecl; external OLLYDBG name 'Getconstantbyname';
function  Getconstantbyvalue(groupname: PWChar;
            value: ULong; name: PWChar): Integer; cdecl; external OLLYDBG name 'Getconstantbyvalue';
function  Decodetype(data: ULong; ptype: PWChar; text: PWChar; ntext: Integer): Integer; cdecl; external OLLYDBG name 'Decodetype';
function  Fillcombowithgroup(hw: HWND; groupname: PWChar;
            sortbyname: Integer; select: ULong): Integer; cdecl; external OLLYDBG name 'Fillcombowithgroup';
function  Fillcombowithstruct(hw: HWND; prefix: PWChar; select: PWChar): Integer; cdecl; external OLLYDBG name 'Fillcombowithstruct';
function  Getrawdata(name: PWChar): p_rawdata; cdecl; external OLLYDBG name 'Getrawdata';
function  Substitutehkeyprefix(key: PWChar): Integer; cdecl; external OLLYDBG name 'Substitutehkeyprefix';
function  Decodeknownbyname(name: PWChar; pd: p_procdata;
            adec: p_argdec; rettype: PWChar; nexp: Integer): Integer; cdecl; external OLLYDBG name 'Decodeknownbyname';
function  Decodeknownbyaddr(addr: ULong; pd: p_procdata;
            adec: p_argdec; rettype: PWChar; name: PWChar;
            nexp: Integer; follow: Integer): Integer; cdecl; external OLLYDBG name 'Decodeknownbyaddr';
function  Isnoreturn(addr: ULong): Integer; cdecl; external OLLYDBG name 'Isnoreturn';
function  Decodeargument(pmod: p_module; prtype: PWChar; data: Pointer;
            ndata: Integer; text: PWChar; ntext: Integer; nontriv: PInteger): Integer; cdecl; external OLLYDBG name 'Decodeargument';
function  Getstructureitemcount(name: PWChar; size: PULong): Integer; cdecl; external OLLYDBG name 'Getstructureitemcount';
function  Findstructureitembyoffset(name: PWChar; offset: ULong): Integer; cdecl; external OLLYDBG name 'Findstructureitembyoffset';
function  Decodestructure(name: PWChar; addr: ULong; item0: Integer;
            str: p_strdec; nstr: Integer): Integer; cdecl; external OLLYDBG name 'Decodestructure';
function  Getstructureitemvalue(code: PUChar; ncode: ULong;
            name: PWChar; itemname: PWChar; value: Pointer; nvalue: ULong): ULong; cdecl; external OLLYDBG name 'Getstructureitemvalue';


////////////////////////////////////////////////////////////////////////////////
////////////////////// EXPRESSIONS, WATCHES AND INSPECTORS /////////////////////
const
  NEXPR          = 16;                      // Max. no. of expressions in EMOD_MULTI

  // Mode of expression evaluation.
  EMOD_CHKEXTRA  = $00000001;               // Report extra characters on line
  EMOD_NOVALUE   = $00000002;               // Don't convert data to text
  EMOD_NOMEMORY  = $00000004;               // Don't read debuggee's memory
  EMOD_MULTI     = $00000008;               // Allow multiple expressions

  EXPR_TYPEMASK  = $0F;                     // Mask to extract type of expression
    EXPR_INVALID = $00;                     // Invalid or undefined expression
    EXPR_BYTE    = $01;                     // 8-bit Integer byte
    EXPR_WORD    = $02;                     // 16-bit Integer word
    EXPR_DWORD   = $03;                     // 32-bit Integer doubleword
    EXPR_FLOAT4  = $04;                     // 32-bit floating-point number
    EXPR_FLOAT8  = $05;                     // 64-bit floating-point number
    EXPR_FLOAT10 = $06;                     // 80-bit floating-point number
    EXPR_SEG     = $07;                     // Segment
    EXPR_ASCII   = $08;                     // Pointer to ASCII string
    EXPR_UNICODE = $09;                     // Pointer to UNICODE string
    EXPR_TEXT    = $0A;                     // Immediate UNICODE string
  EXPR_REG       = $10;                     // Origin is register
  EXPR_SIGNED    = $20;                     // Signed Integer
  EXPR_SIGDWORD  = EXPR_DWORD or EXPR_SIGNED;

type
  t_result_union = record
  case BYTE of
    0: (data: array[0..9] of UChar);        // Value as set of bytes
    1: (u: ULong);                          // Value as address or unsigned Integer
    2: (l: LongInt);                        // Value as signed Integer
    3: (f: Extended);                       // Value as 80-bit float
  end;

  p_result = ^t_result;                     // Result of expression's evaluation
  t_result = packed record
    lvaltype: Integer;                      // type of expression, EXPR_xxx
    lvaladdr: ULong;                        // Address of lvalue or NULL
    datatype: Integer;                      // type of data, EXPR_xxx
    repcount: Integer;                      // Repeat count (0..32, 0 means default)
    resultType: t_result_union;
    value: array[0..TEXTLEN-1] of WChar;    // Value decoded to string
  end;

  p_watch  = ^t_watch;                      // Watch descriptor
  t_watch = packed record
    addr: ULong;                            // 0-based watch index
    size: ULong;                            // Reserved, always 1
    _type: ULong;                           // Service information, TY_xxx
    expr: array[0..TEXTLEN-1] of WChar;     // Watch expression
  end;

function  Cexpression(expression: PWChar; cexpr: PUChar; nexpr: Integer;
            explen: PInteger; err: PWChar; mode: ULong): Integer; cdecl; external OLLYDBG name 'Cexpression';
function  Exprcount(cexpr: PUChar): Integer; cdecl; external OLLYDBG name 'Exprcount';
function  Eexpression(result: p_result; expl: PWChar; cexpr: PUChar;
            index: Integer; data: PUChar; base: ULong; size: ULong; threadid: ULong;
            a: ULong; b: ULong; mode: ULong): Integer; cdecl; external OLLYDBG name 'Eexpression';
function  Expression(result: p_result; expression: PWChar; data: PUChar;
            base: ULong; size: ULong; threadid: ULong; a: ULong; b: ULong;
            mode: ULong): Integer; cdecl; external OLLYDBG name 'Expression';
function  Fastexpression(result: p_result; addr: ULong; itype: Integer;
            threadid: ULong): Integer; cdecl; external OLLYDBG name 'Fastexpression';


////////////////////////////////////////////////////////////////////////////////
///////////////////////////// DIALOGS AND OPTIONS //////////////////////////////
const
  // Mode bits in calls to dialog functions.
  DIA_SIZEMASK   = $0000001F;               // Mask to extract default data size
    DIA_BYTE     = $00000001;               // Byte data size
    DIA_WORD     = $00000002;               // Word data size
    DIA_DWORD    = $00000004;               // Doubleword data size (default)
    DIA_QWORD    = $00000008;               // Quadword data size
    DIA_TBYTE    = $0000000A;               // 10-byte data size
    DIA_DQWORD   = $00000010;               // 16-byte data size
  DIA_HEXONLY    = $00000020;               // Hexadecimal format only
  DIA_EXTENDED   = $00000040;               // Extended format
  DIA_DATAVALID  = $00000080;               // Input data valid (edit mode)
  DIA_DEFMASK    = $00000F00;               // Mask to extract default data type
    DIA_DEFHEX   = $00000100;               // On startup, cursor in hex control
    DIA_DEFSIG   = $00000200;               // On startup, cursor in signed control
    DIA_DEFUNSIG = $00000300;               // On startup, cursor in unsigned control
    DIA_DEFASC   = $00000400;               // On startup, cursor in ASCII control
    DIA_DEFUNI   = $00000500;               // On startup, cursor in UNICODE control
    DIA_DEFCODE  = $00000600;               // Default is code breakpoint
    DIA_DEFFLOAT = $00000700;               // Default selection is float
  DIA_ISSEARCH   = $00001000;               // Is a search dialog
  DIA_ASKCASE    = $00002000;               // Ask if case-insensitive
  DIA_SEARCHDIR  = $00004000;               // Includes direction search buttons
  DIA_HISTORY    = $00008000;               // Supports history
  DIA_SELMASK    = $000F0000;               // Mask to extract selection offset
    DIA_SEL0     = $00000000;               // Select least significant item
    DIA_SEL4     = $00040000;               // Select item with offset 4
    DIA_SEL8     = $00080000;               // Select item with offset 8
    DIA_SEL12    = $000C0000;               // Select item with offset 12
    DIA_SEL14    = $000E0000;               // Select item with offset 14
  DIA_JMPMODE    = $00300000;               // Mask for jump/call/switch display
    DIA_JMPFROM  = $00000000;               // Jumps/calls from specified location
    DIA_JMPTO    = $00100000;               // Jumps/calls to specified location
    DIA_SWITCH   = $00200000;               // Switches
  DIA_JMPGLOB    = $00400000;               // Show global jumps and calls
  DIA_JMPLOC     = $00000000;               // Show local jumps and calls
  DIA_UTF8       = $00800000;               // Support for UTF8
  DIA_ABSXYPOS   = $10000000;               // Use X-Y dialog coordinates as is
  DIA_RESTOREPOS = $20000000;               // Restore X-Y dialog coordinates

  // Types of controls that can be used in dialogs.
  CA_END         = 0;                       // End of control list with dialog size
  CA_COMMENT     = 1;                       // Dummy entry in control list
  CA_TEXT        = 2;                       // Simple left-aligned text
  CA_TEXTC       = 4;                       // Simple centered text
  CA_TEXTR       = 5;                       // Simple right-aligned text
  CA_WARN        = 6;                       // Multiline text, highlighted if differ
  CA_WTEXT       = 7;                       // Text with white bg in sunken frame
  CA_TITLE       = 8;                       // Fat centered text
  CA_FRAME       = 9;                       // Etched frame
  CA_SUNK        = 10;                      // Sunken frame
  CA_GROUP       = 11;                      // Group box (named frame)
  CA_EDIT        = 12;                      // Standard edit control
  CA_NOEDIT      = 13;                      // Read-only edit control
  CA_EDITHEX     = 14;                      // Standard edit control, hex uppercase
  CA_MULTI       = 15;                      // Multiline edit control (DATALEN)
  CA_NOMULTI     = 16;                      // Multiline read-only edit (DATALEN)
  CA_BTN         = 17;                      // Standard pushbutton
  CA_DEFBTN      = 18;                      // Standard default pushbutton
  CA_COMBO       = 19;                      // Combo box control, specified font
  CA_COMBOFIX    = 20;                      // Combo box control, fixed width font
  CA_CEDIT       = 21;                      // Combo edit control, specified font
  CA_CEDITFIX    = 22;                      // Combo edit control, fixed width font
  CA_CESAV0      = 32;                      // Combo edit 0 with autosave & UNICODE
  CA_CESAV1      = 33;                      // Combo edit 1 with autosave & UNICODE
  CA_CESAV2      = 34;                      // Combo edit 2 with autosave & UNICODE
  CA_CESAV3      = 35;                      // Combo edit 3 with autosave & UNICODE
  CA_CESAV4      = 36;                      // Combo edit 4 with autosave & UNICODE
  CA_CESAV5      = 37;                      // Combo edit 5 with autosave & UNICODE
  CA_CESAV6      = 38;                      // Combo edit 6 with autosave & UNICODE
  CA_CESAV7      = 39;                      // Combo edit 7 with autosave & UNICODE
  CA_LIST        = 48;                      // Simple list box
  CA_LISTFIX     = 49;                      // Simple list box, fixed font
  CA_CHECK       = 62;                      // Auto check box, left-aligned
  CA_CHECKR      = 63;                      // Auto check box, right-aligned
  CA_BIT0        = 64;                      // Auto check box, bit 0
  CA_BIT1        = 65;                      // Auto check box, bit 1
  CA_BIT2        = 66;                      // Auto check box, bit 2
  CA_BIT3        = 67;                      // Auto check box, bit 3
  CA_BIT4        = 68;                      // Auto check box, bit 4
  CA_BIT5        = 69;                      // Auto check box, bit 5
  CA_BIT6        = 70;                      // Auto check box, bit 6
  CA_BIT7        = 71;                      // Auto check box, bit 7
  CA_BIT8        = 72;                      // Auto check box, bit 8
  CA_BIT9        = 73;                      // Auto check box, bit 9
  CA_BIT10       = 74;                      // Auto check box, bit 10
  CA_BIT11       = 75;                      // Auto check box, bit 11
  CA_BIT12       = 76;                      // Auto check box, bit 12
  CA_BIT13       = 77;                      // Auto check box, bit 13
  CA_BIT14       = 78;                      // Auto check box, bit 14
  CA_BIT15       = 79;                      // Auto check box, bit 15
  CA_BIT16       = 80;                      // Auto check box, bit 16
  CA_BIT17       = 81;                      // Auto check box, bit 17
  CA_BIT18       = 82;                      // Auto check box, bit 18
  CA_BIT19       = 83;                      // Auto check box, bit 19
  CA_BIT20       = 84;                      // Auto check box, bit 20
  CA_BIT21       = 85;                      // Auto check box, bit 21
  CA_BIT22       = 86;                      // Auto check box, bit 22
  CA_BIT23       = 87;                      // Auto check box, bit 23
  CA_BIT24       = 88;                      // Auto check box, bit 24
  CA_BIT25       = 89;                      // Auto check box, bit 25
  CA_BIT26       = 90;                      // Auto check box, bit 26
  CA_BIT27       = 91;                      // Auto check box, bit 27
  CA_BIT28       = 92;                      // Auto check box, bit 28
  CA_BIT29       = 93;                      // Auto check box, bit 29
  CA_BIT30       = 94;                      // Auto check box, bit 30
  CA_BIT31       = 95;                      // Auto check box, bit 31
  CA_RADIO0      = 96;                      // Radio button, value 0
  CA_RADIO1      = 97;                      // Radio button, value 1
  CA_RADIO2      = 98;                      // Radio button, value 2
  CA_RADIO3      = 99;                      // Radio button, value 3
  CA_RADIO4      = 100;                     // Radio button, value 4
  CA_RADIO5      = 101;                     // Radio button, value 5
  CA_RADIO6      = 102;                     // Radio button, value 6
  CA_RADIO7      = 103;                     // Radio button, value 7
  CA_RADIO8      = 104;                     // Radio button, value 8
  CA_RADIO9      = 105;                     // Radio button, value 9
  CA_RADIO10     = 106;                     // Radio button, value 10
  CA_RADIO11     = 107;                     // Radio button, value 11
  CA_RADIO12     = 108;                     // Radio button, value 12
  CA_RADIO13     = 109;                     // Radio button, value 13
  CA_RADIO14     = 110;                     // Radio button, value 14
  CA_RADIO15     = 111;                     // Radio button, value 15
  CA_CUSTOM      = 124;                     // Custom control
  CA_CUSTSF      = 125;                     // Custom control with sunken frame
  // Controls with special functions that work only in Options dialog.
  CA_FILE        = 129;                     // Edit file (autosave, MAXPATH chars)
  CA_BROWSE      = 130;                     // Browse file name pushbutton
  CA_BRDIR       = 131;                     // Browse directory pushbutton
  CA_LANGS       = 132;                     // Combobox with list of languages
  CA_FONTS       = 133;                     // Combobox with list of fonts
  CA_FHTOP       = 134;                     // Combobox that adjusts top font height
  CA_FHBOT       = 135;                     // Combobox that adjusts bottom font hgt
  CA_SCHEMES     = 136;                     // Combobox with list of schemes
  CA_HILITE      = 137;                     // Combobox with list of hilites
  CA_HILITE1     = 138;                     // Combobox with nontrivial hilites

  // Modes of font usage in dialog windows, if applies.
  DFM_SYSTEM     = 0;                       // Use system font
  DFM_PARENT     = 1;                       // Use font of parent window
  DFM_FIXED      = 2;                       // Use dlgfontindex
  DFM_FIXALL     = 3;                       // Use dlgfontindex for all controls

  HEXLEN         = 1024;                    // Max length of hex edit string, bytes

  NSEARCHCMD     = 128;                     // Max number of assembler search models

type
  p_dialog = ^t_dialog;                     // Descriptor of OllyDbg dialog
  t_dialog = packed record
    controls: p_control;                    // List of controls to place in dialog
    title: PWChar;                          // Pointer to the dialog's title
    focus: Integer;                         // ID of control with focus
    item: Integer;                          // Index of processing item
    u: ULong;                               // Doubleword data
    data: array[0..15] of UChar;            // Data in other formats
    addr0: ULong;                           // Address
    addr1: ULong;                           // Address
    letter: Integer;                        // First character entered in dialog
    x: Integer;                             // X reference screen coordinate
    y: Integer;                             // Y reference screen coordinate
    fi: Integer;                            // Index of font to use in dialog
    mode: Integer;                          // Dialog operation mode, set of DIA_xxx
    cesav: array[0..7] of Integer;          // NM_xxx of CA_CESAVn
    fixfont: HFONT;                         // Fixed font used in dialog
    isfullunicode: Integer;                 // Whether fixfont UNICODE
    fixdx: Integer;                         // Width of dialog fixed font
    fixdy: Integer;                         // Height of dialog fixed font
    htooltip: HWND;                         // Handle of tooltip window
    hwwarn: HWND;                           // Handle of WARN control, if any
    initdone: Integer;                      // WM_INITDIALOG finished
  end;

  // ATTENTION, size of structure t_hexstr must not exceed DATALEN!
  p_hexstr = ^t_hexstr;                     // Data for hex/text search
  t_hexstr = packed record
    n: ULong;                               // Data length, bytes
    nmax: ULong;                            // Maximal data length, bytes
    data: array[0..HEXLEN-1] of UChar;      // Data
    mask: array[0..HEXLEN-1] of UChar;      // Mask, 0 bits are masked
  end;

  BROWSECODEFUNC = function(index: Integer; data: Pointer; addr: PULong; s: PWChar): Integer; cdecl;

function  Findcontrol(hw: HWND): p_control; cdecl; external OLLYDBG name 'Findcontrol';
function  Defaultactions(hparent: HWND; pctr: p_control;
            wp: WPARAM; lp: LPARAM ): Integer; cdecl; external OLLYDBG name 'Defaultactions';
procedure Addstringtocombolist(hc: HWND; s: PWChar); cdecl; external OLLYDBG name 'Addstringtocombolist';
function  Preparedialog(hw: HWND; pdlg: p_dialog): Integer; cdecl; external OLLYDBG name 'Preparedialog';
function  Endotdialog(hw: HWND; result: Integer): Integer; cdecl; external OLLYDBG name 'Endotdialog';
function  Getregister(hparent: HWND; reg: Integer; data: PULong; letter: Integer;
            x: Integer; y: Integer; fi: Integer; mode: Integer ): Integer; cdecl; external OLLYDBG name 'Getregister';
function  GetInteger(hparent: HWND; title: PWChar; data: PULong; letter: Integer ;
            x: Integer; y: Integer; fi: Integer; mode: Integer ): Integer; cdecl; external OLLYDBG name 'GetInteger';
function  Getdword(hparent: HWND; title: PWChar; data: PULong; letter: Integer;
            x: Integer; y: Integer; fi: Integer; mode: Integer): Integer; cdecl; external OLLYDBG name 'Getdword';
function  Getlasterrorcode(hparent: HWND; title: PWChar; data: PULong;
            letter: Integer; x: Integer; y: Integer; fi: Integer): Integer; cdecl; external OLLYDBG name 'Getlasterrorcode';
function  Getaddressrange(hparent: HWND; title: PWChar;
            rmin: PULong; rmax: PULong; x: Integer; y: Integer; fi: Integer; mode: Integer): Integer; cdecl; external OLLYDBG name 'Getaddressrange';
function  Getexceptionrange(hparent: HWND; title: PWChar;
            rmin: PULong; rmax: PULong; x: Integer; y: Integer; fi: Integer): Integer; cdecl; external OLLYDBG name 'Getexceptionrange';
function  Getstructuretype(hparent: HWND; title: PWChar; text: PWChar;
            strname: PWChar; x: Integer; y: Integer; fi: Integer): Integer; cdecl; external OLLYDBG name 'Getstructuretype';
function  Getfpureg(hparent: HWND; reg: Integer; data: Pointer; letter: Integer;
            x: Integer; y: Integer; fi: Integer): Integer; cdecl; external OLLYDBG name 'Getfpureg';
function  Get3dnow(hparent: HWND; title: PWChar; data: Pointer; letter: Integer;
            x: Integer; y: Integer; fi: Integer; mode: Integer): Integer; cdecl; external OLLYDBG name 'Get3dnow';
function  Getfloat(hparent: HWND; title: PWChar; data: Pointer; letter: Integer ;
            x: Integer; y: Integer; fi: Integer; mode: Integer): Integer; cdecl; external OLLYDBG name 'Getfloat';
function  Getmmx(hparent: HWND; title: PWChar; data: Pointer; letter: Integer;
            x: Integer; y: Integer; fi: Integer): Integer; cdecl; external OLLYDBG name 'Getmmx';
function  Getsse(hparent: HWND; title: PWChar; data: Pointer; letter: Integer;
            x: Integer; y: Integer; fi: Integer; mode: Integer): Integer; cdecl; external OLLYDBG name 'Getsse';
function  Getstring(hparent: HWND; title: PWChar; s: PWChar; length: Integer;
            savetype: Integer; letter: Integer; x: Integer; y: Integer; fi: Integer; mode: Integer): Integer; cdecl; external OLLYDBG name 'Getstring';
function  Getdwordexpression(hparent: HWND; title: PWChar; u: PULong;
            threadid: ULong; savetype: Integer; x: Integer; y: Integer; fi: Integer; mode: Integer): Integer; cdecl; external OLLYDBG name 'Getdwordexpression';
function  Getgotoexpression(hparent: HWND; title: PWChar; u: PULong;
            threadid: ULong; savetype: Integer; x: Integer; y: Integer; fi: Integer; mode: Integer): Integer; cdecl; external OLLYDBG name 'Getgotoexpression';
function  Getasmsearchmodel(hparent: HWND; title: PWChar; model: p_asmmod;
            nmodel: Integer; x: Integer; y: Integer; fi: Integer; mode: Integer): Integer; cdecl; external OLLYDBG name 'Getasmsearchmodel';
function  Getseqsearchmodel(hparent: HWND; title: PWChar; model: p_asmmod;
            nmodel: Integer; x: Integer; y: Integer; fi: Integer; mode: Integer): Integer; cdecl; external OLLYDBG name 'Getseqsearchmodel';
function  Binaryedit(hparent: HWND; title: PWChar; hstr: p_hexstr;
            letter: Integer; x: Integer; y: Integer; fi: Integer; mode: Integer): Integer; cdecl; external OLLYDBG name 'Binaryedit';
function  Getpredefinedtypebyindex(fnindex: Integer; itype: PWChar): Integer; cdecl; external OLLYDBG name 'Getpredefinedtypebyindex';
function  Getindexbypredefinedtype(itype: PWChar): Integer; cdecl; external OLLYDBG name 'Getindexbypredefinedtype';
function  Condbreakpoint(hparent: HWND; addr: PULong; naddr: Integer;
            title: PWChar; x: Integer; y: Integer; fi: Integer): Integer; cdecl; external OLLYDBG name 'Condbreakpoint';
function  Condlogbreakpoint(hparent: HWND; addr: PULong; naddr: Integer;
            fnindex: Integer; title: PWChar; x: Integer; y: Integer; fi: Integer): Integer; cdecl; external OLLYDBG name 'Condlogbreakpoint';
function  Membreakpoint(hparent: HWND; addr: ULong; size: ULong ;
            x: Integer; y: Integer; fi: Integer; mode: Integer): Integer; cdecl; external OLLYDBG name 'Membreakpoint';
function  Memlogbreakpoint(hparent: HWND; addr: ULong; size: ULong ;
            x: Integer; y: Integer; fi: Integer; mode: Integer): Integer; cdecl; external OLLYDBG name 'Memlogbreakpoint';
function  Hardbreakpoint(hparent: HWND; addr: ULong;
            x: Integer; y: Integer; fi: Integer; mode: Integer): Integer; cdecl; external OLLYDBG name 'Hardbreakpoint';
function  Hardlogbreakpoint(hparent: HWND; addr: ULong; fnindex: Integer ;
            x: Integer; y: Integer; fi: Integer; mode: Integer): Integer; cdecl; external OLLYDBG name 'Hardlogbreakpoint';
procedure Setrtcond(hparent: HWND; x: Integer; y: Integer; fi: Integer); cdecl; external OLLYDBG name 'Setrtcond';
procedure Setrtprot(hparent: HWND; x: Integer; y: Integer; fi: Integer); cdecl; external OLLYDBG name 'Setrtprot';
function  Browsecodelocations(hparent: HWND; title: PWChar;
            bccallback: BROWSECODEFUNC; data: Pointer): ULong; cdecl; external OLLYDBG name 'Browsecodelocations';
function  Fillcombowithcodepages(hw: HWND; select: Integer): Integer; cdecl; external OLLYDBG name 'Fillcombowithcodepages';


////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// PLUGIN OPTIONS ////////////////////////////////
const
  OPT_TITLE     = 9001;                     // Pane title
  OPT_1         = 9011;                     // First automatical control
  OPT_2         = 9012;                     // Second automatical control
  OPT_3         = 9013;                     // Third automatical control
  OPT_4         = 9014;                     // Fourth automatical control
  OPT_5         = 9015;                     // Fifth automatical control
  OPT_6         = 9016;                     // Sixth automatical control
  OPT_7         = 9017;                     // Seventh automatical control
  OPT_8         = 9018;                     // Eighth automatical control
  OPT_9         = 9019;                     // Ninth automatical control
  OPT_10        = 9020;                     // Tenth automatical control
  OPT_11        = 9021;                     // Eleventh automatical control
  OPT_12        = 9022;                     // Twelfth automatical control
  OPT_13        = 9023;                     // Thirteen automatical control
  OPT_14        = 9024;                     // Fourteen automatical control
  OPT_15        = 9025;                     // Fifteen automatical control
  OPT_16        = 9026;                     // Sixteen automatical control
  OPT_17        = 9027;                     // Seventeen automatical control
  OPT_18        = 9028;                     // Eighteen automatical control
  OPT_19        = 9029;                     // Nineteen automatical control
  OPT_20        = 9030;                     // Twentieth automatical control
  OPT_21        = 9031;                     // Twenty-first automatical control
  OPT_22        = 9032;                     // Twenty-second automatical control
  OPT_23        = 9033;                     // Twenty-third automatical control
  OPT_24        = 9034;                     // Twenty-fourth automatical control
  OPT_W1        = 9101;                     // First automatical autowarn control
  OPT_W2        = 9102;                     // Second automatical autowarn control
  OPT_W3        = 9103;                     // Third automatical autowarn control
  OPT_W4        = 9104;                     // Fourth automatical autowarn control
  OPT_W5        = 9105;                     // Fifth automatical autowarn control
  OPT_W6        = 9106;                     // Sixth automatical autowarn control
  OPT_W7        = 9107;                     // Seventh automatical autowarn control
  OPT_W8        = 9108;                     // Eighth automatical autowarn control
  OPT_W9        = 9109;                     // Ninth automatical autowarn control
  OPT_W10       = 9110;                     // Tenth automatical autowarn control
  OPT_W11       = 9111;                     // Eleventh automatical autowarn control
  OPT_W12       = 9112;                     // Twelfth automatical autowarn control
  OPT_S1        = 9121;                     // First autowarn-if-turned-on control
  OPT_S2        = 9122;                     // Second autowarn-if-turned-on control
  OPT_S3        = 9123;                     // Third autowarn-if-turned-on control
  OPT_S4        = 9124;                     // Fourth autowarn-if-turned-on control
  OPT_S5        = 9125;                     // Fifth autowarn-if-turned-on control
  OPT_S6        = 9126;                     // Sixth autowarn-if-turned-on control
  OPT_S7        = 9127;                     // Seventh autowarn-if-turned-on control
  OPT_S8        = 9128;                     // Eighth autowarn-if-turned-on control
  OPT_S9        = 9129;                     // Ninth autowarn-if-turned-on control
  OPT_S10       = 9130;                     // Tenth autowarn-if-turned-on control
  OPT_S11       = 9131;                     // Eleventh autowarn-if-turned-on control
  OPT_S12       = 9132;                     // Twelfth autowarn-if-turned-on control
  OPT_X1        = 9141;                     // First autowarn-if-all-on control
  OPT_X2        = 9142;                     // Second autowarn-if-all-on control
  OPT_X3        = 9143;                     // Third autowarn-if-all-on control
  OPT_X4        = 9144;                     // Fourth autowarn-if-all-on control
  OPT_X5        = 9145;                     // Fifth autowarn-if-all-on control
  OPT_X6        = 9146;                     // Sixth autowarn-if-all-on control
  OPT_X7        = 9147;                     // Seventh autowarn-if-all-on control
  OPT_X8        = 9148;                     // Eighth autowarn-if-all-on control
  OPT_X9        = 9149;                     // Ninth autowarn-if-all-on control
  OPT_X10       = 9150;                     // Tenth autowarn-if-all-on control
  OPT_X11       = 9151;                     // Eleventh autowarn-if-all-on control
  OPT_X12       = 9152;                     // Twelfth autowarn-if-all-on control

  OPT_CUSTMIN   = 9500;                     // Custom controls by plugins
  OPT_CUSTMAX   = 9999;                     // End of custom area

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// COMMENTS ///////////////////////////////////

  // Comments types used by Commentaddress().
  COMM_USER      = $00000001;               // Add user-defined comment
  COMM_MARK      = $00000002;               // Add important arguments
  COMM_PROC      = $00000004;               // Add procedure description
  COMM_ALL       = $FFFFFFFF;               // Add all possible comments

function  Stringtotext(data: PWChar; ndata: Integer; text: PWChar; ntext: Integer;
            stopatzero: Integer): Integer; cdecl; external OLLYDBG name 'Stringtotext';
function  Isstring(addr: ULong; isstatic: Integer; symb: PWChar; nsymb: Integer): Integer; cdecl; external OLLYDBG name 'Isstring';
function  Squeezename(dest: PWChar; ndest: Integer; src: PWChar; nsrc: Integer): Integer; cdecl; external OLLYDBG name 'Squeezename';
procedure Uncapitalize(s: PWChar); cdecl; external OLLYDBG name 'Uncapitalize';
function  Decoderelativeoffset(addr: ULong; addrmode: Integer;
            symb: PWChar; nsymb: Integer): Integer; cdecl; external OLLYDBG name 'Decoderelativeoffset';
function  Decodeaddress(addr: ULong; amod: ULong; mode: Integer;
            symb: PWChar; nsymb: Integer; comment: PWChar): Integer; cdecl; external OLLYDBG name 'Decodeaddress';
function  Decodearglocal(uip: ULong; offs: ULong; datasize: ULong;
            name: PWChar; len: Integer): Integer; cdecl; external OLLYDBG name 'Decodearglocal';
function  Getanalysercomment(pmod: p_module; addr: ULong;
            comment: PWChar; len: Integer): Integer; cdecl; external OLLYDBG name 'Getanalysercomment';
function  Getswitchcomment(addr: ULong; comment: PWChar; len: Integer): Integer; cdecl; external OLLYDBG name 'Getswitchcomment';
function  Getloopcomment(pmod: p_module; addr: ULong; level: Integer;
            comment: PWChar; len: Integer): Integer; cdecl; external OLLYDBG name 'Getloopcomment';
function  Getproccomment(addr: ULong; acall: ULong;
            comment: PWChar; len: Integer; argonly: Integer): Integer; cdecl; external OLLYDBG name 'Getproccomment';
function  Commentaddress(addr: ULong; typelist: Integer;
            comment: PWChar; len: Integer): Integer; cdecl; external OLLYDBG name 'Commentaddress';


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// LOG WINDOW //////////////////////////////////

procedure   Redrawlist; cdecl; external OLLYDBG name 'Redrawlist';
procedure   Addtolist(addr: ULong; color: Integer; format: PWChar); cdecl; varargs; external OLLYDBG name 'Addtolist';


////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////// DUMP /////////////////////////////////////
const
  DU_STACK       = $80000000;               // Used for internal purposes
  DU_NOSMALL     = $40000000;               // Used for internal purposes
  DU_MODEMASK    = $3C000000;               // Mask for mode bits
    DU_SMALL     = $20000000;               // Small-size dump
    DU_FIXADDR   = $10000000;               // Fix first visible address
    DU_BACKUP    = $08000000;               // Display backup instead of actual data
    DU_USEDEC    = $04000000;               // Show contents using decoding data
  DU_COMMMASK    = $03000000;               // Mask for disassembly comments
    DU_COMMENT   = $00000000;               // Show comments
    DU_SOURCE    = $01000000;               // Show source
  DU_DISCARD     = $00800000;               // Discardable by Esc
  DU_PROFILE     = $00400000;               // Show profile
  DU_TYPEMASK    = $003F0000;               // Mask for dump type
    DU_HEXTEXT   = $00010000;               // Hexadecimal dump with ASCII text
    DU_HEXUNI    = $00020000;               // Hexadecimal dump with UNICODE text
    DU_TEXT      = $00030000;               // Character dump
    DU_UNICODE   = $00040000;               // Unicode dump
    DU_INT       = $00050000;               // Integer signed dump
    DU_UINT      = $00060000;               // Integer unsigned dump
    DU_IHEX      = $00070000;               // Integer hexadecimal dump
    DU_FLOAT     = $00080000;               // Floating-point dump
    DU_ADDR      = $00090000;               // Address dump
    DU_ADRASC    = $000A0000;               // Address dump with ASCII text
    DU_ADRUNI    = $000B0000;               // Address dump with UNICODE text
    DU_DISASM    = $000C0000;               // Disassembly
    DU_DECODE    = $000D0000;               // Same as DU_DISASM but for decoded data
  DU_COUNTMASK   = $0000FF00;               // Mask for number of items/line
  DU_SIZEMASK    = $000000FF;               // Mask for size of single item

  DU_MAINPART    = DU_TYPEMASK or DU_COUNTMASK or DU_SIZEMASK;

  DUMP_HEXA8     = $00010801;               // Hex/ASCII dump, 8 bytes per line
  DUMP_HEXA16    = $00011001;               // Hex/ASCII dump, 16 bytes per line
  DUMP_HEXU8     = $00020801;               // Hex/UNICODE dump, 8 bytes per line
  DUMP_HEXU16    = $00021001;               // Hex/UNICODE dump, 16 bytes per line
  DUMP_ASC32     = $00032001;               // ASCII dump, 32 characters per line
  DUMP_ASC64     = $00034001;               // ASCII dump, 64 characters per line
  DUMP_UNI16     = $00041002;               // UNICODE dump, 16 characters per line
  DUMP_UNI32     = $00042002;               // UNICODE dump, 32 characters per line
  DUMP_UNI64     = $00044002;               // UNICODE dump, 64 characters per line
  DUMP_INT16     = $00050802;               // 16-bit signed Integer dump, 8 items
  DUMP_INT16S    = $00050402;               // 16-bit signed Integer dump, 4 items
  DUMP_INT32     = $00050404;               // 32-bit signed Integer dump, 4 items
  DUMP_INT32S    = $00050204;               // 32-bit signed Integer dump, 2 items
  DUMP_UINT16    = $00060802;               // 16-bit unsigned Integer dump, 8 items
  DUMP_UINT16S   = $00060402;               // 16-bit unsigned Integer dump, 4 items
  DUMP_UINT32    = $00060404;               // 32-bit unsigned Integer dump, 4 items
  DUMP_UINT32S   = $00060204;               // 32-bit unsigned Integer dump, 2 items
  DUMP_IHEX16    = $00070802;               // 16-bit hex Integer dump, 8 items
  DUMP_IHEX16S   = $00070402;               // 16-bit hex Integer dump, 4 items
  DUMP_IHEX32    = $00070404;               // 32-bit hex Integer dump, 4 items
  DUMP_IHEX32S   = $00070204;               // 32-bit hex Integer dump, 2 items
  DUMP_FLOAT32   = $00080404;               // 32-bit floats, 4 items
  DUMP_FLOAT32S  = $00080104;               // 32-bit floats, 1 item
  DUMP_FLOAT64   = $00080208;               // 64-bit floats, 2 items
  DUMP_FLOAT64S  = $00080108;               // 64-bit floats, 1 item
  DUMP_FLOAT80   = $0008010A;               // 80-bit floats
  DUMP_ADDR      = $00090104;               // Address dump
  DUMP_ADDRASC   = $000A0104;               // Address dump with ASCII text
  DUMP_ADDRUNI   = $000B0104;               // Address dump with UNICODE text
  DUMP_DISASM    = $000C0110;               // Disassembly (max. 16 bytes per cmd)
  DUMP_DECODE    = $000D0110;               // Decoded data (max. 16 bytes per line)

  // Types of dump menu in t_dump.menutype.
  DMT_FIXTYPE    = $00000001;               // Fixed dump type, no change
  DMT_STRUCT     = $00000002;               // Dump of the structure
  DMT_CPUMASK    = $00070000;               // Dump belongs to CPU window
    DMT_CPUDASM  = $00010000;               // This is CPU Disassembler pane
    DMT_CPUDUMP  = $00020000;               // This is CPU Dump pane
    DMT_CPUSTACK = $00040000;               // This is CPU Stack pane

  // Modes of Scrolldumpwindow().
  SD_REALIGN     = $01;                     // Realign on specified address
  SD_CENTERY     = $02;                     // Center destination vertically

  // Modes of t_dump.dumpselfunc() and Reportdumpselection().
  SCH_SEL0       = $01;                     // t_dump.sel0 changed
  SCH_SEL1       = $02;                     // t_dump.sel1 changed

  // Modes of Copydumpselection().
  CDS_TITLES     = $00000001;               // Prepend window name and column titles
  CDS_NOGRAPH    = $00000002;               // Replace graphical symbols by spaces

type
  p_dump = ^t_dump;                         // Descriptor of dump data and window

  DUMPSELFUNC = procedure(pd: p_dump; mode: Integer); cdecl;

  t_dump = packed record
    base: ULong;                            // Start of memory block or file
    size: ULong;                            // Size of memory block or file
    dumptype: ULong;                        // Dump type, DU_xxx+count+size= DUMP_xxx
    menutype: ULong;                        // Menu type, set of DMT_xxx
    itemwidth: ULong;                       // Width of one item, characters
    threadid: ULong;                        // Use decoding and registers if not 0
    table: t_table;                         // Dump window is a custom table
    addr: ULong;                            // Address of first visible byte
    sel0: ULong;                            // Address of first selected byte
    sel1: ULong;                            // Last selected byte (not included!)
    selstart: ULong;                        // Addr of first byte of selection start
    selend: ULong;                          // Addr of first byte of selection end
    filecopy: PUChar;                       // Copy of the file or NULL
    path: array[0..MAXPATH-1] of WChar;     // Name of displayed file
    backup: PUChar;                         // Old backup of memory/file or NULL
    strname: array[0..SHORTNAME-1] of WChar;// Name of the structure to decode
    decode: PUChar;                         // Local decoding information or NULL
    bkpath: array[0..MAXPATH-1] of WChar;   // Name of last used backup file
    relreg: Integer;                        // Addresses relative to register
    reladdr: ULong;                         // Addresses relative to this address
    hilitereg: ULong;                       // One of OP_SOMEREG if reg highlighting
    hiregindex: Integer;                    // Index of register to highlight
    graylimit: ULong;                       // Gray data below this address
    dumpselfunc: DUMPSELFUNC;               // Callback indicating change of sel0
  end;

procedure Setdumptype(pd: p_dump; dumptype: ULong ); cdecl; external OLLYDBG name 'Setdumptype';
function  Ensurememorybackup(pmem: p_memory; makebackup: Integer): Integer; cdecl; external OLLYDBG name 'Ensurememorybackup';
procedure Backupusercode(pm: p_module; force: Integer); cdecl; external OLLYDBG name 'Backupusercode';
function  Copydumpselection(pd: p_dump; mode: Integer): HGLOBAL; cdecl; external OLLYDBG name 'Copydumpselection';
function  Dumpback(pd: p_dump; addr: ULong; n: Integer): ULong; cdecl; external OLLYDBG name 'Dumpback';
function  Dumpforward(pd: p_dump; addr: ULong; n: Integer): ULong; cdecl; external OLLYDBG name 'Dumpforward';
function  Scrolldumpwindow(pd: p_dump; addr: ULong; mode: Integer): ULong; cdecl; external OLLYDBG name 'Scrolldumpwindow';
function  Alignselection(pd: p_dump; sel0: PULong; sel1: PULong): Integer; cdecl; external OLLYDBG name 'Alignselection';
function  Getproclimits(addr: ULong; amin: PULong; amax: PULong): Integer; cdecl; external OLLYDBG name 'Getproclimits';
function  Getextproclimits(addr: ULong; amin: PULong; amax: PULong): Integer; cdecl; external OLLYDBG name 'Getextproclimits';
function  Newdumpselection(pd: p_dump; addr: ULong; size: ULong): Integer; cdecl; external OLLYDBG name 'Newdumpselection';
function  Findfiledump(path: PWChar): p_dump; cdecl; external OLLYDBG name 'Findfiledump';
function  Createdumpwindow(title: PWChar; base: ULong; size: ULong;
            path: PWChar; dumptype: ULong; sel0: ULong; sel1: ULong;
            strname: PWChar): HWND; cdecl; external OLLYDBG name 'Createdumpwindow';
function  Embeddumpwindow(hw: HWND; pd: p_dump; dumptype: ULong): HWND; cdecl; external OLLYDBG name 'Embeddumpwindow';
function  Asmindump(hparent: HWND; title: PWChar; pd: p_dump; letter: Integer; x: Integer; y: Integer; fi: Integer;
            mode: Integer): Integer; cdecl; external OLLYDBG name 'Asmindump';

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// SEARCH ////////////////////////////////////
const
  // Layouts of search panel.
  SL_UNDEF       = 0;                       // Undefined layout
  SL_DISASM      = 1;                       // Commands or refs within one module
  SL_SEQASM      = 2;                       // Sequences within one module
  SL_STRINGS     = 3;                       // Referenced strings within one module
  SL_GUIDS       = 4;                       // Referenced GUIDs within one module
  SL_COMMENTS    = 5;                       // All user-defined comments
  SL_SWITCHES    = 6;                       // Switches and cascaded IFs
  SL_FLOATS      = 7;                       // Referenced floats within one module
  SL_CALLS       = 8;                       // Intermodular calls
  SL_MOD         = 9;                       // Modifications

  // Search types.
  SEARCH_NONE    = 0;                       // type is not yet defined
  SEARCH_CMD     = 1;                       // Search for assembler commands
  SEARCH_SEQ     = 2;                       // Search for the sequence of commands
  SEARCH_BINARY  = 3;                       // Search for binary code
  SEARCH_CONST   = 4;                       // Search for referenced constant range
  SEARCH_MOD     = 5;                       // Search for modifications

  // Search directions.
  SDIR_GLOBAL    = 0;                       // Search forward from the beginning
  SDIR_FORWARD   = 1;                       // Search forward from selection
  SDIR_BACKWARD  = 2;                       // Search backward from selection

  // Search modes.
  SRCH_NEW       = 0;                       // Ask for new search pattern
  SRCH_NEWMEM    = 1;                       // Ask for new pattern, memory mode
  SRCH_SAMEDIR   = 2;                       // Search in the specified direction
  SRCH_OPPDIR    = 3;                       // Search in the opposite direction
  SRCH_MEM       = 4;                       // Search forward, memory mode

  // Mode bits in Comparesequence().
  CSEQ_IGNORECMD = $00000001;               // Ignore non-influencing commands
  CSEQ_ALLOWJMP  = $00000002;               // Allow jumps from outside

type
  p_found = ^t_found;                       // Search result
  t_found = packed record
    addr: ULong;                            // Address of found item
    size: ULong;                            // Size of found item, or 0 on error
  end;

  p_search = ^t_search;                     // Descriptor of found item
  t_search = packed record
    addr: ULong;                            // Address of found item
    size: ULong;                            // Must be 1
    _type: ULong;                           // type of found item, TY_xxx+SE_xxx
    data: ULong;                            // Mode-related data
    seqlen: ULong;                          // Length of command sequence
  end;

function  Comparecommand(cmd: PUChar; cmdsize: ULong; cmdip: ULong; model: p_asmmod; nmodel: Integer;
            pa: PInteger; pb: PInteger; da: p_disasm): ULong; cdecl; external OLLYDBG name 'Comparecommand';
function  Comparesequence(cmd: PUChar; cmdsize: ULong; cmdip: ULong;
            decode: PUChar; model: p_asmmod; nmodel: Integer; mode: Integer;
            pa: PInteger; pb: PInteger; da: p_disasm; amatch: PULong;
            namatch: Integer): ULong; cdecl; external OLLYDBG name 'Comparesequence';


////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// PATCHES ////////////////////////////////////
const
  PATCHSIZE      = 512;                     // Maximal patch size, bytes

type
  p_patch = ^t_patch;
  t_patch = packed record
    addr: ULong;                            // Base address of patch in memory
    size: ULong;                            // Size of patch, bytes
    ptype: ULong;                           // type of patch, set of TY_xxx
    orig: array[0..PATCHSIZE-1] of UChar;   // Original code
    pmod: array[0..PATCHSIZE-1] of UChar;   // Patched code
  end;


////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// BREAKPOINTS //////////////////////////////////
const
  // Actions that must be performed if breakpoint of type Bp_ONESHOT or Bp_TEMP
  // is hit.
  BA_PERMANENT   = $00000001;               // Permanent INT3 Bp_TEMP on system call
  BA_PLUGIN      = $80000000;               // Pass notification to plugin

type
  p_bpoint = ^t_bpoint;                     // INT3 breakpoints
  t_bpoint = packed record
    addr: ULong;                            // Address of breakpoint
    size: ULong;                            // Must be 1
    _type: ULong;                           // type of breakpoint, TY_xxx+Bp_xxx
    fnindex: UShort;                        // Index of predefined function
    cmd: UChar;                             // First byte of original command
    patch: UChar;                           // Used only in .udd files
    limit: ULong;                           // Original pass count (0 if not set)
    count: ULong;                           // Actual pass count
    actions: ULong;                         // Actions, set of BA_xxx
  end;

  p_bpmem = ^t_bpmem;                       // Memory breakpoints
  t_bpmem = packed record
    addr: ULong;                            // Address of breakpoint
    size: ULong;                            // Size of the breakpoint, bytes
    _type: ULong;                           // type of breakpoint, TY_xxx+Bp_xxx
    limit: ULong;                           // Original pass count (0 if not set)
    count: ULong;                           // Actual pass count
  end;

  p_bppage = ^t_bppage;                     // Pages with modified attributes
  t_bppage = packed record
    base: ULong;                            // Base address of memory page
    size: ULong;                            // Always PAGESIZE
    _type: ULong;                           // Set of TY_xxx+Bp_ACCESSMASK
    oldaccess: ULong;                       // Initial access
    newaccess: ULong;                       // Modified (actual) access
  end;

  p_bphard = ^t_bphard;                     // Hardware breakpoints
  t_bphard = packed record
    index: ULong;                           // Index of the breakpoint (0..NHARD-1)
    dummy: ULong;                           // Must be 1
    _type: ULong;                           // type of the breakpoint, TY_xxx+Bp_xxx
    addr: ULong;                            // Address of breakpoint
    size: ULong;                            // Size of the breakpoint, bytes
    fnindex: Integer;                       // Index of predefined function
    limit: ULong;                           // Original pass count (0 if not set)
    count: ULong;                           // Actual pass count
    actions: ULong;                         // Actions, set of BA_xxx
    modbase: ULong;                         // Module base, used by .udd only
    path: array[0..MAXPATH-1] of WChar;     // Full module name, used by .udd only
  end;

function  Removeint3breakpoint(addr: ULong; utype: ULong): Integer; cdecl; external OLLYDBG name 'Removeint3breakpoint';
function  Setint3breakpoint(addr: ULong; utype: ULong; fnindex: Integer;
            limit: Integer; count: Integer; actions: ULong;
            condition: PWChar; expression: PWChar; exprtype: PWChar): Integer; cdecl; external OLLYDBG name 'Setint3breakpoint';
function  Enableint3breakpoint(addr: ULong; enable: Integer ): Integer; cdecl; external OLLYDBG name 'Enableint3breakpoint';
function  Confirmint3breakpoint(addr: ULong): Integer; cdecl; external OLLYDBG name 'Confirmint3breakpoint';
function  Confirmhardwarebreakpoint(addr: ULong): Integer; cdecl; external OLLYDBG name 'Confirmhardwarebreakpoint';
function  Confirmint3breakpointlist(addr: PULong; naddr: Integer): Integer; cdecl; external OLLYDBG name 'Confirmint3breakpointlist';
procedure Wipebreakpointrange(addr0: ULong; addr1: ULong); cdecl; external OLLYDBG name 'Wipebreakpointrange';
function  Removemembreakpoint(addr: ULong): Integer; cdecl; external OLLYDBG name 'Removemembreakpoint';
function  Setmembreakpoint(addr: ULong; size: ULong; utype: ULong;
            limit: Integer; count: Integer; condition: PWChar;
            expression: PWChar; exprtype: PWChar): Integer; cdecl; external OLLYDBG name 'Setmembreakpoint';
function  Enablemembreakpoint(addr: ULong; enable: Integer ): Integer; cdecl; external OLLYDBG name 'Enablemembreakpoint';
function  Removehardbreakpoint(index: Integer): Integer; cdecl; external OLLYDBG name 'Removehardbreakpoint';
function  Sethardbreakpoint(index: Integer; size: ULong; utype: ULong; fnindex: Integer;
            addr: ULong; limit: Integer; count: Integer; actions: ULong;
            condition: PWChar; expression: PWChar; exprtype: PWChar): Integer; cdecl; external OLLYDBG name 'Sethardbreakpoint';
function  Enablehardbreakpoint(index: Integer; enable: Integer): Integer; cdecl; external OLLYDBG name 'Enablehardbreakpoint';
function  Findfreehardbreakslot(utype: ULong): Integer; cdecl; external OLLYDBG name 'Findfreehardbreakslot';


////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////// CPU //////////////////////////////////////
const
  // Mode bits for Setcpu().
  CPU_ASMHIST    = $00000001;               // Add change to Disassembler history
  CPU_ASMCENTER  = $00000004;               // Make address in the middle of window
  CPU_ASMFOCUS   = $00000008;               // Move focus to Disassembler
  CPU_DUMPHIST   = $00000010;               // Add change to Dump history
  CPU_DUMPFIRST  = $00000020;               // Make address the first byte in Dump
  CPU_DUMPFOCUS  = $00000080;               // Move focus to Dump
  CPU_STACKFOCUS = $00000100;               // Move focus to Stack
  CPU_STACKCTR   = $00000200;               // Center stack instead moving to top
  CPU_REGAUTO    = $00001000;               // Automatically switch to FPU/MMX/3DNow!
  CPU_NOCREATE   = $00002000;               // Don't create CPU window if absent
  CPU_REDRAW     = $00004000;               // Redraw CPU window immediately
  CPU_NOFOCUS    = $00008000;               // Don't assign focus to main window
  CPU_RUNTRACE   = $00010000;               // asmaddr is run trace backstep
  CPU_NOTRACE    = $00020000;               // Stop run trace display

  // Options for autoregtype.
  ASR_OFF        = 0;                       // No FPU/MMX/3DNow! autoselection
  ASR_EVENT      = 1;                       // Autoselection on debug events
  ASR_ALWAYS     = 2;                       // Autoselection when command selected

  NHISTORY       = 1024;                    // Length of history buffer, records

type
  p_histrec = ^t_histrec;                   // Walk history record
  t_histrec = packed record
    threadid: ULong;                        // Thread ID, ignored by Dump pane
    dumptype: ULong;                        // Dump type, ignored by Disasm pane
    addr: ULong;                            // Address of first visible line
    sel0: ULong;                            // Begin of selection
    sel1: ULong;                            // End of selection (not included)
  end;

  // Note that hnext points to the free record following the last written, and
  // hcurr points record that follows currently selected one.
  p_history = ^t_history;                   // Walk history data
  t_history = packed record
    h: array[0..NHISTORY-1] of t_histrec;   // Circular buffer with history records
    holdest: Integer;                       // Index of oldest valid record in h
    hnext: Integer;                         // Index of first free record in h
    hcurr: Integer;                         // Index of record following actual in h
  end;

procedure Redrawcpudisasm; cdecl; external OLLYDBG name 'Redrawcpudisasm';
procedure Redrawcpureg; cdecl; external OLLYDBG name 'Redrawcpureg';
function  Getcputhreadid: ULong; cdecl; external OLLYDBG name 'Getcputhreadid';
function  Getcpuruntracebackstep: Integer; cdecl; external OLLYDBG name 'Getcpuruntracebackstep';
function  Getcpudisasmdump: p_dump; cdecl; external OLLYDBG name 'Getcpudisasmdump';
function  Getcpudumpdump: p_dump; cdecl; external OLLYDBG name 'Getcpudumpdump';
function  Getcpustackdump: p_dump; cdecl; external OLLYDBG name 'Getcpustackdump';
function  Getcpudisasmselection: ULong; cdecl; external OLLYDBG name 'Getcpudisasmselection';
function  Getcpudisasmtable: p_table; cdecl; external OLLYDBG name 'Getcpudisasmtable';
procedure Addtohistory(ph: p_history; threadid: ULong; dumptype: ULong;
            addr: ULong; sel0: ULong; sel1: ULong); cdecl; external OLLYDBG name 'Addtohistory';
function  Walkhistory(ph: p_history; dir: Integer; threadid: PULong;
            dumptype: PULong; addr: PULong; sel0: PULong; sel1: PULong): Integer; cdecl; external OLLYDBG name 'Walkhistory';
function  Checkhistory(ph: p_history; dir: Integer; isnewest: PInteger): Integer; cdecl; external OLLYDBG name 'Checkhistory';
procedure Setcpu(threadid: ULong; asmaddr: ULong; dumpaddr: ULong;
            selsize: ULong; stackaddr: ULong; mode: Integer); cdecl; external OLLYDBG name 'Setcpu';


////////////////////////////////////////////////////////////////////////////////
/////////////////////// DEBUGGING AND TRACING FUNCTIONS ////////////////////////
const
  NIGNORE        = 32;                      // Max. no. of ignored exception ranges
  NRTPROT        = 64;                      // No. of protocolled address ranges

  FP_SYSBP       = 0;                       // First pause on system breakpoint
  FP_TLS         = 1;                       // First pause on TLS callback, if any
  FP_ENTRY       = 2;                       // First pause on program entry point
  FP_WINMAIN     = 3;                       // First pause on WinMain, if known
  FP_NONE        = 4;                       // Run program immediately

  AP_SYSBP       = 0;                       // Attach pause on system breakpoint
  AP_CODE        = 1;                       // Attach pause on program code
  AP_NONE        = 2;                       // Run attached program immediately

  DP_LOADDLL     = 0;                       // Loaddll pause on Loaddll entry point
  DP_ENTRY       = 1;                       // Loaddll pause on DllEntryPoint()
  DP_LOADED      = 2;                       // Loaddll pause after LoadLibrary()
  DP_NONE        = 3;                       // Run Loaddll immediately

  DR6_SET        = $FFFF0FF0;               // DR6 bits specified as always 1
  DR6_TRAP       = $00004000;               // Single-step trap
  DR6_BD         = $00002000;               // Debug register access detected
  DR6_BHIT       = $0000000F;               // Some hardware breakpoint hit
    DR6_B3       = $00000008;               // Hardware breakpoint 3 hit
    DR6_B2       = $00000004;               // Hardware breakpoint 2 hit
    DR6_B1       = $00000002;               // Hardware breakpoint 1 hit
    DR6_B0       = $00000001;               // Hardware breakpoint 0 hit

  DR7_GD         = $00002000;               // Enable debug register protection
  DR7_SET        = $00000400;               // DR7 bits specified as always 1
  DR7_EXACT      = $00000100;               // Local exact instruction detection
  DR7_G3         = $00000080;               // Enable breakpoint 3 globally
  DR7_L3         = $00000040;               // Enable breakpoint 3 locally
  DR7_G2         = $00000020;               // Enable breakpoint 2 globally
  DR7_L2         = $00000010;               // Enable breakpoint 2 locally
  DR7_G1         = $00000008;               // Enable breakpoint 1 globally
  DR7_L1         = $00000004;               // Enable breakpoint 1 locally
  DR7_G0         = $00000002;               // Enable breakpoint 0 globally
  DR7_L0         = $00000001;               // Enable breakpoint 0 locally

  DR7_IMPORTANT  = DR7_G3 or DR7_L3 or DR7_G2 or DR7_L2 or DR7_G1 or DR7_L1 or DR7_G0 or DR7_L0;

  NCOND          = 4;                       // Number of run trace conditions
  NRANGE         = 2;                       // Number of memory ranges
  NCMD           = 2;                       // Number of commands
  NMODLIST       = 24;                      // Number of modules in pause list

  // Run trace condition bits.
  RTC_COND1      = $00000001;               // Stop run trace if condition 1 is met
  RTC_COND2      = $00000002;               // Stop run trace if condition 2 is met
  RTC_COND3      = $00000004;               // Stop run trace if condition 3 is met
  RTC_COND4      = $00000008;               // Stop run trace if condition 4 is met
  RTC_CMD1       = $00000010;               // Stop run trace if command 1 matches
  RTC_CMD2       = $00000020;               // Stop run trace if command 2 matches
  RTC_INRANGE    = $00000100;               // Stop run trace if in range
  RTC_OUTRANGE   = $00000200;               // Stop run trace if out of range
  RTC_COUNT      = $00000400;               // Stop run trace if count is reached
  RTC_MEM1       = $00001000;               // Access to memory range 1
  RTC_MEM2       = $00002000;               // Access to memory range 2
  RTC_MODCMD     = $00008000;               // Attempt to execute modified command

  // Run trace protocol types.
  RTL_ALL        = 0;                       // Log all commands
  RTL_JUMPS      = 1;                       // Taken jmp/call/ret/int + destinations
  RTL_CDEST      = 2;                       // Call destinations only
  RTL_MEM        = 3;                       // Access to memory

  // Hit trace outside the code section.
  HTNC_RUN       = 0;                       // Continue trace the same way as code
  HTNC_PAUSE     = 1;                       // Pause hit trace if outside the code
  HTNC_TRACE     = 2;                       // Trace command by command (run trace)

  // SFX extraction mode.
  SFM_RUNTRACE   = 0;                       // Use run trace to extract SFX
  SFM_HITTRACE   = 1;                       // Use hit trace to extract SFX

type
  p_rtcond = ^t_rtcond;                                   // Run trace break condition
  t_rtcond = packed record
    // These fields are saved to .udd data directly.
    options: Integer;                                     // Set of RTC_xxx
    inrange0: ULong;                                      // Start of in range
    inrange1: ULong;                                      // End of in range (not included)
    outrange0: ULong;                                     // Start of out range
    outrange1: ULong;                                     // End of out range (not included)
    count: ULong;                                         // Stop count
    currcount: ULong;                                     // Actual command count
    memaccess: array[0..NRANGE-1] of Integer;             // type of access (0; R, 1; W, 2; R/W)
    memrange0: array[0..NRANGE-1] of ULong;               // Start of memory range
    memrange1: array[0..NRANGE-1] of ULong;               // End of memory range
    // These fields are saved to .udd data truncated by first null.
    cond: array[0..NCOND-1,0..TEXTLEN-1] of WChar;        // Conditions as text
    cmd: array[0..NCMD-1,0..TEXTLEN-1] of WChar;          // Matching commands
    // These fields are not saved to .udd data.
    ccomp: array[0..NCOND-1,0..TEXTLEN-1] of UChar;       // Precompiled conditions
    validmodels: Integer;                                 // Valid command models, RTC_xxx
    model: array[0..NCMD-1,0..NSEARCHCMD-1] of t_asmmod;  // Command search models
    nmodel: array[0..NCMD-1] of Integer;                  // Number of slots in each model
  end;

  p_rtprot = ^t_rtprot;                     // Run trace protocol condition
  t_rtprot = packed record
    tracelogtype: Integer;                  // Commands to protocol, one of RTL_xxx
    memranges: Integer;                     // 0x1: range 1, 0x2: range 2 active
    memaccess: array[0..NRANGE-1] of Integer; // type of access (0; R, 1; W, 2; R/W)
    memrange0: array[0..NRANGE-1] of ULong; // Start of memory range
    memrange1: array[0..NRANGE-1] of ULong; // End of memory range
    rangeactive: Integer;                   // Log only commands in the range
    range: array[0..NRTPROT-1] of t_range;  // Set of EIP ranges to protocol
  end;

procedure Suspendallthreads; cdecl; external OLLYDBG name 'Suspendallthreads';
procedure Resumeallthreads; cdecl; external OLLYDBG name 'Resumeallthreads';
function  Pauseprocess: Integer; cdecl; external OLLYDBG name 'Pauseprocess';
function  Closeprocess(confirm: Integer): Integer; cdecl; external OLLYDBG name 'Closeprocess';
function  Detachprocess: Integer; cdecl; external OLLYDBG name 'Detachprocess';
function  Getlasterror(pthr: p_thread; error: PULong; s: PWChar): Integer; cdecl; external OLLYDBG name 'Getlasterror';
function  Followcall(addr: ULong): ULong; cdecl; external OLLYDBG name 'Followcall';
function  Run(status: t_status; pass: Integer): Integer; cdecl; external OLLYDBG name 'Run';
function  Checkfordebugevent: Integer; cdecl; external OLLYDBG name 'Checkfordebugevent';
function  Addprotocolrange(addr0: ULong; addr1: ULong): Integer; cdecl; external OLLYDBG name 'Addprotocolrange';
function  Getruntrace(nback: Integer; preg: p_reg; cmd: UChar): Integer; cdecl; external OLLYDBG name 'Getruntrace';
function  Findruntracerecord(addr0: ULong; addr1: ULong): Integer; cdecl; external OLLYDBG name 'Findruntracerecord';


////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// LIST OF GUIDS /////////////////////////////////
const
  GUIDSIZE       = 16;                   // GUID size, bytes

function Getguidname(data: UChar; ndata: ULong; name: PWChar): Integer; cdecl; external OLLYDBG name 'Getguidname';
function Isguid(addr: ULong; name: PWChar; nname: Integer): Integer; cdecl; external OLLYDBG name 'Isguid';


////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// SOURCE CODE //////////////////////////////////
type
  p_srcline = ^t_srcline;                   // Descriptor of source line
  t_srcline = packed record
    offset: ULong;                          // Offset in source text
    nextent: Integer;                       // Number of code extents (-1: unknown)
    extent: Integer;                        // Index of first extent (nextent>0)
  end;

  p_srcext = ^t_srcext;                     // Descriptor of code extent
  t_srcext = packed record
    amin: ULong;                            // Address of the first command
    amax: ULong;                            // Address of last command; included
  end;

  p_source = ^t_source;                     // Descriptor of source file
  t_source = packed record
    addr: ULong;                            // Module base plus file index
    size: ULong;                            // Dummy parameter, must be 1
    _type: ULong;                           // type, TY_xxx+SRC_xxx
    path: array[0..MAXPATH-1] of WChar;     // File path
    nameoffs: Integer;                      // Name offset in path, characters
    text: PAChar;                           // Source code in UTF-8 format or NULL
    line: p_srcline;                        // nline+1 line descriptors or NULL
    nline: Integer;                         // Number of lines (0: as yet unknown)
    extent: p_srcext;                       // List of code extents
    maxextent: Integer;                     // Capacity of extent table
    nextent: Integer;                       // Current number of extents
    lastline: Integer;                      // Last selected line
    lastoffset: Integer;                    // Last topmost visible line
  end;

function  Findsource(base: ULong; path: PWChar): p_source; cdecl; external OLLYDBG name 'Findsource';
function  Getsourceline(base: ULong; path: PWChar; line: Integer; skipspaces: Integer;
            text: PWChar; fname: PWChar; var extent: p_srcext; nextent: PInteger): Integer; cdecl; external OLLYDBG name 'Getsourceline';
function  Showsourcecode(base: ULong; path: PWChar; line: Integer): Integer; cdecl; external OLLYDBG name 'Showsourcecode';


////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// DEBUGGEE ///////////////////////////////////
const
  // Types of exception in application.
  AE_NONE        = 0;                       // No exception, or caused by OllyDbg
  AE_APP         = 1;                       // Exception in the application
  AE_SYS         = 2;                       // System exception, don't pass

type
  p_run = ^t_run;                           // Run status of debugged application
  t_run = packed record
    status: t_status;                       // Operation mode, one of STAT_xxx
    threadid: ULong;                        // ID of single running thread, 0 if all
    tpausing: ULong;                        // Tick count when pausing was requested
    wakestep: Integer;                      // 0: wait, 1: waked, 2: warned
    eip: ULong;                             // EIP at last debugging event
    ecx: ULong;                             // ECX at last debugging event
    restoreint3addr: ULong;                 // Address of temporarily removed INT3
    stepoverdest: ULong;                    // Destination of STAT_STEPOVER
    updatebppage: Integer;                  // Update temporarily removed bppage's
    de: DEBUG_EVENT;                        // Information from WaitForDebugEvent()
    indebugevent: Integer;                  // Paused on event, threads suspended
    netevent: Integer;                      // Event is from .NET debugger
    isappexception: Integer;                // Exception in application, AE_xxx
    lastexception: ULong;                   // Last exception in application or 0
    suspended: Integer;                     // Suspension counter
    suspendonpause: Integer;                // Whether first suspension on pause
    updatedebugreg: Integer;                // 1: set, -1: reset HW breakpoints
    dregmodified: Integer;                  // Debug regs modified by application
  end;


////////////////////////////////////////////////////////////////////////////////
//////////// OLLYDBG VARIABLES AND STRUCTURES ACCESSIBLE BY PLUGINS ////////////

// ATTENTION, never, ever change these variables directly! Either use plugin
// API or keep your hands off! Names of variables are preceded with underscore.

type
  p_bincmd_export = ^t_bincmd_export;
  t_bincmd_export = array[0..0] of t_bincmd;

  p_regname_export = ^t_regname_export;
  t_regname_export = array[0..2, 0..NREG-1] of PWChar;

  p_fpuname_export = ^t_fpuname_export;
  t_fpuname_export = array[0..1, 0..NREG-1] of PWChar;

  p_segname_export = ^t_nreg_export;
  p_mmxname_export = ^t_nreg_export;
  p_ssename_export = ^t_nreg_export;
  p_crname_export  = ^t_nreg_export;
  p_drname_export  = ^t_nreg_export;
  t_nreg_export = array[0..NREG-1] of PWChar;

  p_sizename_export = ^t_size_export;
  p_sizekey_export  = ^t_size_export;
  p_sizeatt_export  = ^t_size_export;
  t_size_export = array[0..16] of PWChar;

  p_font_export = ^t_font_export;
  t_font_export = array[0..NFIXFONTS-1] of t_font;

  p_color_export = ^t_color_export;
  t_color_export = array[0..NCOLORS-1] of COLORREF;

  p_scheme_export = ^t_scheme_export;
  t_scheme_export = array[0..NSCHEMES-1] of t_scheme;

  p_hilite_export = ^t_hilite_export ;
  t_hilite_export = array[0..NHILITE] of t_scheme;

var

  ///////////////////////////////// DISASSEMBLER /////////////////////////////////

  bincmd: p_bincmd_export;                  // List of 80x86 commands

  regname: p_regname_export;                // Names of 8/16/32-bit registers
  segname: p_segname_export;                // Names of segment registers
  fpuname: p_fpuname_export;                // FPU regs (ST(n) and STn forms)
  mmxname: p_mmxname_export;                // Names of MMX/3DNow! registers
  ssename: p_ssename_export;                // Names of SSE registers
  crname: p_crname_export;                  // Names of control registers
  drname: p_drname_export;                  // Names of debug registers
  sizename: p_sizename_export;              // Data size keywords
  sizekey: p_sizekey_export;                // Keywords for immediate data
  sizeatt: p_sizeatt_export;                // Keywords for immediate data, AT&T

  /////////////////////////////// OLLYDBG SETTINGS ///////////////////////////////

  ollyfile: PWChar;                         // Path to OllyDbg
  ollydir: PWChar;                          // OllyDbg directory w/o backslash
  systemdir: PWChar;                        // Windows system directory
  plugindir: PWChar;                        // Plugin data dir without backslash
  hollyinst: PHandle;                       // Current OllyDbg instance
  hwollymain: PHandle;                      // Handle of the main OllyDbg window
  hwclient: PHandle;                        // Handle of MDI client or NULL
  ottable: PWChar;                          // Class of table windows
  cpufeatures: PULong;                      // CPUID feature information
  ischild: PInteger;                        // Whether child debugger
  asciicodepage: PInteger;                  // Code page to display ASCII dumps
  mbcscodepage: PInteger;                   // Code page to display MBCS dumps (add by TQN)
  tracefile: p_file;                        // System log file (FILE *) or NULL
  restorewinpos: PInteger;                  // Restore window position & appearance

  ////////////////////////////// OLLYDBG STRUCTURES //////////////////////////////

  font: p_font_export;                      // Fixed fonts used in table windows
  sysfont: p_font;                          // Proportional system font
  titlefont: p_font;                        // Proportional, 2x height of sysfont
  fixfont: p_font;                          // Fixed system font
  color:p_color_export;                     // Colours used by OllyDbg
  scheme: p_scheme_export;                  // Colour schemes used in table windows
  hilite: p_hilite_export;                  // Colour schemes used for highlighting

  /////////////////////////////////// DEBUGGEE ///////////////////////////////////

  executable: PWChar;                       // Path to main (.exe) file
  arguments: PWChar;                        // Command line passed to debuggee

  netdbg: PInteger;                         // .NET debugging active
  rundll: PInteger;                         // Debugged file is a DLL
  process: PHandle;                         // Handle of Debuggee or NULL
  processid: PULong;                        // Process ID of Debuggee or 0
  mainthreadid: PULong;                     // Thread ID of main thread or 0
  _run: p_run;                              // Run status of debugged application
  skipsystembp: PInteger;                   // First system INT3 not yet hit

  debugbreak: PULong;                        // Address of DebugBreak() in Debuggee
  dbgbreakpoint: PULong;                     // Address of DbgBreakPoint() in Debuggee
  kiuserexcept: PULong;                      // Address of KiUserExceptionDispatcher()
  zwcontinue: PULong;                        // Address of ZwContinue() in Debuggee
  uefilter: PULong;                          // Address of UnhandledExceptionFilter()
  ntqueryinfo: PULong;                       // Address of NtQueryInformationProcess()
  corexemain: PULong;                        // Address of MSCOREE:_CorExeMain()
  peblock: PULong;                           // Address of PE block in Debuggee
  kusershareddata: PULong;                   // Address of KUSER_SHARED_DATA
  userspacelimit: PULong;                    // Size of virtual process memory

  rtcond: p_rtcond;                         // Run trace break condition
  rtprot: p_rtprot;                         // Run trace protocol condition

  ///////////////////////////////// DATA TABLES //////////////////////////////////

  list: p_table;                            // List descriptor
  premod: p_sorted;                         // Preliminary module data
  module: p_table;                          // Loaded modules
  aqueue: p_sorted;                         // Modules that are not yet analysed
  thread: p_table;                          // Active threads
  memory: p_table;                          // Allocated memory blocks
  win: p_table;                             // List of windows
  handles: p_table;                         // Handles (add by TQN)
  bpoint: p_table;                          // INT3 breakpoints
  bpmem: p_table;                           // Memory breakpoints
  bppage: p_sorted;                         // Memory pages with changed attributes
  bphard: p_table;                          // Hardware breakpoints
  watch: p_table;                           // Watch expressions
  patch: p_table;                           // List of patches from previous runs
  procdata: p_sorted;                       // Descriptions of analyzed procedures
  encaddr: p_sorted;                        // Unknown (add by TQN)
  sehchain: p_table;                        // SEH chain (add by TQN)
  callstk: p_table;                         // Call stack (add by TQN)
  source: p_table;                          // List of source files
  srccode: p_table;                         // Source code


////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// PLUGIN EXPORTS ////////////////////////////////
const
  // Relatively infrequent events passed to ODBG2_Pluginnotify().
  PN_NEWPROC     = 1;                       // New process is created
  PN_ENDPROC     = 2;                       // Process is terminated
  PN_NEWTHR      = 3;                       // New thread is created
  PN_ENDTHR      = 4;                       // Thread is terminated
  PN_PREMOD      = 5;                       // New module is reported by Windows
  PN_NEWMOD      = 6;                       // New module is added to the table
  PN_ENDMOD      = 7;                       // Module is removed from the memory
  PN_STATUS      = 8;                       // Execution status has changed
  PN_REMOVE      = 16;                      // OllyDbg removes analysis from range
  PN_RUN         = 24;                      // User continues code execution

  // Flags returned by ODBG2_Pluginexception().
  PE_IGNORED     = $00000000;               // Plugin does not process exception
  PE_CONTINUE    = $00000001;               // Exception by plugin, continue
  PE_STEP        = $00000002;               // Exception by plugin, execute command
  PE_PAUSE       = $00000004;               // Exception by plugin, pause program

procedure LogError(err: Boolean; const pwzMsg: PWChar);

implementation

function Iscall;
begin
  Result:= (jmp._type = JT_CALL ) or (jmp._type = JT_SWCALL);
end;

function Isjump;
begin
  Result:= ((jmp._type >= JT_JUMP ) and (jmp._type <= JT_RET)) or
           ((jmp._type >= JT_NETJUMP) and (jmp._type <= JT_NETSW));
end;

function IS_REAL(r: Integer): Boolean;
begin
  Result := r > REG_R32;
end;

function IS_PSEUDO(r: Integer): Boolean;
begin
  Result := r >= REG_R32;
end;

function IS_SEMI(r: Integer): Boolean;
begin
  Result := r >= REG_RA;
end;

procedure LogError(err: Boolean; const pwzMsg: PWChar);
const
  pfnLog: procedure(addr: ULong; color: Integer; format: PWChar); cdecl = nil;
begin
  if err then
  begin
    if IsConsole then
      WriteLn(string(pwzMsg))
    else if IsLibrary then
    begin
      if @pfnLog = nil then
        pfnLog := GetProcAddress(GetModuleHandle(nil), PAChar('_Addtolist'));

      if @pfnLog <> nil then
        pfnLog(0, DRAW_HILITE, pwzMsg)
      else
        OutputDebugStringW(pwzMsg);
    end
    else
      OutputDebugStringW(pwzMsg);
  end;
end;

function GetOdbg2ExportVars: Boolean;
var
  hOdbg2: THandle;
begin
  hOdbg2 := GetModuleHandle(nil);

  bincmd          := GetProcAddress(hOdbg2, PAChar('_bincmd'));

  regname         := GetProcAddress(hOdbg2, PAChar('_regname'));
  segname         := GetProcAddress(hOdbg2, PAChar('_segname'));
  fpuname         := GetProcAddress(hOdbg2, PAChar('_fpuname'));
  mmxname         := GetProcAddress(hOdbg2, PAChar('_mmxname'));
  ssename         := GetProcAddress(hOdbg2, PAChar('_ssename'));
  crname          := GetProcAddress(hOdbg2, PAChar('_crname'));
  drname          := GetProcAddress(hOdbg2, PAChar('_drname'));
  sizename        := GetProcAddress(hOdbg2, PAChar('_sizename'));
  sizekey         := GetProcAddress(hOdbg2, PAChar('_sizekey'));
  sizeatt         := GetProcAddress(hOdbg2, PAChar('_sizeatt'));

  ollyfile        := GetProcAddress(hOdbg2, PAChar('_ollyfile'));
  ollydir         := GetProcAddress(hOdbg2, PAChar('_ollydir'));
  systemdir       := GetProcAddress(hOdbg2, PAChar('_systemdir'));
  plugindir       := GetProcAddress(hOdbg2, PAChar('_plugindir'));
  hollyinst       := GetProcAddress(hOdbg2, PAChar('_hollyinst'));
  hwollymain      := GetProcAddress(hOdbg2, PAChar('_hwollymain'));
  hwclient        := GetProcAddress(hOdbg2, PAChar('_hwclient'));
  ottable         := GetProcAddress(hOdbg2, PAChar('_ottable'));
  cpufeatures     := GetProcAddress(hOdbg2, PAChar('_cpufeatures'));
  ischild         := GetProcAddress(hOdbg2, PAChar('_ischild'));
  asciicodepage   := GetProcAddress(hOdbg2, PAChar('_asciicodepage'));
  mbcscodepage    := GetProcAddress(hOdbg2, PAChar('_mbcscodepage'));
  tracefile       := GetProcAddress(hOdbg2, PAChar('_tracefile'));
  restorewinpos   := GetProcAddress(hOdbg2, PAChar('_restorewinpos'));

  font            := GetProcAddress(hOdbg2, PAChar('_font'));
  sysfont         := GetProcAddress(hOdbg2, PAChar('_sysfont'));
  titlefont       := GetProcAddress(hOdbg2, PAChar('_titlefont'));
  fixfont         := GetProcAddress(hOdbg2, PAChar('_fixfont'));
  color           := GetProcAddress(hOdbg2, PAChar('_color'));
  scheme          := GetProcAddress(hOdbg2, PAChar('_scheme'));
  hilite          := GetProcAddress(hOdbg2, PAChar('_hilite'));

  executable      := GetProcAddress(hOdbg2, PAChar('_executable'));
  arguments       := GetProcAddress(hOdbg2, PAChar('_arguments'));
  netdbg          := GetProcAddress(hOdbg2, PAChar('_netdbg'));
  rundll          := GetProcAddress(hOdbg2, PAChar('_rundll'));
  process         := GetProcAddress(hOdbg2, PAChar('_process'));
  processid       := GetProcAddress(hOdbg2, PAChar('_processid'));
  mainthreadid    := GetProcAddress(hOdbg2, PAChar('_mainthreadid'));
  _run            := GetProcAddress(hOdbg2, PAChar('_run'));
  skipsystembp    := GetProcAddress(hOdbg2, PAChar('_skipsystembp'));
  debugbreak      := GetProcAddress(hOdbg2, PAChar('_debugbreak'));
  dbgbreakpoint   := GetProcAddress(hOdbg2, PAChar('_dbgbreakpoint'));
  kiuserexcept    := GetProcAddress(hOdbg2, PAChar('_kiuserexcept'));
  zwcontinue      := GetProcAddress(hOdbg2, PAChar('_zwcontinue'));
  uefilter        := GetProcAddress(hOdbg2, PAChar('_uefilter'));
  ntqueryinfo     := GetProcAddress(hOdbg2, PAChar('_ntqueryinfo'));
  corexemain      := GetProcAddress(hOdbg2, PAChar('_corexemain'));
  peblock         := GetProcAddress(hOdbg2, PAChar('_peblock'));
  kusershareddata := GetProcAddress(hOdbg2, PAChar('_kusershareddata'));
  userspacelimit  := GetProcAddress(hOdbg2, PAChar('_userspacelimit'));
  rtcond          := GetProcAddress(hOdbg2, PAChar('_rtcond'));
  rtprot          := GetProcAddress(hOdbg2, PAChar('_rtprot'));

  list            := GetProcAddress(hOdbg2, PAChar('_list'));
  premod          := GetProcAddress(hOdbg2, PAChar('_premod'));
  module          := GetProcAddress(hOdbg2, PAChar('_module'));
  aqueue          := GetProcAddress(hOdbg2, PAChar('_aqueue'));
  thread          := GetProcAddress(hOdbg2, PAChar('_thread'));
  memory          := GetProcAddress(hOdbg2, PAChar('_memory'));
  win             := GetProcAddress(hOdbg2, PAChar('_win'));
  handles         := GetProcAddress(hOdbg2, PAChar('_handles'));
  bpoint          := GetProcAddress(hOdbg2, PAChar('_bpoint'));
  bpmem           := GetProcAddress(hOdbg2, PAChar('_bpmem'));
  bppage          := GetProcAddress(hOdbg2, PAChar('_bppage'));
  bphard          := GetProcAddress(hOdbg2, PAChar('_bphard'));
  watch           := GetProcAddress(hOdbg2, PAChar('_watch'));
  patch           := GetProcAddress(hOdbg2, PAChar('_patch'));
  procdata        := GetProcAddress(hOdbg2, PAChar('_procdata'));
  encaddr         := GetProcAddress(hOdbg2, PAChar('_encaddr'));
  sehchain        := GetProcAddress(hOdbg2, PAChar('_sehchain'));
  callstk         := GetProcAddress(hOdbg2, PAChar('_callstk'));
  source          := GetProcAddress(hOdbg2, PAChar('_source'));
  srccode         := GetProcAddress(hOdbg2, PAChar('_srccode'));

{$IFDEF DEBUG}
  LogError(bincmd = nil, 'bincmd export variable not found');
  LogError(regname = nil, 'regname export variable not found');
  LogError(segname = nil, 'segname export variable not found');
  LogError(fpuname = nil, 'fpuname export variable not found');
  LogError(mmxname = nil, 'mmxname export variable not found');
  LogError(ssename = nil, 'ssename export variable not found');
  LogError(crname = nil, 'crname export variable not found');
  LogError(drname = nil, 'drname export variable not found');
  LogError(sizename = nil, 'sizename export variable not found');
  LogError(sizekey = nil, 'sizekey export variable not found');
  LogError(sizeatt = nil, 'sizeatt export variable not found');
  LogError(ollyfile = nil, 'ollyfile export variable not found');
  LogError(ollydir = nil, 'ollydir export variable not found');
  LogError(systemdir = nil, 'systemdir export variable not found');
  LogError(plugindir = nil, 'plugindir export variable not found');
  LogError(hollyinst = nil, 'hollyinst export variable not found');
  LogError(hwollymain = nil, 'hwollymain export variable not found');
  LogError(hwclient = nil, 'hwclient export variable not found');
  LogError(ottable = nil, 'ottable export variable not found');
  LogError(cpufeatures = nil, 'cpufeatures export variable not found');
  LogError(ischild = nil, 'ischild export variable not found');
  LogError(asciicodepage = nil, 'asciicodepage export variable not found');
  LogError(mbcscodepage = nil, 'mbcscodepage export variable not found');
  LogError(tracefile = nil, 'tracefile export variable not found');
  LogError(restorewinpos = nil, 'restorewinpos export variable not found');
  LogError(font = nil, 'font export variable not found');
  LogError(sysfont = nil, 'sysfont export variable not found');
  LogError(titlefont = nil, 'titlefont export variable not found');
  LogError(fixfont = nil, 'fixfont export variable not found');
  LogError(color = nil, 'color export variable not found');
  LogError(scheme = nil, 'scheme  export variable not found');
  LogError(hilite = nil, 'hilite export variable not found');
  LogError(executable = nil, 'executable export variable not found');
  LogError(arguments = nil, 'arguments export variable not found');
  LogError(netdbg = nil, 'netdbg export variable not found');
  LogError(rundll = nil, 'rundll export variable not found');
  LogError(process = nil, 'process export variable not found');
  LogError(processid = nil, 'processid export variable not found');
  LogError(mainthreadid = nil, 'mainthreadid export variable not found');
  LogError(_run = nil, '_run export variable not found');
  LogError(skipsystembp = nil, 'skipsystembp export variable not found');
  LogError(debugbreak = nil, 'debugbreak export variable not found');
  LogError(dbgbreakpoint = nil, 'dbgbreakpoint export variable not found');
  LogError(kiuserexcept = nil, 'kiuserexcept export variable not found');
  LogError(zwcontinue = nil, 'zwcontinue export variable not found');
  LogError(uefilter = nil, 'uefilter export variable not found');
  LogError(ntqueryinfo = nil, 'ntqueryinfo export variable not found');
  LogError(corexemain = nil, 'corexemain export variable not found');
  LogError(peblock = nil, 'peblock export variable not found');
  LogError(kusershareddata = nil, 'kusershareddata export variable not found');
  LogError(userspacelimit = nil, 'userspacelimit export variable not found');
  LogError(rtcond = nil, 'rtcond export variable not found');
  LogError(rtprot = nil, 'rtprot export variable not found');
  LogError(list = nil, 'list export variable not found');
  LogError(premod = nil, 'premod export variable not found');
  LogError(module = nil, 'module export variable not found');
  LogError(aqueue = nil, 'aqueue export variable not found');
  LogError(thread = nil, 'thread export variable not found');
  LogError(memory = nil, 'memory export variable not found');
  LogError(win = nil, 'win export variable not found');
  LogError(handles = nil, 'handles export variable not found');
  LogError(bpoint = nil, 'bpoint export variable not found');
  LogError(bpmem = nil, 'bpmem export variable not found');
  LogError(bppage = nil, 'bppage export variable not found');
  LogError(bphard = nil, 'bphard export variable not found');
  LogError(watch = nil, 'watch export variable not found');
  LogError(patch = nil, 'patch export variable not found');
  LogError(procdata = nil, 'procdata export variable not found');
  LogError(encaddr = nil, 'encaddr export variable not found');
  LogError(sehchain = nil, 'sehchain export variable not found');
  LogError(callstk = nil, 'callstk export variable not found');
  LogError(source = nil, 'source export variable not found');
  LogError(srccode = nil, 'srccode export variable not found');
{$ENDIF ~DEBUG}

  Result := (bincmd <> nil) and
            (regname <> nil) and
            (segname <> nil) and
            (fpuname <> nil) and
            (mmxname <> nil) and
            (ssename <> nil) and
            (crname <> nil) and
            (drname <> nil) and
            (sizename <> nil) and
            (sizekey <> nil) and
            (sizeatt <> nil) and
            (ollyfile <> nil) and
            (ollydir <> nil) and
            (systemdir <> nil) and
            (plugindir <> nil) and
            (hollyinst <> nil) and
            (hwollymain <> nil) and
            (hwclient <> nil) and
            (ottable <> nil) and
            (cpufeatures <> nil) and
            (ischild <> nil) and
            (asciicodepage <> nil) and
            (mbcscodepage <> nil) and
            (tracefile <> nil) and
            (restorewinpos <> nil) and
            (font <> nil) and
            (sysfont <> nil) and
            (titlefont <> nil) and
            (fixfont <> nil) and
            (color <> nil) and
            (scheme <> nil) and
            (hilite <> nil) and
            (executable <> nil) and
            (arguments <> nil) and
            (netdbg <> nil) and
            (rundll <> nil) and
            (process <> nil) and
            (processid <> nil) and
            (mainthreadid <> nil) and
            (_run <> nil) and
            (skipsystembp <> nil) and
            (debugbreak <> nil) and
            (dbgbreakpoint <> nil) and
            (kiuserexcept <> nil) and
            (zwcontinue <> nil) and
            (uefilter <> nil) and
            (ntqueryinfo <> nil) and
            (corexemain <> nil) and
            (peblock <> nil) and
            (kusershareddata <> nil) and
            (userspacelimit <> nil) and
            (rtcond <> nil) and
            (rtprot <> nil) and
            (list <> nil) and
            (premod <> nil) and
            (module <> nil) and
            (aqueue <> nil) and
            (thread <> nil) and
            (memory <> nil) and
            (win <> nil) and
            (handles <> nil) and
            (bpoint <> nil) and
            (bpmem <> nil) and
            (bppage <> nil) and
            (bphard <> nil) and
            (watch <> nil) and
            (patch <> nil) and
            (procdata <> nil) and
            (encaddr <> nil) and
            (sehchain <> nil) and
            (callstk <> nil) and
            (source <> nil) and
            (srccode <> nil);
end;


(*
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
function  ODBG2_Pluginquery(ollydbgversion: Integer; features: PULong; pluginname, pluginversion: PWChar): Integer; cdecl;
function  ODBG2_Plugininit: Integer; cdecl;
procedure ODBG2_Pluginanalyse(pmod: p_module); cdecl;
procedure ODBG2_Pluginmainloop(pDbgEvent: PDebugEvent); cdecl;
function  ODBG2_Pluginexception(prun: p_run; const da: p_disasm; pthr: p_thread; preg: p_reg; message: PWChar): Integer; cdecl;
procedure ODBG2_Plugintempbreakpoint(addr: ULong; const da: p_disasm; pthr: p_thread; preg: p_reg); cdecl;
procedure ODBG2_Pluginnotify(code: Integer; data: Pointer; parm1: ULong; parm2: ULong); cdecl;
function  ODBG2_Plugindump(pd: p_dump; s: PWChar; mask: PWChar; n: Integer; select: PInteger; addr: ULong; column: Integer): Integer; cdecl;
function  ODBG2_Pluginmenu(ptype: PWChar): p_menu; cdecl;
function  ODBG2_Pluginoptions(msg: UINT; wp: WPARAM; lp: LPARAM): p_control; cdecl;
procedure ODBG2_Pluginsaveudd(psave: p_uddsave; pmod: p_module; ismainmodule: Integer); cdecl;
procedure ODBG2_Pluginuddrecord(pmod: p_module; ismainmodule: Integer; tag: ULong; size: ULong; data: pointer); cdecl;
procedure ODBG2_Pluginreset; cdecl;
function  ODBG2_Pluginclose: Integer; cdecl;
procedure ODBG2_Plugindestroy; cdecl;
*)

initialization
  if not GetOdbg2ExportVars then
  begin
{$IFDEF DEBUG}
    LogError(True, 'Some export variables of OllyDbg2 not found');
{$ENDIF ~DEBUG}
  end;

end.
