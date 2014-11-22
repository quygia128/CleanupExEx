Library CleanupExEx;
(*
 * CleanupExEx v201.01
 * Author: quygia128
 * IDE: Delphi
 * Date: 11.25.2013
 *
 * Name of plugin get from a good plugin is "CleanupEx" by Gigapede
 * v2 - Coded by atom0s (OllyDbg 2.x)
 * v1 - Coded by Gigapede (OllyDbg 1.x)
 *
 * Thanks and Credits to: TQN, phpbb3, BOB, Gigapede, atom0s,
 * of course thanks to all CiN1's members & all my friends.
 *)

uses
  Windows, plugin2, CleanupEx;
  {$WARN UNSAFE_CODE OFF}
  {$WARN UNSAFE_TYPE OFF}
  {$WARN UNSAFE_CAST OFF}
  {$R Resource.res}

  function ShellExecuteW(hWnd:HWND;Operation,FileName,Parameters,Directory: PWChar;ShowCmd: Integer): HINST; stdcall; external 'shell32.dll' name 'ShellExecuteW';
  function MP_MainMenu(table:P_table;text:PWChar;index:ULong;mode:LongInt): LongInt; cdecl; forward;

var
  SaveDLLProc: TDLLProc;

const
  PLUGIN_NAME: PWChar = 'CleanupExEx';
  PLUGIN_VERS: PWChar = '201.01';
  PLUGIN_AUTH: PWChar = 'quygia128';
  PLUGIN_SITE: PWChar = 'http://cin1team.biz';
  PLUGIN_BLOG: PWChar = 'http://crackertool.blogspot.com';
  PLUGIN_DATE: PWChar = '11.25.2013';

  DEL_ALL: LongInt = 1;
  DEL_UDD: LongInt = 2;
  DEL_BAK: LongInt = 3;
  DEL_XXX: LongInt = 4;
////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// Plugin Menu ///////////////////////////////

MainMenu:array[0..8] of t_menu=(
  (Name:'All OllyDbg Data (*.*)';help: nil;shortcutid: 0;menufunc: MP_MainMenu;submenu: nil;menuType: (index: 1)),
  (Name:'|All Debug Data (*.UDD)';help: nil;shortcutid: 0;menufunc: MP_MainMenu;submenu: nil;menuType: (index: 2)),
  (Name:'All Backup Data (*.BAK)';help: nil;shortcutid: 0;menufunc: MP_MainMenu;submenu: nil;menuType: (index: 3)),
  (Name: '|++++ Future Data (*.XXX)';help: nil;shortcutid: 0;menufunc: MP_MainMenu;submenu: nil;menuType: (index: 4)),
  (Name:'|Latest Used (*.UDD;*.BAK)';help: nil;shortcutid: 0;menufunc: MP_MainMenu;submenu: nil;menuType: (index: 5)),
  (Name:'Open UDD Directory';help: nil;shortcutid: 0;menufunc: MP_MainMenu;submenu: nil;menuType: (index: 6)),
  (Name:'|Empty Recent Files Debug List';help: nil;shortcutid: 0;menufunc: MP_MainMenu;submenu: nil;menuType: (index: 7)),
  (Name:'|About..';help: '^-^';shortcutid: 0;menufunc: MP_MainMenu;submenu: nil;menuType: (index: 8)),
  ()
  );
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// Plugin Menu End /////////////////////////////

(*
function IntToStr(Value: DWord): string;
begin
  Str(Value, Result);
end;

function StrToInt(const S: string): Integer;
var
  E: Integer;
begin
  Val(S, Result, E);
  //if E <> 0 then ConvertErrorFmt(@SInvalidInteger, [S]);
end;

function IntToHex(Int: DWord; Digit: byte): string;
var
  OutStr: array[0..9] of AnsiChar;
  FmtStr: string;
begin
  FmtStr:= '%'+ IntToStr(Digit)+'.'+ IntToStr(Digit) +'X'+#0;
  asm
    push  Int
    push  FmtStr;
    lea   eax, OutStr[0]
    push  eax
    call  wsprintfA
    add   esp, 4*3
  end;
  Result:= string(OutStr);
end;

function UpperString(S: string): string;
var
  i: Integer;
begin
  for i:= 1 to Length(S) do
    S[i]:= Ansichar(CharUpper(PAnsiChar(S[i])));
  Result:= S;
end;

//==============================================================================
// Return minimum value of two params ..
function Min(const A, B: DWORD): DWORD;          //This code from BOB in WinMax2
Begin
  If (A <= B) Then Result:= A Else Result:= B;
End;
//==============================================================================
// Return pointer of mem allocate...
function AllocMem(const Size: DWORD): Pointer;
Begin
  GetMem(Result, Size);
  if (Result <> nil) then FillChar(Result^, Size, 0);
End;

//==============================================================================
// Return allocated ansi string converted from widechar ..
function AsAnsi(const Src: PWChar) : PAnsiChar;  //This code from BOB in WinMax2
var
  WL: DWORD;
  Len: DWORD;
Begin
  Result:= nil;
  if IsBadReadPtr(Src, Max_Path) then Exit;
  // Get length of Wide string ..
  WL:= 0;
  while (Src[WL] <> #0) do Inc(WL);
  // Get Length of buffer needed ..
  Len:= WideCharToMultiByte(GetACP, 0, Src, WL, Result, 0, nil, nil);
  Result:= AllocMem(Len + 2);
  // Convert string and return ..
  WideCharToMultiByte(GetACP, 0, Src, WL, Result, Len, nil, nil);
End;
//==============================================================================
// Return string from widechar ..
function  WideToStr(const Src: PWChar): string;  //This code from BOB in WinMax2
var
  A: PAnsiChar;
  L: DWORD;
Begin
  Result:= '';
  A:= AsAnsi(Src);
  if (not IsBadReadPtr(A, MAX_PATH)) then
  try
    L:= lstrlenA(A);
    SetLength(Result, L);
    Move(A^, Result[1], L);
  finally
    FreeMem(A);
  end;
End;

function  WriteUnicode(Const Src: PChar; Const Dst: PWChar; Const MaxLen: DWORD): DWORD;
var
  Len: DWORD;
Begin
  Result:= 0;
  If IsBadWritePtr(Dst, Max_Path) Then Exit;
  FillMemory(Dst, MaxLen Shl 1, 0);
  If IsBadReadPtr(Src, Max_Path) Then Exit;
  Result:= lstrlenA(Src);
  If (Result = 0) Then Exit;
  Len:= Min(Result, MaxLen);
  // Get Length of buffer needed ..
  Result:= MultiByteToWideChar(GetACP, 0, Src, Len, Dst, 0);
  // Convert string and return length ..
  Result:= MultiByteToWideChar(GetACP, 0, Src, Len, Dst, Result);
End;
////////////////////////////////////////////////////////////////////////////////
function GetOllyIni: string;
var
  OD2Dir: string;
  i: LongInt;
begin
  OD2Dir:= PAnsiChar(WideToStr(ollyfile^));
  for i:= lstrlenA(PAnsiChar(OD2Dir)) downto 1 do begin
    if OD2Dir[i] <> '.' then OD2Dir[i]:= #0
    else begin
      OD2Dir:= lstrcatA(PAnsiChar(OD2Dir),PAnsiChar('ini'));
      Break;
    end;
  end;
  Result:= OD2Dir;
end;

function GetPluginPath: PAnsiChar;
var
  i: WORD;
  oddir: PAnsiChar;
begin
  Result:= nil;
  oddir:= PChar(WideToStr(plugindir^));
  for i:= lstrlenA(oddir) downto 1 do begin
    if oddir[i] <> '\' then oddir[i]:= #0
    else begin
      oddir[i]:= #0;
      Break;
    end;
  end;
  Result:= oddir;
end;
*)
////////////////////////////////////////////////////////////////////////////////
function MP_MainMenu(table:P_table;text:PWChar;index:ULong;mode:LongInt): LongInt;
var
  szinfo:array[0..TEXTLEN*2-1] of WCHAR;
  szUDDPath:array[0..MAXPATH-1] of WCHAR;
  n: LongInt;
begin
  case mode of
    MENU_VERIFY: begin
      Result:= MENU_NORMAL;
      {
      case index of
        1: Begin
          Result:= MENU_NORMAL;
        end;
      end;
      }
    end;
    MENU_EXECUTE: begin
      Result:= MENU_NOREDRAW;
      case index of
        1: begin
          // Delete all olly data
          DeleteFilesProc(DEL_ALL);
        end;
        2:begin
          // Delete all debug data
          DeleteFilesProc(DEL_UDD);
        end;
        3: begin
          // Delete all bak file
          DeleteFilesProc(DEL_BAK);
        end;
        4:begin
          // For Future
          DeleteFilesProc(DEL_XXX);
        end;
        5:begin
          DeletelatestData;
        end;
        6:begin
          ZeroMemory(@szUDDPath,sizeof(szUDDPath));
          Swprintf(szUDDPath,@ollydir^);
          n:= StrlenW(szUDDPath,TEXTLEN);
          Swprintf(szUDDPath+n,'\UDD');
          if ShellExecuteW(hwOllymain^,'OPEN',szUDDPath,nil,nil,SW_NORMAL) <= 32 then
            if CreateDirectoryW(szUDDPath,nil) then
              ShellExecuteW(hwOllymain^,'OPEN',szUDDPath,nil,nil,SW_NORMAL);
        end;
        7:begin
          Writetoini(nil,'History','Executable[0]','');
          Writetoini(nil,'History','Arguments[0]','');
          Writetoini(nil,'History','Current dir[0]','');

          Writetoini(nil,'History','Executable[1]','');
          Writetoini(nil,'History','Arguments[1]','');
          Writetoini(nil,'History','Current dir[1]','');

          Writetoini(nil,'History','Executable[2]','');
          Writetoini(nil,'History','Arguments[2]','');
          Writetoini(nil,'History','Current dir[2]','');

          Writetoini(nil,'History','Executable[3]','');
          Writetoini(nil,'History','Arguments[3]','');
          Writetoini(nil,'History','Current dir[3]','');

          Writetoini(nil,'History','Executable[4]','');
          Writetoini(nil,'History','Arguments[4]','');
          Writetoini(nil,'History','Current dir[4]','');

          Writetoini(nil,'History','Executable[5]','');
          Writetoini(nil,'History','Arguments[5]','');
          Writetoini(nil,'History','Current dir[5]','');

          Writetoini(nil,'History','Executable[6]','');
          Writetoini(nil,'History','Arguments[6]','');
          Writetoini(nil,'History','Current dir[6]','');
        end;
        8: begin
          Suspendallthreads;
          FillChar(szinfo,SizeOf(szinfo),#0);
          Swprintf(szinfo,'%s v%s ~ Date: %s'#10#10, PLUGIN_NAME, PLUGIN_VERS,PLUGIN_DATE);
          n:= StrlenW(szinfo,TEXTLEN*2);
          Swprintf(szinfo+n,'Coded by %s'#10'Home: %s'#10#10,PLUGIN_AUTH, PLUGIN_SITE);
          n:= StrlenW(szinfo,TEXTLEN*2);
          Swprintf(szinfo+n,'I want to say thanks to:'#10'CiN1''s members & all my friends'#10#10);
          n:= StrlenW(szinfo,TEXTLEN*2);
          Swprintf(szinfo+n,'Greetz fly go to:'#10'AT4RE ~ ARTeam ~ eXeTools ~ FFF'#10'SnD ~ AORET ~ REPT ~ REA ~ CIN1'#10#10);
          MessageBoxW(hwollymain^,szinfo,'-=About=-',MB_OK);
          Resumeallthreads;
        end;
      end;
    end;
  else
    Result:= 0;
  end;
end;

// ODBG_Pluginquery() is a "must" for valid OllyDbg plugin. First it must check
// whether given OllyDbg version is correctly supported, and return 0 if not.
// Then it should make one-time initializations and allocate resources. On
// error, it must clean up and return 0. On success, if should fill plugin name
// and plugin version (as UNICODE strings) and return version of expected
// plugin interface. If OllyDbg decides that this plugin is not compatible, it
// will call ODBG2_Plugindestroy() and unload plugin. Plugin name identifies it
// in the Plugins menu. This name is max. 31 alphanumerical UNICODE characters
// or spaces + terminating L'\0' long. To keep life easy for users, this name
// should be descriptive and correlate with the name of DLL. This function
// replaces ODBG_Plugindata() and ODBG_Plugininit() from the version 1.xx.
function  ODBG2_Pluginquery(ollydbgversion: LongInt;features: PULong;pluginname,pluginversion: PWChar): LongInt; cdecl;
Begin
  if (ollydbgversion < 201) then Result:= 0
  else begin
    lstrcpyW(pluginname,PLUGIN_NAME);
    lstrcmpW(pluginversion,PLUGIN_VERS);
    Result:= PLUGIN_VERSION;
  end;
End;

function  fr332_Pluginquery(ollydbgversion: LongInt;features: PULong;pluginname,pluginversion: PWChar): LongInt; cdecl;
Begin
  if (ollydbgversion < 201) then Result:= 0
  else begin
    lstrcpyW(pluginname,PLUGIN_NAME);
    lstrcpyW(pluginversion,PLUGIN_VERS);
    Result:= PLUGIN_VERSION;
  end;
End;

// Optional entry, called immediately after ODBG2_Plugininit(). Plugin should
// make one-time initializations and allocate resources. On error, it must
// clean up and return -1. On success, it must return 0.
function  ODBG2_Plugininit: LongInt; cdecl;
Begin
  Addtolist(DRAW_NORMAL,DRAW_GRAY,' ');
  Addtolist(DRAW_NORMAL,DRAW_HILITE,'- %s v%s by %s. Compiled Date: %s', PLUGIN_NAME, PLUGIN_VERS, PLUGIN_AUTH, PLUGIN_DATE);
  Addtolist(DRAW_NORMAL,DRAW_GRAY,' - Home: %s',PLUGIN_SITE);
  Addtolist(DRAW_NORMAL,DRAW_GRAY,' - Blog: %s',PLUGIN_BLOG);
  Addtolist(DRAW_NORMAL,DRAW_GRAY,' - ');
  Result:= 0;
End;

function  fr332_Plugininit: LongInt; cdecl;
Begin
  Addtolist(DRAW_NORMAL,DRAW_GRAY,' ');
  Addtolist(DRAW_NORMAL,DRAW_HILITE,'- %s v%s by %s. Compiled Date: %s', PLUGIN_NAME, PLUGIN_VERS, PLUGIN_AUTH, PLUGIN_DATE);
  Addtolist(DRAW_NORMAL,DRAW_GRAY,' - Home: %s',PLUGIN_SITE);
  Addtolist(DRAW_NORMAL,DRAW_GRAY,' - Blog: %s',PLUGIN_BLOG);
  Addtolist(DRAW_NORMAL,DRAW_GRAY,' - ');
  Result:= 0;
End;
////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// DUMP WINDOW HOOK ///////////////////////////////

// Dump windows display contents of memory or file as bytes, characters,
// integers, floats or disassembled commands. Plugins have the option to modify
// the contents of the dump windows. If ODBG2_Plugindump() is present and some
// dump window is being redrawn, this function is called first with column=
// DF_FILLCACHE, addr set to the address of the first visible element in the
// dump window and n to the estimated total size of the data displayed in the
// window (n may be significantly higher than real data size for disassembly).
// If plugin returns 0, there are no elements that will be modified by plugin
// and it will receive no other calls. If necessary, plugin may cache some data
// necessary later. OllyDbg guarantees that there are no calls to
// ODBG2_Plugindump() from other dump windows till the final call with
// DF_FREECACHE.
// When OllyDbg draws table, there is one call for each table cell (line/column
// pair). Parameters s (UNICODE), mask (DRAW_xxx) and select (extended DRAW_xxx
// set) contain description of the generated contents of length n. Plugin may
// modify it and return corrected length, or just return the original length.
// When table is completed, ODBG2_Plugindump() receives final call with
// column=DF_FREECACHE. This is the time to free resources allocated on
// DF_FILLCACHE. Returned value is ignored.
// Use this feature only if absolutely necessary, because it may strongly
// impair the responsiveness of the OllyDbg. Always make it switchable with
// default set to OFF!
(*
function  ODBG2_Plugindump(pd: P_dump;s: PWChar;mask: PWChar;n: LongInt;select: PInteger;addr: ULong;column: LongInt): LongInt; cdecl;
begin

  if (column= DF_FILLCACHE)then begin

    Result:= 0;
  end
  else
  if (column=TSC_MOUSE) then
  begin

  end
  else
  if (column=DF_FREECACHE)then
  begin
    // We have allocated no resources, so we have nothing to do here.
  end;
end;
*)

function  ODBG2_Pluginmenu(WdType: PWChar): P_Menu; cdecl;
begin
   Result:= nil;
   if (lstrcmpW(WdType,PWM_MAIN) = 0) then Result:= @MainMenu;
end;

function  fr332_Pluginmenu(WdType: PWChar): P_Menu; cdecl;
begin
   Result:= nil;
   if (lstrcmpW(WdType,PWM_MAIN) = 0) then Result:= @MainMenu;
end;
// OllyDbg calls this optional function when user wants to terminate OllyDbg.
// All MDI windows created by plugins still exist. Function must return 0 if
// it is safe to terminate. Any non-zero return will stop closing sequence. Do
// not misuse this possibility! Always inform user about the reasons why
// termination is not good and ask for his decision! Attention, don't make any
// unrecoverable actions for the case that some other plugin will decide that
// OllyDbg should continue running.
function ODBG2_Pluginclose:LongInt cdecl;
begin
  // For automatical restoring of open windows, mark in .ini file whether
  // Bookmarks window is still open.
  Result:= 0;
end;

function fr332_Pluginclose:LongInt cdecl;
begin
  // For automatical restoring of open windows, mark in .ini file whether
  // Bookmarks window is still open.
  Result:= 0;
end;
// OllyDbg calls this optional function once on exit. At this moment, all MDI
// windows created by plugin are already destroyed (and received WM_DESTROY
// messages). Function must free all internally allocated resources, like
// window classes, files, memory etc.

exports

  ODBG2_Pluginquery             name   '_ODBG2_Pluginquery',
  ODBG2_Plugininit              name   '_ODBG2_Plugininit',
  ODBG2_Pluginmenu              name   '_ODBG2_Pluginmenu',
  ODBG2_Pluginclose             name   '_ODBG2_Pluginclose',
  fr332_Pluginquery             name   '_4fr33_Pluginquery',
  fr332_Plugininit              name   '_4fr33_Plugininit',
  fr332_Pluginmenu              name   '_4fr33_Pluginmenu',
  fr332_Pluginclose             name   '_4fr33_Pluginclose';

procedure DLLEntryPoint(dwReason: DWORD);
var
  szPluginName:array[0..TEXTLEN] of WCHAR;
begin
  if (dwReason = DLL_PROCESS_DETACH) then
  begin
    // Uninitialize code here
    lstrcatW(szPluginName,PLUGIN_NAME);
    lstrcatW(szPluginName,' Unloaded By DLL_PROCESS_DETACH');
    OutputDebugStringW(szPluginName);
  end;
  // Call saved entry point procedure
  if Assigned(SaveDLLProc) then SaveDLLProc(dwReason);
end;

begin
  //Initialize code here
  SaveDLLProc:= @DLLProc;
  DLLProc:= @DLLEntryPoint;
end.
