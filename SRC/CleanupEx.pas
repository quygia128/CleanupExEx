unit CleanupEx;
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

interface

uses
  windows, plugin2;

  function DeletelatestData: Boolean;
  function DeleteFilesProc(DelType: LongInt): Boolean;

implementation

function DeletelatestData: Boolean;
var
  szOllyPath:array[0..MAXPATH] of WCHAR;
  szInfomation:array[0..MAXPATH] of WCHAR;
  szUDDFullPath:array[0..MAXPATH] of WCHAR;
  szFileNameW:array[0..MAXPATH] of WCHAR;
  szFName:array[0..MAXPATH] of WCHAR;
  n,i: LongInt;
Begin
  Result:= False;
  if 6 = MessageBox(hwollymain^,'Are you sure you want to delete the latest data ?','Confirm!',MB_ICONQUESTION + MB_YESNO) then begin
    //Zero initmemory
    ZeroMemory(@szOllyPath,SizeOf(szOllyPath));
    ZeroMemory(@szFileNameW,SizeOf(szFileNameW));
    ZeroMemory(@szFName,SizeOf(szFName));
    ZeroMemory(@szUDDFullPath,SizeOf(szUDDFullPath));
    ZeroMemory(@szInfomation,SizeOf(szInfomation));
    // Get UDD path and backslash
    Swprintf(szOllyPath,@ollydir^);
    n:= StrlenW(szOllyPath,TEXTLEN);
    Swprintf(szOllyPath+n,'\UDD\');
    lstrcpyW(szUDDFullPath,szOllyPath);

    // Case Delete data type
    // Delete debug data
    Stringfromini('History','Executable[0]',szFileNameW,TEXTLEN);
    if not(lstrlenW(szFileNameW) > 0) then begin
      Flash('WARNING: File Not Found!');
      Exit;
    end
    else lstrcpyW(szInfomation,szFileNameW);

    for i:= lstrlenW(szFileNameW) downto 1 do begin
      if szFileNameW[i] <> '.' then szFileNameW[i]:= #0
      else begin
        lstrcatW(szFileNameW,'UDD');
        Break;
      end;
    end;
    for n:= lstrlenW(szFileNameW) downto 1 do begin
      if szFileNameW[n] <> '\' then
      else begin
        lstrcpynW(szFName,@szFileNameW[n+1],lstrlenW(szFileNameW) - n);
        Break;
      end;
    end;
    if DeleteFileW(lstrcatW(szUDDFullPath,szFName)) then Result:= True;
    ZeroMemory(@szFileNameW,SizeOf(szFileNameW));
    ZeroMemory(@szFName,SizeOf(szFName));
    ZeroMemory(@szUDDFullPath,SizeOf(szUDDFullPath));

    // Delete Backup data
    lstrcpyW(szUDDFullPath,szOllyPath);
    Stringfromini('History','Executable[0]',szFileNameW,TEXTLEN);
    for i:= lstrlenW(szFileNameW) downto 1 do begin
      if szFileNameW[i] <> '.' then szFileNameW[i]:= #0
      else begin
        lstrcatW(szFileNameW,'BAK');
        Break;
      end;
    end;
    for n:= lstrlenW(szFileNameW) downto 1 do begin
      if szFileNameW[n] <> '\' then
      else begin
        lstrcpynW(szFName,@szFileNameW[n+1],lstrlenW(szFileNameW) - n);
        Break;
      end;
    end;
    if DeleteFileW(lstrcatW(szUDDFullPath,szFName)) then Result:= True;
    Flash('Deleted latest Data Debug: %s',szInfomation);
    ZeroMemory(@szFileNameW,SizeOf(szFileNameW));
    ZeroMemory(@szFName,SizeOf(szFName));
    ZeroMemory(@szUDDFullPath,SizeOf(szUDDFullPath));
  end;
End;
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
function DeleteFilesProc(DelType: LongInt): Boolean;
var
  wfd: WIN32_FIND_DATAW;
  hsnapshot: THandle;
  szUDDPath:array[0..MAXPATH] of WCHAR;
  szFileNameW:array[0..MAXPATH] of WCHAR;
  szExtensionNameW:array[0..MAXPATH] of WCHAR;
  szExtensionNameBuffW:array[0..SHORTNAME] of WCHAR;
  n,Ext,DelDataCt: LongInt;
Begin
  Result:= False;
  DelDataCt:= 0;
  ZeroMemory(@szUDDPath,SizeOf(szUDDPath));
  ZeroMemory(@szFileNameW,SizeOf(szFileNameW));
  ZeroMemory(@szExtensionNameW,SizeOf(szExtensionNameW));
  ZeroMemory(@szExtensionNameBuffW,SizeOf(szExtensionNameBuffW));
  FillChar(wfd,SizeOf(wfd),0);

  // Get UDD path and backslash
  Swprintf(szUDDPath,@ollydir^);
  n:= StrlenW(szUDDPath,TEXTLEN);
  Swprintf(szUDDPath+n,'\UDD\');
  
  // Case Delete data type
  case DelType of
    1:begin
      // All ollydbg data
      Swprintf(szExtensionNameW,szUDDPath);
      ext:= StrlenW(szExtensionNameW,TEXTLEN);
      Swprintf(szExtensionNameW+ext,'*.*');
    end;
    2:begin
      // All Debug data
      Swprintf(szExtensionNameW,szUDDPath);
      ext:= StrlenW(szExtensionNameW,TEXTLEN);
      Swprintf(szExtensionNameW+ext,'*.UDD');
    end;
    3:begin
      // All Backup data
      Swprintf(szExtensionNameW,szUDDPath);
      ext:= StrlenW(szExtensionNameW,TEXTLEN);
      Swprintf(szExtensionNameW+ext,'*.BAK');
    end;
	  4:begin
      // For Future (Edit extentions(XXX))
      Stringfromini('CleanupExEx','Extension',szExtensionNameBuffW,TEXTLEN);
      Swprintf(szExtensionNameW, szUDDPath);
      ext:= StrlenW(szExtensionNameW,TEXTLEN);
      if not(lstrlenW(szExtensionNameBuffW) > 0) then //$00BC4681
        Swprintf(szExtensionNameW+ext,'*.XXX')
      else Swprintf(szExtensionNameW+ext,szExtensionNameBuffW);
    end;
  end;
  if 6 = MessageBox(hwollymain^,'Are you sure you want to delete all ollydbg data ?','Confirm!',MB_ICONQUESTION + MB_YESNO) then begin
    hSnapshot:= FindFirstFileW(@szExtensionNameW,wfd);
    Try
      if (hSnapshot <> INVALID_HANDLE_VALUE) then begin
        lstrcatW(szFileNameW,szUDDPath);
        lstrcatW(szFileNameW,wfd.cFileName);
        if not(DeleteFileW(szFileNameW)) then
          Addtolist(DRAW_NORMAL,DRAW_HILITE,'Failed to delete the file: %s',wfd.cFileName)
        else Inc(DelDataCt);
        ZeroMemory(@szFileNameW,SizeOf(szFileNameW));
        while FindNextFileW(hSnapshot,wfd) do begin
          lstrcatW(szFileNameW,szUDDPath);
          lstrcatW(szFileNameW,wfd.cFileName);
          if not(DeleteFileW(szFileNameW)) then
            Addtolist(DRAW_NORMAL,DRAW_HILITE,'Failed to delete the file: %s',wfd.cFileName)
          else Inc(DelDataCt);
          ZeroMemory(@szFileNameW,SizeOf(szFileNameW));
        end;
        Flash('CleanupExEx Deleted: %i Files!',DelDataCt);
      end
      else begin
        Flash('WARNING[Folder Empty]: File Not Found!');
      end;
      Result:= True;
    except
      Result:= False;
    end;
  end;
End;

end.