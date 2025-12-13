# Microsoft Developer Studio Generated NMAKE File, Format Version 4.10
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Application" 0x0101

!IF "$(CFG)" == ""
CFG=midiox32 - Win32 Debug
!MESSAGE No configuration specified.  Defaulting to midiox32 - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "midiox32 - Win32 Release" && "$(CFG)" !=\
 "midiox32 - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE 
!MESSAGE NMAKE /f "midiox32.mak" CFG="midiox32 - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "midiox32 - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "midiox32 - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 
################################################################################
# Begin Project
# PROP Target_Last_Scanned "midiox32 - Win32 Debug"
RSC=rc.exe
MTL=mktyplib.exe
CPP=cl.exe

!IF  "$(CFG)" == "midiox32 - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
OUTDIR=.\Release
INTDIR=.\Release

ALL : "$(OUTDIR)\midiox32.exe"

CLEAN : 
	-@erase "$(INTDIR)\About.obj"
	-@erase "$(INTDIR)\Circbuf.obj"
	-@erase "$(INTDIR)\Ctlpnl.obj"
	-@erase "$(INTDIR)\debug.obj"
	-@erase "$(INTDIR)\Display.obj"
	-@erase "$(INTDIR)\file.obj"
	-@erase "$(INTDIR)\Filtdlg.obj"
	-@erase "$(INTDIR)\Filter.obj"
	-@erase "$(INTDIR)\Instdata.obj"
	-@erase "$(INTDIR)\LogFile.obj"
	-@erase "$(INTDIR)\Midimcbk.obj"
	-@erase "$(INTDIR)\Midiox16.obj"
	-@erase "$(INTDIR)\Midiox32.res"
	-@erase "$(INTDIR)\Msapi.obj"
	-@erase "$(INTDIR)\Mscroll.obj"
	-@erase "$(INTDIR)\Msinit.obj"
	-@erase "$(INTDIR)\Mstatus.obj"
	-@erase "$(INTDIR)\Paint.obj"
	-@erase "$(INTDIR)\Piano.obj"
	-@erase "$(INTDIR)\Prefer.obj"
	-@erase "$(INTDIR)\Spinedit.obj"
	-@erase "$(INTDIR)\Syxbuf.obj"
	-@erase "$(OUTDIR)\midiox32.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /Gz /Zp1 /W3 /WX /GX /O2 /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "STRICT" /YX /c /Tp
# SUBTRACT CPP /nologo
CPP_PROJ=/Gz /Zp1 /ML /W3 /WX /GX /O2 /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D\
 "STRICT" /Fp"$(INTDIR)/midiox32.pch" /YX /Fo"$(INTDIR)/" /c /Tp 
CPP_OBJS=.\Release/
CPP_SBRS=.\.
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /win32
MTL_PROJ=/nologo /D "NDEBUG" /win32 
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
RSC_PROJ=/l 0x409 /fo"$(INTDIR)/Midiox32.res" /d "NDEBUG" 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/midiox32.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib winmm.lib /nologo /subsystem:windows /machine:I386
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib winmm.lib /nologo /subsystem:windows\
 /incremental:no /pdb:"$(OUTDIR)/midiox32.pdb" /machine:I386\
 /out:"$(OUTDIR)/midiox32.exe" 
LINK32_OBJS= \
	"$(INTDIR)\About.obj" \
	"$(INTDIR)\Circbuf.obj" \
	"$(INTDIR)\Ctlpnl.obj" \
	"$(INTDIR)\debug.obj" \
	"$(INTDIR)\Display.obj" \
	"$(INTDIR)\file.obj" \
	"$(INTDIR)\Filtdlg.obj" \
	"$(INTDIR)\Filter.obj" \
	"$(INTDIR)\Instdata.obj" \
	"$(INTDIR)\LogFile.obj" \
	"$(INTDIR)\Midimcbk.obj" \
	"$(INTDIR)\Midiox16.obj" \
	"$(INTDIR)\Midiox32.res" \
	"$(INTDIR)\Msapi.obj" \
	"$(INTDIR)\Mscroll.obj" \
	"$(INTDIR)\Msinit.obj" \
	"$(INTDIR)\Mstatus.obj" \
	"$(INTDIR)\Paint.obj" \
	"$(INTDIR)\Piano.obj" \
	"$(INTDIR)\Prefer.obj" \
	"$(INTDIR)\Spinedit.obj" \
	"$(INTDIR)\Syxbuf.obj"

"$(OUTDIR)\midiox32.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "midiox32"
# PROP BASE Intermediate_Dir "midiox32"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
OUTDIR=.\Debug
INTDIR=.\Debug

ALL : "$(OUTDIR)\midiox32.exe"

CLEAN : 
	-@erase "$(INTDIR)\About.obj"
	-@erase "$(INTDIR)\Circbuf.obj"
	-@erase "$(INTDIR)\Ctlpnl.obj"
	-@erase "$(INTDIR)\debug.obj"
	-@erase "$(INTDIR)\Display.obj"
	-@erase "$(INTDIR)\file.obj"
	-@erase "$(INTDIR)\Filtdlg.obj"
	-@erase "$(INTDIR)\Filter.obj"
	-@erase "$(INTDIR)\Instdata.obj"
	-@erase "$(INTDIR)\LogFile.obj"
	-@erase "$(INTDIR)\Midimcbk.obj"
	-@erase "$(INTDIR)\Midiox16.obj"
	-@erase "$(INTDIR)\Midiox32.res"
	-@erase "$(INTDIR)\Msapi.obj"
	-@erase "$(INTDIR)\Mscroll.obj"
	-@erase "$(INTDIR)\Msinit.obj"
	-@erase "$(INTDIR)\Mstatus.obj"
	-@erase "$(INTDIR)\Paint.obj"
	-@erase "$(INTDIR)\Piano.obj"
	-@erase "$(INTDIR)\Prefer.obj"
	-@erase "$(INTDIR)\Spinedit.obj"
	-@erase "$(INTDIR)\Syxbuf.obj"
	-@erase "$(INTDIR)\vc40.idb"
	-@erase "$(INTDIR)\vc40.pdb"
	-@erase "$(OUTDIR)\midiox32.exe"
	-@erase "$(OUTDIR)\midiox32.ilk"
	-@erase "$(OUTDIR)\midiox32.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /Gz /Zp1 /W3 /WX /Gm /GX /Zi /Od /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "STRICT" /YX /c /Tp
# SUBTRACT CPP /nologo
CPP_PROJ=/Gz /Zp1 /MLd /W3 /WX /Gm /GX /Zi /Od /D "_DEBUG" /D "WIN32" /D\
 "_WINDOWS" /D "STRICT" /Fp"$(INTDIR)/midiox32.pch" /YX /Fo"$(INTDIR)/"\
 /Fd"$(INTDIR)/" /c /Tp 
CPP_OBJS=.\Debug/
CPP_SBRS=.\.
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /win32
MTL_PROJ=/nologo /D "_DEBUG" /win32 
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
RSC_PROJ=/l 0x409 /fo"$(INTDIR)/Midiox32.res" /d "_DEBUG" 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/midiox32.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /debug /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib winmm.lib /nologo /subsystem:windows /debug /machine:I386
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib winmm.lib /nologo /subsystem:windows\
 /incremental:yes /pdb:"$(OUTDIR)/midiox32.pdb" /debug /machine:I386\
 /out:"$(OUTDIR)/midiox32.exe" 
LINK32_OBJS= \
	"$(INTDIR)\About.obj" \
	"$(INTDIR)\Circbuf.obj" \
	"$(INTDIR)\Ctlpnl.obj" \
	"$(INTDIR)\debug.obj" \
	"$(INTDIR)\Display.obj" \
	"$(INTDIR)\file.obj" \
	"$(INTDIR)\Filtdlg.obj" \
	"$(INTDIR)\Filter.obj" \
	"$(INTDIR)\Instdata.obj" \
	"$(INTDIR)\LogFile.obj" \
	"$(INTDIR)\Midimcbk.obj" \
	"$(INTDIR)\Midiox16.obj" \
	"$(INTDIR)\Midiox32.res" \
	"$(INTDIR)\Msapi.obj" \
	"$(INTDIR)\Mscroll.obj" \
	"$(INTDIR)\Msinit.obj" \
	"$(INTDIR)\Mstatus.obj" \
	"$(INTDIR)\Paint.obj" \
	"$(INTDIR)\Piano.obj" \
	"$(INTDIR)\Prefer.obj" \
	"$(INTDIR)\Spinedit.obj" \
	"$(INTDIR)\Syxbuf.obj"

"$(OUTDIR)\midiox32.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 

.c{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.c{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

################################################################################
# Begin Target

# Name "midiox32 - Win32 Release"
# Name "midiox32 - Win32 Debug"

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

################################################################################
# Begin Source File

SOURCE=.\Syxbuf.h

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\Circbuf.c
DEP_CPP_CIRCB=\
	".\Circbuf.h"\
	".\debug.h"\
	".\Midimon.h"\
	

"$(INTDIR)\Circbuf.obj" : $(SOURCE) $(DEP_CPP_CIRCB) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Circbuf.h

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\Ctlpnl.c
DEP_CPP_CTLPN=\
	".\Circbuf.h"\
	".\debug.h"\
	".\Filter.h"\
	".\Instdata.h"\
	".\Midimcbk.h"\
	".\Midimon.h"\
	".\Mscroll.h"\
	".\Spinedit.h"\
	".\Syxbuf.h"\
	

"$(INTDIR)\Ctlpnl.obj" : $(SOURCE) $(DEP_CPP_CTLPN) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\debug.c

"$(INTDIR)\debug.obj" : $(SOURCE) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\debug.h

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\Display.c
DEP_CPP_DISPL=\
	".\Circbuf.h"\
	".\debug.h"\
	".\Display.h"\
	".\Midimon.h"\
	

"$(INTDIR)\Display.obj" : $(SOURCE) $(DEP_CPP_DISPL) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Display.h

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\file.c
DEP_CPP_FILE_=\
	".\Circbuf.h"\
	".\debug.h"\
	".\file.h"\
	".\Filter.h"\
	".\Instdata.h"\
	".\Midimcbk.h"\
	".\Midimon.h"\
	".\Prefer.h"\
	".\Syxbuf.h"\
	

"$(INTDIR)\file.obj" : $(SOURCE) $(DEP_CPP_FILE_) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\file.h

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\Filtdlg.c
DEP_CPP_FILTD=\
	".\debug.h"\
	".\Filter.h"\
	".\Midimon.h"\
	".\Prefer.h"\
	

"$(INTDIR)\Filtdlg.obj" : $(SOURCE) $(DEP_CPP_FILTD) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Filter.c
DEP_CPP_FILTE=\
	".\debug.h"\
	".\Display.h"\
	".\Filter.h"\
	".\Midimon.h"\
	

"$(INTDIR)\Filter.obj" : $(SOURCE) $(DEP_CPP_FILTE) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Filter.h

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\Instdata.c
DEP_CPP_INSTD=\
	".\Circbuf.h"\
	".\debug.h"\
	".\Filter.h"\
	".\Instdata.h"\
	".\Midimon.h"\
	".\Syxbuf.h"\
	

"$(INTDIR)\Instdata.obj" : $(SOURCE) $(DEP_CPP_INSTD) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Instdata.h

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LogFile.c
DEP_CPP_LOGFI=\
	".\debug.h"\
	".\logfile.h"\
	".\Midimon.h"\
	

"$(INTDIR)\LogFile.obj" : $(SOURCE) $(DEP_CPP_LOGFI) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\logfile.h

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\Midimcbk.c
DEP_CPP_MIDIM=\
	".\Circbuf.h"\
	".\debug.h"\
	".\Filter.h"\
	".\Instdata.h"\
	".\Midimcbk.h"\
	".\Midimon.h"\
	".\Mscrdll.h"\
	".\Mscroll.h"\
	".\Prefer.h"\
	".\Syxbuf.h"\
	

"$(INTDIR)\Midimcbk.obj" : $(SOURCE) $(DEP_CPP_MIDIM) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Midimcbk.h

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\Midimon.h

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\Midiox16.c
DEP_CPP_MIDIO=\
	".\Circbuf.h"\
	".\debug.h"\
	".\Display.h"\
	".\file.h"\
	".\Filter.h"\
	".\Instdata.h"\
	".\logfile.h"\
	".\Midimcbk.h"\
	".\Midimon.h"\
	".\Mstatus.h"\
	".\Piano.h"\
	".\Prefer.h"\
	".\Syxbuf.h"\
	

"$(INTDIR)\Midiox16.obj" : $(SOURCE) $(DEP_CPP_MIDIO) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Mmres.h

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\Msapi.c
DEP_CPP_MSAPI=\
	".\Mscrdll.h"\
	".\Mscroll.h"\
	

"$(INTDIR)\Msapi.obj" : $(SOURCE) $(DEP_CPP_MSAPI) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Mscrdll.h

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\Mscroll.c
DEP_CPP_MSCRO=\
	".\Mscrdll.h"\
	".\Mscroll.h"\
	

"$(INTDIR)\Mscroll.obj" : $(SOURCE) $(DEP_CPP_MSCRO) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Mscroll.h

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\Msinit.c
DEP_CPP_MSINI=\
	".\Mscrdll.h"\
	".\Mscroll.h"\
	

"$(INTDIR)\Msinit.obj" : $(SOURCE) $(DEP_CPP_MSINI) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Mstatus.c
DEP_CPP_MSTAT=\
	".\Circbuf.h"\
	".\debug.h"\
	".\Filter.h"\
	".\Instdata.h"\
	".\Midimon.h"\
	".\Mstatus.h"\
	".\Syxbuf.h"\
	

"$(INTDIR)\Mstatus.obj" : $(SOURCE) $(DEP_CPP_MSTAT) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Mstatus.h

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\Paint.c
DEP_CPP_PAINT=\
	".\Mscrdll.h"\
	".\Mscroll.h"\
	

"$(INTDIR)\Paint.obj" : $(SOURCE) $(DEP_CPP_PAINT) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Piano.c
DEP_CPP_PIANO=\
	".\Circbuf.h"\
	".\debug.h"\
	".\Filter.h"\
	".\Instdata.h"\
	".\Midimcbk.h"\
	".\Midimon.h"\
	".\Piano.h"\
	".\Syxbuf.h"\
	

"$(INTDIR)\Piano.obj" : $(SOURCE) $(DEP_CPP_PIANO) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Piano.h

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\Prefer.c
DEP_CPP_PREFE=\
	".\debug.h"\
	".\Filter.h"\
	".\Midimon.h"\
	".\Prefer.h"\
	".\Syxbuf.h"\
	

"$(INTDIR)\Prefer.obj" : $(SOURCE) $(DEP_CPP_PREFE) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Prefer.h

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\Resb.h

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\Resbak.h

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\Rescbk.h

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\Rescmn.h

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\resource.h

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\Spinedit.c
DEP_CPP_SPINE=\
	".\debug.h"\
	".\Midimon.h"\
	".\Mscroll.h"\
	".\Spinedit.h"\
	

"$(INTDIR)\Spinedit.obj" : $(SOURCE) $(DEP_CPP_SPINE) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Spinedit.h

!IF  "$(CFG)" == "midiox32 - Win32 Release"

!ELSEIF  "$(CFG)" == "midiox32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\Syxbuf.c
DEP_CPP_SYXBU=\
	".\debug.h"\
	".\Midimon.h"\
	".\Syxbuf.h"\
	

"$(INTDIR)\Syxbuf.obj" : $(SOURCE) $(DEP_CPP_SYXBU) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\About.c
DEP_CPP_ABOUT=\
	".\debug.h"\
	".\Midimon.h"\
	

"$(INTDIR)\About.obj" : $(SOURCE) $(DEP_CPP_ABOUT) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Midiox32.rc
DEP_RSC_MIDIOX=\
	".\Midimon.h"\
	".\Midiox16.rc"\
	".\MM1.ICO"\
	".\MM2.ICO"\
	".\MM3.ICO"\
	".\MM4.ICO"\
	".\Mscrdll.h"\
	".\Mscroll.h"\
	".\OFF.ICO"\
	".\ON.ICO"\
	

"$(INTDIR)\Midiox32.res" : $(SOURCE) $(DEP_RSC_MIDIOX) "$(INTDIR)"
   $(RSC) $(RSC_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Midiox16.rc
# PROP Exclude_From_Build 1
# End Source File
# End Target
# End Project
################################################################################
