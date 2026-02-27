////////////////////////////////////////////////////////
// prefer.c - Routines to get and set user preferences.
//

#include <windows.h>
#include <mmsystem.h>
#include <stdlib.h>
#include <string.h>
#include "midimon.h"
#include "filter.h"
#include "prefer.h"
#include "syxbuf.h"

static char DevNum[8];
static char szINIPath[_MAX_PATH];
         
const char szDisplaySect[]	= "Display Window";
const char szOptionSect[]	= "Options";
const char szMIDIIn[]      = "MidiInputDevice";
const char szMIDIOut[]     = "MidiOutputDevice";
const char szLogSect[]		= "LogFile";
const char szXKey[]        = "x";
const char szYKey[]        = "y";
const char szWKey[]        = "w";
const char szHKey[]        = "h";
const char szThruKey[]     = "ThruOn";
const char szOnTopKey[]    = "OnTop";
const char szSXKey[]       = "PassSysEx";
const char szOctKey[]		= "Octave";   
const char szNBufKey[]     = "BufferCount";
const char szBufSizeKey[]  = "BufferSize";
const char szFixFontKey[]  = "FixedFont";
const char szOutNm[]       = "Out1";
const char szLogEnable[]	= "Enabled";
const char szLogAppend[]	= "Append";
const char szLogPath[]		= "LogPath";
const char szBkGd[]        = "BackGround";
const char szText[]        = "TextColor";
const char szLblBkGd[]     = "LblBkGd";
const char szLblText[]     = "LblText";
const char szClrNtOff[]    = "ClrNoteOff";
const char szClrNtOn[]     = "ClrNoteOn";
const char szClrAfterT[]   = "ClrAfterTouch";
const char szClrControl[]  = "ClrControlChg";
const char szClrProgram[]  = "ClrProgramChg";
const char szClrPitchB[]   = "ClrPitchBend";
const char szClrSystem[]   = "ClrSystemMsg";
const char szDftBkGd[]     = "0,0,0";			// Black
const char szDftText[]     = "192,192,192";  // lt grey
const char szDftNtOff[]    = "0,128,0";      // teal green
const char szDftNtOn[]     = "0,255,0";      // bright green
const char szDftAfterT[]   = "128,0,128";    // violet
const char szDftControl[]  = "0,0,255";		// lt blu
const char szDftProgram[]  = "255,0,255";		// blue
const char szDftPitchB[]   = "255,0,0";		// red
const char szDftSystem[]   = "255,255,0";		// yellow
const char szDftLog[]		= "MIDILog.txt";
const char szSyxFileDir[]  = "SysexFileDir";
#if 0
const char szMidiFileDir[] = "MidiFileDir";
#endif
const char szSysexDelay[]  = "SysexDelay";

char szMMMsg[255]; 

////////////////////////////////////////////////////////////////////
// Shortcut function
int GetProfInt(LPCSTR szSect, LPCSTR szKey, int nDefault) 
{
	return (int)GetPrivateProfileInt(szSect, szKey, nDefault, szINIPath);
	}

////////////////////////////////////////////////////////////////////
// Shortcut function
BOOL SetProfInt(LPCSTR szSect, LPCSTR szKey, int nValue) 
{
	char Buf[16];

	wsprintf(Buf, "%d", (short)nValue);
	return WritePrivateProfileString(szSect, szKey, Buf, szINIPath);
	}

////////////////////////////////////////////////////////////////////
// Shortcut function

BOOL SetProfColor(LPCSTR szKey, COLORREF rgb) 
{
	char szBuf[24];

   wsprintf(szBuf, "%d,%d,%d", 
			(int)GetRValue(rgb), 
			(int)GetGValue(rgb), 
			(int)GetBValue(rgb));
	return WritePrivateProfileString(szDisplaySect, szKey, szBuf, szINIPath);
	}

////////////////////////////////////////////////////////////////////

COLORREF GetProfColor(LPCSTR szKey, LPCSTR szDft)
{
	char szBuf[24];
	short r, g, b;

   GetPrivateProfileString(
				szDisplaySect, 
				szKey, 
				szDft,
            szBuf, 
				24, 
				szINIPath
				);
   r = atoi(strtok(szBuf, ","));
   g = atoi(strtok(NULL, ","));
   b = atoi(strtok(NULL, "; "));
   return RGB(r, g, b);
	}

////////////////////////////////////////////////////////////////////
// getPreferences - Reads .INI file and gets the setup preferences.
//      Currently, the only user preferences are window location and size.
//      If the .INI file does not exist, returns default values.
//
// Params:  lpPreferences - Points to a PREFERENCES data structure that
//              is filled with the retrieved user preferences.
//
// Return:  void
//

void getPreferences(HINSTANCE hInst, LPPREFERENCES lpPreferences) {
	short i;
	char  szBuf[24];
	char  szColBuf[24];
	LPSTR lp;
	COLORREF colRef;

   LoadString(hInst, IDS_ININAME, szBuf, sizeof(szBuf)); 

	// Look for ini file in the current directory
	GetModuleFileName(hInst, szINIPath, sizeof(szINIPath));
	if ((lp = strrchr(szINIPath, '\\')))
		STRCPY(lp+1, szBuf);
	else // just use windows dir
		STRCPY(szINIPath, szBuf);

   lpPreferences->iInitialX = 
        GetPrivateProfileInt(szDisplaySect, szXKey, DEF_X, szINIPath);

   lpPreferences->iInitialY = 
        GetPrivateProfileInt(szDisplaySect, szYKey, DEF_Y, szINIPath);

   lpPreferences->iInitialW = 
        GetPrivateProfileInt(szDisplaySect, szWKey, DEF_W, szINIPath);

   lpPreferences->iInitialH = 
        GetPrivateProfileInt(szDisplaySect, szHKey, DEF_H, szINIPath);

   lpPreferences->bThruOn =
        GetPrivateProfileInt(szOptionSect, szThruKey, DEF_ON, szINIPath);

   lpPreferences->bOnTop =
        GetPrivateProfileInt(szOptionSect, szOnTopKey, DEF_ON, szINIPath);
    
   lpPreferences->bPasSX =
        GetPrivateProfileInt(szOptionSect, szSXKey, DEF_ON, szINIPath);
                         
   lpPreferences->nOctave =
        GetPrivateProfileInt(szOptionSect, szOctKey, DEF_OCTV, szINIPath);
    
   // number of sysex buffers per opening
   lpPreferences->nSxBuf =
        GetPrivateProfileInt(szOptionSect, szNBufKey, NUMSXBUF, szINIPath);
    
    // byte size of each buffer
   lpPreferences->bufSize =
        GetPrivateProfileInt(szOptionSect, szBufSizeKey, SYXBUFSIZE, szINIPath);

   // The background color    
   lpPreferences->colBkGd = GetProfColor(szBkGd, szDftBkGd);
   lpPreferences->colText = GetProfColor(szText, szDftText);

   // Label Colors
   colRef = GetSysColor(COLOR_ACTIVECAPTION);
   wsprintf(
			szColBuf, 
			"%d,%d,%d", 
			(short)GetRValue(colRef),
			(short)GetGValue(colRef), 
			(short)GetBValue(colRef)
			);
   lpPreferences->colLblBkGd = GetProfColor(szLblBkGd, szColBuf);

   colRef = GetSysColor(COLOR_CAPTIONTEXT);
   wsprintf(
			szColBuf, 
			"%d,%d,%d", 
			(short)GetRValue(colRef),
			(short)GetGValue(colRef), 
			(short)GetBValue(colRef)
			);
   lpPreferences->colLblText = GetProfColor(szLblText, szColBuf);
   
   // COLOR_APPWORKSPACE and the Labels text uses COLOR_WINDOWTEXT.
   // The font to use
    
   lpPreferences->iFixFont = GetPrivateProfileInt(
												szDisplaySect, 
												szFixFontKey, 
												OEM_FIXED_FONT, 
												szINIPath
												);

   // Deal with event type colors
   // Note Off
   lpPreferences->clrNoteOff = GetProfColor(szClrNtOff, szDftNtOff);
               
	// Note On               
   lpPreferences->clrNoteOn = GetProfColor(szClrNtOn, szDftNtOn);
    
   // After Touch
   lpPreferences->clrAfterT = GetProfColor(szClrAfterT, szDftAfterT);
    
   // Control Msg
   lpPreferences->clrControl = GetProfColor(szClrControl, szDftControl);
    
   // Program Change
   lpPreferences->clrProgram = GetProfColor(szClrProgram, szDftProgram);
    
   // Pitch Bend
   lpPreferences->clrPitchB = GetProfColor(szClrPitchB, szDftPitchB);
    
   // Program Change
   lpPreferences->clrSystem = GetProfColor(szClrSystem, szDftSystem);

   /* Find Input devices in INI */

   for (i=0; i < lpPreferences->nInDev; i++) {
      wsprintf(DevNum, "In%d", i+1);
      GetPrivateProfileString(
				szMIDIIn, 
				DevNum, 
				"",
            lpPreferences->lpIDN->Nm[i],
            40,
            szINIPath
				);
      if (lpPreferences->lpIDN->Nm[i][0] == '\0')            // end of list
         break;
      }

   lpPreferences->nInDev = i;  // actual number to open
							          /* Find Output device in INI */

   GetPrivateProfileString(
			szMIDIOut, 
			szOutNm, 
			"",
         lpPreferences->lpszOutDev,
         40,
         szINIPath
			);
	InitFilter(lpPreferences->lpFilter);

	// Get the Log file parms
   GetPrivateProfileString(
			szLogSect, 
			szLogPath, 
			szDftLog,
         lpPreferences->lpszLogFile,
         _MAX_PATH,
         szINIPath
			);
   lpPreferences->bLogEnabled =
        GetPrivateProfileInt(szLogSect, szLogEnable, FALSE, szINIPath);
   lpPreferences->bLogAppend =
        GetPrivateProfileInt(szLogSect, szLogAppend, TRUE, szINIPath);
	}

////////////////////////////////////////////////////////////////////////
// setPreferences - Writes the .INI file with the given setup preferences.
//
// Params:  lpPreferences - Points to a PREFERENCES data structure containing
//              the user preferences.
//
// Return:  void
//

void setPreferences(LPPREFERENCES lpPreferences) {
	char szTempString[24];
	int  i;

	// set up error message, for maybe later
   wsprintf(szMMMsg, "Error writing %s", (LPSTR)szINIPath);    

   wsprintf(szTempString, "%d", lpPreferences->iInitialX);
   if (WritePrivateProfileString(
					szDisplaySect, 
					szXKey,
               (LPSTR)szTempString, 
					szINIPath
					) == 0)
      Error((LPSTR)szMMMsg);
        
   wsprintf(szTempString, "%d", lpPreferences->iInitialY);
   if	(WritePrivateProfileString(
					szDisplaySect, 
					szYKey,
               (LPSTR)szTempString, 
					szINIPath
					) == 0)
      Error((LPSTR)szMMMsg);
        
   wsprintf(szTempString, "%d", lpPreferences->iInitialW);
   if	(WritePrivateProfileString(
					szDisplaySect, 
					szWKey,
               (LPSTR)szTempString, 
					szINIPath
					) == 0)
      Error((LPSTR)szMMMsg);
        
   wsprintf(szTempString, "%d", lpPreferences->iInitialH);
   if (WritePrivateProfileString(
					szDisplaySect, 
					szHKey,
               (LPSTR)szTempString, 
					szINIPath
					) == 0)
      Error((LPSTR)szMMMsg);

   // Window Colors...
   // The background color
	if (!SetProfColor(szBkGd, lpPreferences->colBkGd))
      Error((LPSTR)szMMMsg);

	if (!SetProfColor(szText, lpPreferences->colText))
      Error((LPSTR)szMMMsg);

   // Label Colors
	if (!SetProfColor(szLblBkGd, lpPreferences->colLblBkGd))
      Error((LPSTR)szMMMsg);

   // Label Text
	if (!SetProfColor(szLblText, lpPreferences->colLblText))
      Error((LPSTR)szMMMsg);
   
   // COLOR_APPWORKSPACE and the Labels text uses COLOR_WINDOWTEXT.
   // The font to use !!!

	if (!SetProfInt(szDisplaySect, szFixFontKey, lpPreferences->iFixFont))
      Error((LPSTR)szMMMsg);

   // Deal with event type colors
   // Note Off
	if (!SetProfColor(szClrNtOff, lpPreferences->clrNoteOff))
      Error((LPSTR)szMMMsg);
               
	// Note On               
	if (!SetProfColor(szClrNtOn, lpPreferences->clrNoteOn))
      Error((LPSTR)szMMMsg);

   // After Touch
	if (!SetProfColor(szClrAfterT, lpPreferences->clrAfterT))
      Error((LPSTR)szMMMsg);

   // Control Msg
	if (!SetProfColor(szClrControl, lpPreferences->clrControl))
      Error((LPSTR)szMMMsg);

   // Program Change
	if (!SetProfColor(szClrProgram, lpPreferences->clrProgram))
      Error((LPSTR)szMMMsg);
    
   // Pitch Bend
	if (!SetProfColor(szClrPitchB, lpPreferences->clrPitchB))
      Error((LPSTR)szMMMsg);
    
   // System message
	if (!SetProfColor(szClrSystem, lpPreferences->clrSystem))
      Error((LPSTR)szMMMsg);

	wsprintf(szTempString, "%d", lpPreferences->bThruOn);
   if (WritePrivateProfileString(
					szOptionSect, 
					szThruKey,
               (LPSTR)szTempString, 
					szINIPath
					) == 0)
      Error((LPSTR)szMMMsg);
 
	wsprintf(szTempString, "%d", lpPreferences->bPasSX);
   if (WritePrivateProfileString(
					szOptionSect, 
					szSXKey,
               (LPSTR)szTempString, 
					szINIPath
					) == 0)
      Error((LPSTR)szMMMsg);
   
	wsprintf(szTempString, "%d", lpPreferences->bOnTop);
   if (WritePrivateProfileString(
					szOptionSect, 
					szOnTopKey,
               (LPSTR)szTempString, 
					szINIPath
					) == 0)
      Error((LPSTR)szMMMsg);
   
	wsprintf(szTempString, "%d", lpPreferences->nSxBuf);
   if (WritePrivateProfileString(
					szOptionSect, 
					szNBufKey,
               (LPSTR)szTempString, 
					szINIPath
					) == 0)
      Error((LPSTR)szMMMsg);
   
	wsprintf(szTempString, "%d", lpPreferences->bufSize);
   if (WritePrivateProfileString(
					szOptionSect, 
					szBufSizeKey,
               (LPSTR)szTempString, 
					szINIPath
					) == 0)
      Error((LPSTR)szMMMsg);

   wsprintf(szTempString, "%d", lpPreferences->nOctave);
   if (WritePrivateProfileString(
					szOptionSect, 
					szOctKey,
               (LPSTR)szTempString, 
					szINIPath
					) == 0)
      Error((LPSTR)szMMMsg);

	// The filter
   SaveFilter(lpPreferences->lpFilter);

	// The MIDI Devices
   WritePrivateProfileString(szMIDIIn, NULL, NULL, szINIPath);
   for (i = 0; i < lpPreferences->nInDev; ++i) {
       wsprintf(DevNum, "In%d", i+1);
       if (WritePrivateProfileString(
						szMIDIIn, 
						DevNum,
						lpPreferences->lpIDN->Nm[i], 
						szINIPath
						) == 0)
          Error((LPSTR)szMMMsg);

       }

   WritePrivateProfileString(szMIDIOut, NULL, NULL, szINIPath);
   if (*lpPreferences->lpszOutDev != '\0') {
      if (WritePrivateProfileString(
						szMIDIOut, 
						"Out1",
						lpPreferences->lpszOutDev, 
						szINIPath
						) == 0)
         Error((LPSTR)szMMMsg);
         }

	// save the log options
   if (WritePrivateProfileString(
					szLogSect, 
					szLogPath, 
					lpPreferences->lpszLogFile, 
					szINIPath
					) == 0)
      Error((LPSTR)szMMMsg);

	if (!SetProfInt(szLogSect, szLogEnable, lpPreferences->bLogEnabled))
      Error((LPSTR)szMMMsg);

	if (!SetProfInt(szLogSect, szLogAppend, lpPreferences->bLogAppend))
      Error((LPSTR)szMMMsg);
   }
                                     
/*--------------------------------------------------------------------------
    GetSysexFileDirPreference() reads the .ini file and gets the
    default directory for sysex files.
---------------------------------------------------------------------------*/

void GetSysexFileDirPreference(LPSTR lpszFileDir)
{
    GetPrivateProfileString(szOptionSect, szSyxFileDir, "",
                            lpszFileDir, _MAX_PATH,
                            szINIPath);
}

#if 0
/*--------------------------------------------------------------------------
    GetMidiFileDirPreference() reads the .ini file and gets the
    default directory for MIDI files.
---------------------------------------------------------------------------*/

void GetMidiFileDirPreference(LPSTR lpszFileDir)
{
    GetPrivateProfileString(szOptionSect, szMidiFileDir, "",
                            lpszFileDir, _MAX_PATH,
                            szINIPath);
}
#endif

/*-------------------------------------------------------------------
    GetSysexDelayPreference returns the choice from the .ini file
-------------------------------------------------------------------*/

UINT GetSysexDelayPreference(void)
{
    UINT nSysexTimerDelay;
    
    return (nSysexTimerDelay =
        GetPrivateProfileInt(szOptionSect, szSysexDelay,
                             SYSEXTIMERDELAY, szINIPath));
}

                                   