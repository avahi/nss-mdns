#include <windows.h>
#include <mmsystem.h>
#include <commdlg.h>
#include <stdlib.h>
#include <memory.h>
#include "midimon.h"
#include "circbuf.h"
#include "syxbuf.h"
#include "filter.h"
#include "instdata.h" 
#include "midimcbk.h"
#include "file.h"
#include "prefer.h"

#ifndef _WIN32
#define FILE_CURRENT 1
#define FILE_END     2
#define FILE_BEGIN   0
#endif

extern WORD bufSize;                             //global holding sysex buffer size                                             
extern MIDIINCAPS  midiInCaps[MAX_NUM_DEVICES];  // Device capabilities structures

char *szFileFilter[] = { "SysEx Files\0*.syx;*.cbk\0All Files\0*.*\0",
                         "MIDI Files\0*.mid\0",
                         "WAVE Files\0*.wav\0" };
char *szTitleString[] = {"Send Sysex File",
                         "Play MIDI File",
                         "Play Wave File" };
enum FileTypes
{
    SYSEX_FILE,
    MIDI_FILE,
    WAVE_FILE,
};

extern LPCALLBACKINSTANCEDATA FAR PASCAL DefInstData(void);
extern void  MIDIErr(MMRESULT code, LPSTR szName, BOOL in);
HANDLE GetFileHandle(UINT uFileType);
DWORD GetBytesToRead(HANDLE hFile);
BOOL ReadSysexFile(HANDLE hFile, UINT uBytesToRead);
void EndFileProcess(LPHANDLE lpFile);

/*-------------------------------------------------------------------
    SendSysexFile
       Entry point from "File => Send Sysex" menu and
       re-entry from timer (if necessary)
-------------------------------------------------------------------*/
BOOL SendSysexFile(BOOL bSend)
{
   UINT uBytesToRead = 0;
   static HANDLE hFile = NULL;

   if(!bSend) {
         EndFileProcess(&hFile);
         return FALSE;
         }

   if(!hFile) {
      if(!(hFile = GetFileHandle(SYSEX_FILE))) {
         EndFileProcess(&hFile);
         return FALSE;
         }
   }

   uBytesToRead = (UINT)GetBytesToRead(hFile);
   if(!uBytesToRead) {
      EndFileProcess(&hFile);
      return FALSE;
      }

   if (uBytesToRead >= bufSize)  //bufSize is global sysex buffer size
      uBytesToRead = bufSize;

   if(!ReadSysexFile(hFile, uBytesToRead)) {
      EndFileProcess(&hFile);
      return FALSE;
      }

   if(GetBytesToRead(hFile) == 0) {
      EndFileProcess(&hFile);
      return FALSE;
      }
   return TRUE;
}

/*-------------------------------------------------------------------
    GetFileHandle
-------------------------------------------------------------------*/
HANDLE GetFileHandle(UINT uFileType)
{
#ifndef _WIN32
   OFSTRUCT ofs;
#endif
   OPENFILENAME ofn;
   char szFileName[_MAX_PATH];
   char szInitialDir[_MAX_PATH];
   DWORD dwFlags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
   HANDLE hFile;

   #ifdef _WIN32
   DWORD dwPlatformId;
   //DWORD dwMajorVersion;  //other version info may be useful in future
   //DWORD dwMinorVersion;
   //DWORD dwBuildNumber;
   OSVERSIONINFO stVersInfo;
   LPOSVERSIONINFO lpVersBuf = &stVersInfo;
   ZeroMemory(lpVersBuf, sizeof(OSVERSIONINFO));
   lpVersBuf->dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
   GetVersionEx(lpVersBuf);
   dwPlatformId   = lpVersBuf->dwPlatformId;
   //dwMajorVersion = lpVersBuf->dwMajorVersion;
   //dwMinorVersion = lpVersBuf->dwMinorVersion;
   //dwBuildNumber  = lpVersBuf->dwBuildNumber & 0xFFFF;

   switch(dwPlatformId) {
      case VER_PLATFORM_WIN32_WINDOWS: 
         dwFlags |= OFN_EXPLORER;
         break;
   
      case VER_PLATFORM_WIN32_NT: 
         dwFlags |= OFN_LONGNAMES; 
         break;

      default:
         break;
   }
#endif   

    // Get the name stored in the .ini file
   switch (uFileType)
   {
      case SYSEX_FILE:
         GetSysexFileDirPreference((LPSTR)szInitialDir);
         break;

      case MIDI_FILE:
         //GetMidiFileDirPreference((LPSTR)szInitialDir);
         break;
            
      case WAVE_FILE:
         break;  

      default:
         break;
   }

   *szFileName = '\0';
   MEMSET((LPOPENFILENAME)&ofn, 0, sizeof(OPENFILENAME));
   ofn.lStructSize      = sizeof(OPENFILENAME);
   ofn.hwndOwner        = NULL; //hWnd ? Make any difference ?;
   ofn.lpstrFilter      = szFileFilter[uFileType];
   ofn.lpstrFile        = szFileName;
   ofn.nMaxFile         = sizeof(szFileName);
   ofn.lpstrInitialDir  = NULL;
   ofn.lpstrTitle       = szTitleString[uFileType];
   ofn.Flags            = dwFlags;
   ofn.lpstrDefExt      = NULL;  //default extension added if not supplied by user
   ofn.nFilterIndex     = 1;
   ofn.lpstrFileTitle   = NULL;
   ofn.nMaxFileTitle    = 0;
   ofn.lpstrInitialDir  = *szInitialDir == '\0' ? NULL : szInitialDir;
       
   if (!GetOpenFileName( &ofn ))
      return (HANDLE)NULL;

#ifndef _WIN32
   MEMSET((LPOFSTRUCT)&ofs, 0, sizeof(OFSTRUCT));
   ofs.cBytes = sizeof(OFSTRUCT);
   // open the file
   hFile = (HANDLE)OpenFile(ofn.lpstrFile, &ofs, OF_READ);
   if ((HFILE)hFile == HFILE_ERROR) {
      Error("Error opening file.");
      return (HANDLE)NULL;
      }
        
#else //_WIN32   
   hFile = CreateFile(ofn.lpstrFile,
                      GENERIC_READ,
                      0,
                      (LPSECURITY_ATTRIBUTES)NULL,
                      OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL,
                      (HANDLE)NULL);
   if (hFile == INVALID_HANDLE_VALUE) {
      Error("Error opening file.");
      return (HANDLE)NULL;
   }
#endif

   return hFile;
}

/*-------------------------------------------------------------------
    GetBytesToRead
-------------------------------------------------------------------*/

DWORD GetBytesToRead(HANDLE hFile)
{
 #ifndef _WIN32 
   long lCurrentPos = _llseek ((HFILE)hFile, 0L, FILE_CURRENT); //1
   long lFileLength = _llseek ((HFILE)hFile, 0L, FILE_END); //2
   _llseek((HFILE)hFile, lCurrentPos, FILE_BEGIN); //0

   return (DWORD)(lFileLength - lCurrentPos);
#else
   DWORD dwCurrentPos = SetFilePointer(hFile, 0L, NULL, FILE_CURRENT);
   DWORD dwFileLength = SetFilePointer (hFile, 0L, NULL, FILE_END); 
   SetFilePointer (hFile, dwCurrentPos, NULL, FILE_BEGIN);

   return (dwFileLength - dwCurrentPos);
#endif
}


/*-------------------------------------------------------------------
    ReadSysexFile
-------------------------------------------------------------------*/

BOOL ReadSysexFile(HANDLE hFile, UINT uBytesToRead)
{
   LPMIDIHDR lpMHOut = NULL;     
   UINT uBytesRead = 0;
   UINT uError = MMSYSERR_NOERROR;
   LPCALLBACKINSTANCEDATA lpInst = NULL;
   EVENT event;

   lpInst = DefInstData();
   if(!lpInst) {
      Error("No default Instance.");
      return FALSE;
      }

   if(!lpInst->hMOut) {
      Error("No Out port.");
      return FALSE;
      }

   lpMHOut = FindOutBuffer(lpInst->lpSxOut);   
   if (!lpMHOut) {
      Error("No Output buffer.");
      return FALSE;
      }

#ifndef _WIN32
   uBytesRead = _lread((HFILE)hFile, lpMHOut->lpData, uBytesToRead); //bufSize 
   if (uBytesRead == HFILE_ERROR) {
      Error("Error reading file!");
      return FALSE;
      }
   if (uBytesRead == 0) {
      // we're at the end of the file
      return FALSE;
      }
#else
   if (!ReadFile(hFile, lpMHOut->lpData, uBytesToRead, (ULONG *)&uBytesRead, NULL)) {
      Error("Error reading file!");
      return FALSE;
      }
   if (uBytesRead == 0) {
      // we're at the end of the file
      return FALSE;
      }
#endif
   lpMHOut->dwBufferLength = (DWORD)uBytesRead;
   uError = midiOutLongMsg(lpInst->hMOut, lpMHOut, sizeof(MIDIHDR));
   event.wDevice   = 0xFFFF;
   event.data      = 0x0000F0;
   event.timestamp = 0L;
   PutEvent(lpInst->lpBuf, (LPEVENT)&event); 
   PostMessage(lpInst->hWnd, MM_MIDIINPUT, 0, 0L);
  
   if(uError != MMSYSERR_NOERROR) {
      MIDIErr(uError, (LPSTR)midiInCaps[lpInst->wDevice].szPname, FALSE);
      return FALSE;
      }
   return TRUE;
}

/*-------------------------------------------------------------------
    EndFileProcess
-------------------------------------------------------------------*/
void EndFileProcess(LPHANDLE lpFile)
{
    HANDLE hFile = *lpFile;
    //bFileBeingSent = FALSE;
    if (hFile != NULL) {
#ifndef _WIN32
       if (_lclose((HFILE)hFile))  
          Error("Error closing file.");
#else
       if(!CloseHandle(hFile))
          Error("Error closing file.");
#endif
       hFile = (HANDLE)NULL;
       *lpFile = hFile;
    }
}

