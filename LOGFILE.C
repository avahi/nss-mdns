///////////////////////////////////////////////////////////////////
// LogFile.c
//

#include <windows.h>
#include <commdlg.h>
#include <stdlib.h>
#include <stdio.h>
#include <io.h>
#include <time.h>
#include <memory.h>
#include "midimon.h"
#include "logfile.h"

#if 0
  #define MAYBE_TRACE TRACE
#else
  #define MAYBE_TRACE
#endif
 
#define LOGBUFSIZE 0x2000

extern char	szAppName[];              // Application name

static char  szLogPath[_MAX_PATH];
static LPSTR pszBuf = NULL;
static BOOL  isOpen = FALSE;

static int nCur = 0;

static LPLOGFILE lpLog;

static LPSTR TimeStamp(void);
static BOOL FlushBuffer(void);
static BOOL OpenLog(LPCSTR szLogPath, BOOL bAppend);

#ifdef _WIN32
static HANDLE h32File;
#else  // 16 bit
static HFILE h16File;
#endif

/* LogDlgProc - The dialog procedure for the "LogFile" dialog.
 *
 * Params:  hDlg - Specifies the associated dialog box.
 *          msg - Specifies the message from the dialog box.
 *          wParam - 16 bits of message-dependent data.
 *          lParam - 32 bits of message-dependent data.
 *
 * Returns: Non-zero if the message is processed, zero otherwise.
 */


BOOL FAR PASCAL LogDlgProc(
						HWND hDlg, 
						UINT msg, 
						WPARAM wParam, 
						LPARAM lParam
						)
{
	
   switch (msg) {
   	case WM_INITDIALOG:
			lpLog = (LPLOGFILE)lParam;
			CheckDlgButton(hDlg, IDC_LOGENABLED, lpLog->bEnabled);
			CheckDlgButton(hDlg, IDC_LOGAPPEND,  lpLog->bAppend);
        	SetDlgItemText(hDlg, IDC_LOGFILE,    lpLog->szLogFile);
        	CenterOnParent(hDlg);    
        	break;       
        	        
    	case WM_COMMAND:
         switch (LOWORD(wParam)) {
            case IDOK:              
					lpLog->bEnabled = IsDlgButtonChecked(hDlg, IDC_LOGENABLED);
					lpLog->bAppend  = IsDlgButtonChecked(hDlg, IDC_LOGAPPEND);
        			GetDlgItemText(hDlg, IDC_LOGFILE, lpLog->szLogFile, _MAX_PATH);
					if (IsLogOpen()) {
						if (lpLog->bEnabled) { // need to switch paths?
							if (ExpandPath(lpLog->szLogFile)) {
								if (STRICMP(lpLog->szLogFile, szLogPath)) { // not the same
									CloseLog();
									InitLog(lpLog);
									}
								}
							else {
								char szBuf[80];
								wsprintf(szBuf, "Invalid File Path: %s", (LPSTR)lpLog->szLogFile);
								MessageBox(hDlg, szBuf, NULL, MB_OK);
								break;
								}
							}
						else // disabling => stop logging
							CloseLog();
						}
					else {	// not open => need to start?
						if (lpLog->bEnabled) 
							InitLog(lpLog);
						}
		        	EndDialog(hDlg, IDOK);
					break;
					
				case IDCANCEL:
        			EndDialog(hDlg, IDCANCEL);
					break;

				case IDC_BROWSE:
					{
						OPENFILENAME ofn;
						char szFileName[_MAX_PATH];
  						DWORD dwVersion = GetVersion();
						DWORD dwFlags = OFN_HIDEREADONLY;
                  WORD  wWinVer = ((WORD)(LOBYTE(LOWORD(dwVersion)) << 8) | 
                  					  (WORD)HIBYTE(LOWORD(dwVersion)));

						// Win95 Only has Exlorer, but NT can do long filenames.
						if (dwVersion >= 0x80000000) // tricky code! = Win95 & WIN32
							dwFlags |= OFN_EXPLORER;
						else if (wWinVer >= 0x035F)	// 0x035F = 3.95 (Win95)	
							dwFlags |= OFN_LONGNAMES; 
     			   
						GetDlgItemText(hDlg, IDC_LOGFILE, szFileName, _MAX_PATH);

						MEMSET((LPOPENFILENAME)&ofn, 0, sizeof(OPENFILENAME));
						ofn.lStructSize		= sizeof(OPENFILENAME);
						ofn.hwndOwner			= hDlg;
						ofn.lpstrFilter		= "Text\0*.txt\0Any\0*.*\0";
						ofn.lpstrFile			= szFileName;
						ofn.nMaxFile			= sizeof(szFileName);
						ofn.lpstrInitialDir	= NULL;
						ofn.lpstrTitle			= "Create Log File";
						ofn.Flags				= dwFlags;
						ofn.lpstrDefExt		= "txt";
		             
						if (!GetSaveFileName( &ofn ))
							break;
			  
						SetDlgItemText(hDlg, IDC_LOGFILE, szFileName);
			        	break;
					}

				default:
		        	return FALSE;
					break;
				}

    	default:
        	return FALSE;
        	break;
    	}
    return TRUE;
}

////////////////////////////////////////////////////////////////////////

BOOL  FAR PASCAL InitLog(LPLOGFILE lpLF) 
{
	char szBuf[80];
   
   ASSERT(lpLF); 
   ASSERT(!isOpen);
   
	if (!lpLF->bEnabled)
		return FALSE;

	lpLF->bEnabled = FALSE; // until success...

	if (!VERIFY(ExpandPath(lpLF->szLogFile)))
		return FALSE;

	STRCPY(szLogPath, lpLF->szLogFile);

	if (!VERIFY(pszBuf = (LPSTR)malloc( LOGBUFSIZE ))) {
		Error("Out of memory -- Log Buffer");	
		return FALSE;
	   }
	nCur = 0;

	if (!OpenLog(szLogPath, lpLF->bAppend)) { 
		char szBuf[80];
		wsprintf(szBuf, "Open Log Failed: %s", (LPSTR)szLogPath);
		Error(szBuf);
		return FALSE;
		}
		
   LogString(
		szBuf, 
		wsprintf(szBuf, " ===> %s Log Opened: %s ===>", (LPSTR)szAppName, (LPSTR)TimeStamp())
		);       
	
	// print the column headings
  	LogString(LABEL, sizeof(LABEL));

	lpLF->bEnabled = TRUE;

   return TRUE;
	}

////////////////////////////////////////////////////////////////////////

BOOL  FAR PASCAL IsLogOpen(void) 
{
	return isOpen;
	}

////////////////////////////////////////////////////////////////////////

LPSTR FAR PASCAL GetLogPath(void)
{
	return szLogPath;
	}

////////////////////////////////////////////////////////////////////////

LPSTR FAR PASCAL ExpandPath(LPSTR pszPath)
{
	char szBuf[_MAX_PATH];
	char *p = (char *)(DWORD)pszPath;
   
	if (NULL != _fullpath(szBuf, p, _MAX_PATH)) {
		STRCPY(pszPath, (LPSTR)szBuf);             
		return pszPath;
		}    
	return NULL;
	}

////////////////////////////////////////////////////////////////////////

BOOL FAR PASCAL CloseLog(void)
{
	char szBuf[80];

	ASSERT(isOpen);
   MAYBE_TRACE("in CloseLog()\n");

   LogString(
		szBuf, 
		wsprintf(szBuf, " <=== %s Log Closed: %s <===", (LPSTR)szAppName, (LPSTR)TimeStamp())
		);

	VERIFY(FlushBuffer());	// force writes to file
	free((char *)(DWORD)pszBuf);
	pszBuf = NULL;
	
#ifdef _WIN32
	CloseHandle(h32File);
#else
	_lclose(h16File);
#endif
	isOpen = FALSE;
	return TRUE;
	}

////////////////////////////////////////////////////////////////////////

BOOL  FAR PASCAL LogString(LPCSTR psz, int nLen) 
{
	if (!isOpen)
		return FALSE;

	if (nCur + nLen + 2 >= LOGBUFSIZE) {
		if (!FlushBuffer())
			return FALSE;
		}

	// stick the string in the buffer
	nCur += wsprintf(&pszBuf[nCur], "%s\r\n", (LPSTR)psz);
   return TRUE;
}


////////////////////////////////////////////////////////////////////////

BOOL OpenLog(LPCSTR lpszPath, BOOL bAppend) 
{
#ifdef _WIN32
	DWORD 	dwMode = bAppend ? OPEN_ALWAYS : CREATE_ALWAYS;
	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = FALSE;

	ASSERT(!isOpen);
   MAYBE_TRACE("in OpenLog() 32 Bit\n");

	h32File = CreateFile
					(
						lpszPath,
						GENERIC_WRITE,
						0L,
						&sa,
						dwMode,
						FILE_ATTRIBUTE_NORMAL,
						NULL
					);
	if (INVALID_HANDLE_VALUE == h32File)
		return FALSE;

	if (bAppend) // move to end of file
		SetFilePointer(h32File, 0, NULL, FILE_END);

#else	// !_WIN32
	OFSTRUCT ofs;
	UINT     uMode	= OF_WRITE;
	BOOL     bExist = FALSE;
	ofs.cBytes = sizeof(OFSTRUCT);
	
	ASSERT(!isOpen);
   MAYBE_TRACE("in OpenLog() 16 Bit\n");
   
	// see if it exists...try to read it
	h16File = _lopen(lpszPath, READ);
	if (h16File != HFILE_ERROR) {
	   bExist  = TRUE; 	// assume existence
   	_lclose(h16File);	// close regardless
   	}
   	
	if (!bAppend || !bExist) { // create the file
		if ((h16File = _lcreat(lpszPath, 0)) == HFILE_ERROR) // normal file = 0
			return FALSE;
   	_lclose(h16File);	// again, close regardless
   	}
		
	if ((h16File = _lopen(lpszPath, WRITE| OF_SHARE_EXCLUSIVE)) == HFILE_ERROR) 
		return FALSE;

	if (bAppend) // move to end of file
		_llseek(h16File, 0, 2);

#endif
		
	isOpen = TRUE;
	return TRUE;
	}	


////////////////////////////////////////////////////////////////////////

BOOL FlushBuffer(void)
{
	ASSERT(isOpen);
	ASSERT(pszBuf);
   MAYBE_TRACE("in FlushBuffer()\n");

	if (nCur > 0) {
#ifdef _WIN32
		DWORD dwCb;
		if (!WriteFile(h32File, pszBuf, nCur, &dwCb, NULL)) 
			return FALSE;
#else
		if (_lwrite(h16File, pszBuf, nCur) == HFILE_ERROR)
			return FALSE;
#endif
		}
	nCur = 0;		// reset to start over

	return TRUE;
	}
	
////////////////////////////////////////////////////////////////////////

LPSTR TimeStamp(void)
{  
	const char WDay[7][4] 	 =  { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
	const char Month[12][4] =	 {	"Jan", "Feb", "Mar",	"Apr", "May", "Jun", 
											"Jul", "Aug", "Sep",	"Oct", "Nov", "Dec" };
	static char szBuf[32];
	struct tm *nt;
	time_t aclock;
   
   time( &aclock );            // Get time in seconds 
   nt = localtime( &aclock );  // Convert time to struct 
                               // tm form
   wsprintf(
   	szBuf, 
   	"%3.3s %02.2d-%3.3s-%02.2d %02.2d:%02.2d:%02.2d",
   	(LPSTR)WDay[nt->tm_wday], 
   	nt->tm_mday, 
   	(LPSTR)Month[nt->tm_mon], 
   	nt->tm_year,
   	nt->tm_hour,
   	nt->tm_min,
   	nt->tm_sec
   	);
	return szBuf;
	}
