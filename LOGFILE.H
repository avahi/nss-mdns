/*
 *   logfile.h
 */

/* Structure to specify a filter for MIDI events.
 */
typedef struct logfile_tag
{
    BOOL		bEnabled;					// is log enabled
	 BOOL		bAppend;						// do we append
	 char		szLogFile[_MAX_PATH];	// the file path
} LOGFILE, FAR *LPLOGFILE;


/* Function prototypes
 */                               

BOOL  FAR PASCAL InitLog(LPLOGFILE lpLF);
BOOL  FAR PASCAL IsLogOpen(void);
LPSTR FAR PASCAL GetLogPath(void);
LPSTR FAR PASCAL ExpandPath(LPSTR pszPath);
BOOL  FAR PASCAL CloseLog(void); 
BOOL  FAR PASCAL LogString(LPCSTR psz, int nLen);

BOOL FAR PASCAL LogDlgProc(
						HWND hDlg, 
						UINT msg, 
						WPARAM wParam, 
						LPARAM lParam
						);

