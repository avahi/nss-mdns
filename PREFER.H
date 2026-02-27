///////////////////////////////////////////////////////////////////
//  prefer.h
//

#ifndef PREFER_H_
#define PREFER_H_

/* MIDIMON.INI entries.
 */

/* Default values for preference variables.
 */
#define DEF_X               20
#define DEF_Y              100
#define DEF_W              531
#define DEF_H              281
#define DEF_ON               0
#define DEF_OCTV             4
#define SYSEXTIMERDELAY     55

/* Data structure used to specify user preferences.
 */

typedef struct tagNMBLK {
        char Nm[24][40];
        } NMBLK;
        
typedef NMBLK FAR *LPNM;
 
typedef struct preferences_tag {
    int      iInitialX;
    int      iInitialY;
    int      iInitialW;
    int      iInitialH;
    COLORREF colBkGd;
    COLORREF colText;
    COLORREF colLblBkGd;
    COLORREF colLblText;
    COLORREF clrNoteOff;
    COLORREF clrNoteOn;
    COLORREF clrAfterT;
    COLORREF clrControl;
    COLORREF clrProgram;
    COLORREF clrPitchB;
    COLORREF clrSystem;
    int      iFixFont;    
    DWORD    dwInputBufferSize;
    DWORD    dwDisplayBufferSize;
    int      wDisplayFormat;
    int      bThruOn;
    int      bOnTop;
    int      bPasSX;
    int      nInDev;
    int      nSxBuf;
    int      bufSize;
    int      nOctave;
	 BOOL		 bLogEnabled;
	 BOOL		 bLogAppend;
	 LPSTR    lpszLogFile;
    LPNM     lpIDN;
    LPSTR    lpszOutDev;
	 LPFILTER lpFilter;
    } PREFERENCES;

typedef PREFERENCES FAR *LPPREFERENCES;

/* Function prototypes
 */

void		getPreferences(HINSTANCE, LPPREFERENCES);
void		setPreferences(LPPREFERENCES);
int		GetProfInt(LPCSTR szSect, LPCSTR szKey, int nDefault); 
BOOL		SetProfInt(LPCSTR szSect, LPCSTR szKey, int nValue); 
BOOL		SetProfColor(LPCSTR szKey, COLORREF rgb);
COLORREF GetProfColor(LPCSTR szKey, LPCSTR szDft);
void GetSysexFileDirPreference(LPSTR lpszFileDir);
//void GetMidiFileDirPreference(LPSTR lpszFileDir);
UINT GetSysexDelayPreference(void);

#endif
