/*
 *    midimon.h
 */

#ifndef _MIDIMON_H
#define _MIDIMON_H

#include "resource.h"

#ifdef _WIN32
#  define _export
#  define STRICMP _stricmp
#  define MEMSET  memset
#  define MEMCPY  memcpy
#  define STRCPY  strcpy
#  define GlobalPageLock(a)	((void *)0)
#  define GlobalPageUnlock(a) ((void *)0)
#  define STRDUP  _strdup
#else	// win31
   typedef MINMAXINFO FAR* LPMINMAXINFO; // not defed for 3.1
#  ifdef __BORLANDC__
#    define STRICMP stricmp
#  else
#    define STRICMP lstrcmpi
#    define MEMSET  _fmemset
#    define MEMCPY  _fmemcpy
#    define STRDUP  _fstrdup
#  endif                             
// Etched is Win32 enhanced -- gray looks etched in ctl3d
#  define SS_ETCHEDFRAME SS_GRAYFRAME
#  define SS_SUNKEN		 SS_BLACKFRAME
#  define STRCPY lstrcpy
// appropriated from MSDEV commdlg.h
// #define OFN_EXPLORER                 0x00080000     // new look commdlg
// #define OFN_NODEREFERENCELINKS       0x00100000
#  define OFN_LONGNAMES               	0x00200000     // force long names for 3.x modules
#  define OFN_EXPLORER						0x00000000
#endif

#include "debug.h"

#define TODO()

#ifndef MMRESULT
#define MMRESULT UINT
#endif

#ifndef WM_PAINTICON
#define WM_PAINTICON  0x26
#endif

/* Compile-time application metrics
 */
#define MAX_NUM_DEVICES         24       // max # of MIDI devices
#define INPUT_BUFFER_SIZE       200     // size of input buffer in events
#define DISPLAY_BUFFER_SIZE     1000    // size of display buffer in events

/* Menu IDs 
 */

/* ICON in the About Box...
 *
 */
 
#define IDC_MMICON              1007

/* Custom messages sent by low-level callback to application 
 */
#define MM_MIDIINPUT     WM_USER + 20
#define MM_SUICIDE       WM_USER + 21
#define MM_ANIMATEICON   WM_USER + 22
#define MM_ADDBUFFER     WM_USER + 23

// Sent by subsequent instance
#define WM_ACTIVATEFIRST WM_USER + 24

#define MM_ADDTXTMSG     WM_USER + 25

// MIDI command codes
#define MC_NOTEOFF              0x80
#define MC_CONTROLLER           0xB0
#define MC_PATCHCHANGE          0xC0
#define MC_PITCHBEND            0xE0

#define MCV_MODWHEEL            0x01
#define MCV_SUSTPEDAL           0x40
#define MCV_RPNMSB              0x65
#define MCV_RPNLSB              0x64
#define MCV_DATAMSB             0x06
#define MCV_DATALSB             0x26
#define MCV_RESETCTL            0x79
#define MCV_ALLOFF              0x7B


// Icon Data => scrolling icons

#define NUMICONS    4

// special display IDs

#define DEVMON	 -1
#define DEVMSG	 -2

/* The label for the display window.
 */
#define LABEL " TIMESTAMP PORT STATUS DATA1 DATA2 CHAN NOTE EVENT             "

/* MIDI status byte definitions
 */
#define NOTEON          0x90
#define NOTEOFF         0x80
#define KEYAFTERTOUCH   0xA0
#define CONTROLCHANGE   0xB0
#define PROGRAMCHANGE   0xC0
#define CHANAFTERTOUCH  0xD0
#define PITCHBEND       0xE0
#define SYSTEMMESSAGE   0xF0
#define BEGINSYSEX      0xF0
#define MTCQUARTERFRAME 0xF1
#define SONGPOSPTR      0xF2
#define SONGSELECT      0xF3

#define CCBANKMSB			0		// Bank change
#define CCMODULATION		1		// Modulation Wheel
#define CCDEMSB			6		// Data Entry MSB
#define CCVOLUME			7		// Volume controller
#define CCPAN				10		// Panning controller
#define CCBANKLSB			32		// Bank change LSB
#define CCDELSB			38		// Data Entry LSB
#define CCPEDAL			64		// Sustain pedal
#define CCREVERB			91		// Reverb Depth
#define CCCHORUS			93		// Chorus Depth
#define CCINCR				96		// Data increment
#define CCDECR				97		// Data decrement
#define CCNRPNLSB			98		// Non Reg Parm LSB
#define CCNRPNMSB			99		// Non Reg Parm MSB
#define CCRPNLSB			100	// Reg Parm LSB
#define CCRPNMSB			101	// Reg Parm MSB
#define CCRESETCC			121	// Reset Controllers

#define BENDRNG           0   // Registered Parm number

/* Structure for translating virtual key messages to scroll messages.
 */
typedef struct keyToScroll_tag {
     WORD wVirtKey;
     int  iMessage;
     WORD wRequest;
     } KEYTOSCROLL;

/* Structure to represent a single MIDI event.
 */
typedef struct event_tag
{
    WORD  wDevice;
    DWORD timestamp;
    DWORD data;
} EVENT;
typedef EVENT FAR *LPEVENT;

typedef COLORREF FAR *LPCOLORREF;

/* Function prototypes 
 */

#ifdef __cplusplus
extern "C" {
#endif
      
long FAR PASCAL _export WndProc(HWND, UINT, WPARAM ,LPARAM );
BOOL FAR PASCAL _export MDevDlgProc(HWND hwndDlg, UINT msg,
                             WPARAM wParam, LPARAM lParam);
BOOL FAR PASCAL _export CtlPnl(HWND hwndDlg, UINT msg,
                             WPARAM wParam, LPARAM lParam);
BOOL FAR PASCAL _export FilterDlgProc(HWND hDlg, UINT msg, 
                             WPARAM wParam, LPARAM lParam);
BOOL FAR PASCAL _export MIDIStatus(HWND hDlg, UINT msg, 
									  WPARAM wParam, LPARAM lParam);

void About(HINSTANCE hInstance, HWND hWnd);
int  FAR PASCAL _export AboutDlgProc(HWND, UINT, WPARAM, LPARAM);
void CommandMsg(HWND hWnd, WPARAM wParam, LPARAM lParam);
void DoMenuItemCheck(HWND hWnd, UINT menuItem, BOOL newState);
void SetupCustomChecks(HINSTANCE hInstance, HWND hWnd);
BOOL InitFirstInstance(HINSTANCE hInstance);
int  Error(LPSTR msg);
void CenterOnParent(HWND hDlg);
void FAR PASCAL InitInstance(HINSTANCE hInst);

#ifdef __cplusplus
}
#endif

#endif
