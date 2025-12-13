/*
 * MSCRDLL.H
 *
 * DLL Specific include file.
 *
 * Contains all definitions and and prototypes pertinent ONLY
 * to the DLL.  API related information is contained in MUSCROLL.H.
 * API in any way.
 *
 * Version 1.1, October 1991, Kraig Brockschmidt
 *
 */


#ifndef MSCRDLL_H
#define MSCRDLL_H

#include <custcntl.h>   //Standard Windows header file for custom controls.
#include "mscroll.h"    //Get interface stuff for the control.

#ifdef _WIN32
#  define MOVETO(a, b, c, d) MoveToEx((a),(b),(c),(d))
#  define W16CS_GLOBALCLASS 0
#else	// win31
#  define MOVETO(a, b, c, d) MoveTo((a),(b),(c))
#  define W16CS_GLOBALCLASS CS_GLOBALCLASS
#endif

#define MMSCROLLNAME	"MMMScroll"

/*
 * In window extra bytes we simply store a local handle to
 * a MSCROLL data structure.  The local memory is allocated
 * from the control's local heap (either application or DLL)
 * instead of from USER's heap, thereby saving system resources.
 *
 * Note that the window styles that are stored in the regular
 * windwow structure are copied here.  This is to optimize access
 * to these bits, avoiding extra calls to GetWindowLong.
 */

typedef struct tagMUSCROLL
    {
    HWND        hWndAssociate;  //Associate window handle
    DWORD       dwStyle;        //Copy of GetWindowLong(hWnd, GWL_STYLE)
    short       iMin;           //Minimum position
    short       iMax;           //Maximum position
    short       iPos;           //Current position
    WORD        wState;         //State flags
    COLORREF    rgCr[CCOLORS];  //Configurable colors.
    } MUSCROLL;

typedef MUSCROLL     *PMUSCROLL;
typedef MUSCROLL FAR *LPMUSCROLL;

#define CBMUSCROLL sizeof(MUSCROLL)


//Offsets to use with GetWindowWord
#define GWW_MUSCROLLHMEM    0
#define GWL_MUSCROLLHMEM    0	// win32

//Extra bytes for the window if the size of a local handle.
#define CBWINDOWEXTRA       sizeof(HLOCAL)

//Extra Class bytes.
#define CBCLASSEXTRA        0

//Control state flags.
#define MUSTATE_GRAYED      0x0001
#define MUSTATE_HIDDEN      0x0002
#define MUSTATE_MOUSEOUT    0x0004
#define MUSTATE_UPCLICK     0x0008
#define MUSTATE_DOWNCLICK   0x0010
#define MUSTATE_LEFTCLICK   0x0008  //Repeated since MSS_VERTICAL and
#define MUSTATE_RIGHTCLICK  0x0010  //MSS_HORIZONTAL are exclusive.

//Combination of click states.
#define MUSTATE_CLICKED     (MUSTATE_LEFTCLICK | MUSTATE_RIGHTCLICK)

//Combination of state flags.
#define MUSTATE_ALL         0x001F

/*
 * Macros to change the control state given a PMUSCROLL
 * and state flag(s)
 */
#define StateSet(p, wFlags)    (p->wState |=  (wFlags))
#define StateClear(p, wFlags)  (p->wState &= ~(wFlags))
#define StateTest(p, wFlags)   (p->wState &   (wFlags))

//Private functions specific to the control.

#ifdef __cplusplus
extern "C" {
#endif

//INIT.C

BOOL   FAR PASCAL MMRegisterControl( HINSTANCE );
LONG   FAR PASCAL LMicroScrollCreate(HWND, UINT, PMUSCROLL, LPCREATESTRUCT);
BOOL   FAR PASCAL FTextParse(LPSTR, LPINT, LPINT, LPINT);
WORD   FAR PASCAL WTranslateUpToChar(LPSTR FAR *, char);

//MSAPI.C
LONG   FAR PASCAL LMicroScrollAPI(HWND, UINT, WPARAM, LPARAM, PMUSCROLL);


//MUSCROLL.C
LONG   FAR PASCAL MMMScrollWndProc(HWND, UINT, WPARAM, LPARAM);
void   FAR PASCAL PositionChange(HWND, PMUSCROLL);
void   FAR PASCAL ClickedRectCalc(HWND, PMUSCROLL, LPRECT);


//PAINT.C
LONG   FAR PASCAL LMicroScrollPaint(HWND, PMUSCROLL);
void   FAR PASCAL Draw3DButtonRect(HDC, HPEN, HPEN, WORD, WORD,\
                                   WORD, WORD, BOOL);

//WEP.C
// void   FAR PASCAL WEP(int);


#ifndef _WIN32
//Standard dialog editor callbacks.
HANDLE FAR PASCAL HCtlInfo(void);
WORD   FAR PASCAL WTranslateCtlFlags(DWORD, LPSTR, WORD);
BOOL   FAR PASCAL FShowCtlStyleDlg(HWND, HANDLE, LPFNSTRTOID, LPFNIDTOSTR);
BOOL   FAR PASCAL FCtlStyleDlgProc(HWND, WORD, WORD, LONG);
#endif

#ifdef __cplusplus
}
#endif

//Timer identifiers.
#define IDT_FIRSTCLICK      500
#define IDT_HOLDCLICK       501

#define CTICKS_FIRSTCLICK   400
#define CTICKS_HOLDCLICK    50


//Default range and position constants.
#define IDEFAULTMIN         0
#define IDEFAULTMAX         9
#define IDEFAULTPOS         5

//Stringtable identifiers
#define IDS_CLASSNAME           2
#define IDS_FULLNAME            3
#define IDS_CREDITS             4

//Dialog editor interface string
#define IDS_VERTICAL            5
#define IDS_HORIZONTAL          6
#define IDS_MSS_VERTICAL        7
#define IDS_MSS_HORIZONTAL      8
#define IDS_MSS_TEXTHASRANGE    9
#define IDS_MSS_NOPEGSCROLL     10
#define IDS_MSS_INVERTRANGE     11
#define IDS_RANGEERROR          12

/*
 * All that follows in this include file is specific to
 * the dialog editor interface for the MicroScroll control.
 */

//Identifiers for the Style dialog.
#define ID_NULL                 -1
#define ID_IDEDIT               100
#define ID_TEXTEDIT             101
#define ID_RADIOVERTICAL        102
#define ID_RADIOHORIZONTAL      103
#define ID_CHECKTEXTHASRANGE    104
#define ID_CHECKNOPEGSCROLL     105
#define ID_CHECKINVERTRANGE     106

//Dialog box identifiers.
#define IDD_STYLEDIALOG         1


#endif
