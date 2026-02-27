/*
 * MSCROLL.H
 *
 * Public definitions for application that use the MicroScroll.
 *  - Messages
 *  - Prototypes for Message API Functions
 *  - Notification codes.
 *  - Control Styles.
 *
 * Version 1.1, October 1991, Kraig Brockschmidt
 *
 */

#ifndef MSCROLL_H
#define MSCROLL_H


//Control-specific messages
#define MSM_HWNDASSOCIATESET  (WM_USER+1)
#define MSM_HWNDASSOCIATEGET  (WM_USER+2)
#define MSM_DWRANGESET        (WM_USER+3)
#define MSM_DWRANGEGET        (WM_USER+4)
#define MSM_WCURRENTPOSSET    (WM_USER+5)
#define MSM_WCURRENTPOSGET    (WM_USER+6)
#define MSM_FNOPEGSCROLLSET   (WM_USER+7)
#define MSM_FNOPEGSCROLLGET   (WM_USER+8)
#define MSM_FINVERTRANGESET   (WM_USER+9)
#define MSM_FINVERTRANGEGET   (WM_USER+10)
#define MSM_CRCOLORSET        (WM_USER+11)
#define MSM_CRCOLORGET        (WM_USER+12)

#ifdef __cplusplus
extern "C" {
#endif

//Message API Functions
HWND     FAR PASCAL MSHwndAssociateSet(HWND hWnd, HWND hWndAssociate);
HWND     FAR PASCAL MSHwndAssociateGet(HWND hWnd);
DWORD    FAR PASCAL MSDwRangeSet(HWND hWnd, WORD iMin, WORD iMax);
DWORD    FAR PASCAL MSDwRangeGet(HWND hWnd);
WORD     FAR PASCAL MSWCurrentPosSet(HWND hWnd, WORD iPos);
WORD     FAR PASCAL MSWCurrentPosGet(HWND hWnd);
BOOL     FAR PASCAL MSFNoPegScrollSet(HWND hWnd, BOOL fNoPegScroll);
BOOL     FAR PASCAL MSFNoPegScrollGet(HWND hWnd);
BOOL     FAR PASCAL MSFInvertRangeSet(HWND hWnd, BOOL fInvertRange);
BOOL     FAR PASCAL MSFInvertRangeGet(HWND hWnd);
COLORREF FAR PASCAL MSCrColorSet(HWND hWnd, WORD iColor, COLORREF cr);
COLORREF FAR PASCAL MSCrColorGet(HWND hWnd, WORD iColor);

#ifdef __cplusplus
}
#endif


//Notification codes sent via WM_COMMAND from the control.
#define MSN_ASSOCIATEGAIN   1
#define MSN_ASSOCIATELOSS   2
#define MSN_RANGECHANGE     3


//Color indices for MSM_COLORSET/GET and MSCrColorSet/Get
#define MSCOLOR_FACE        0
#define MSCOLOR_ARROW       1
#define MSCOLOR_SHADOW      2
#define MSCOLOR_HIGHLIGHT   3
#define MSCOLOR_FRAME       4

#define CCOLORS             5

//Control specific styles.
#define MSS_VERTICAL        0x0001L
#define MSS_HORIZONTAL      0x0002L
#define MSS_NOPEGSCROLL     0x0004L
#define MSS_TEXTHASRANGE    0x0008L
#define MSS_INVERTRANGE     0x0010L

#endif

