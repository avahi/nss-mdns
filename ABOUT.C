/*
 * about.c - Show the "About" box.
 */

#include <windows.h>
#include "midimon.h"

/* About - Shows the "About MIDI Monitor"  dialog.
 *
 * Params:  hWnd - The application's main window handle.
 *          hInstance - The application's instance handle.
 *
 * Returns: void
 */     

extern char szAppName[];
extern char VerStr[];

void About(
      HINSTANCE hInstance, 
      HWND hWnd
      ) 
{
    FARPROC fpDlg;

    fpDlg = MakeProcInstance((FARPROC)AboutDlgProc, hInstance);
    DialogBox(hInstance, "About", hWnd, (DLGPROC)fpDlg);
    FreeProcInstance(fpDlg);
    }


/* AboutDlgProc - The dialog procedure for the "About MIDI Monitor" dialog.
 *
 * Params:  hDlg - Specifies the associated dialog box.
 *          msg - Specifies the message from the dialog box.
 *          wParam - 16 bits of message-dependent data.
 *          lParam - 32 bits of message-dependent data.
 *
 * Returns: Non-zero if the message is processed, zero otherwise.
 */
int  FAR PASCAL AboutDlgProc(HWND hDlg, 
                             UINT msg, 
                             WPARAM wParam, 
                             LPARAM lParam) {
	static int x = 0;
	static int y = 0;
	static curIcon = 0;
	
   extern HICON hIconList[];
   char   Buf[80];
   RECT   rc;
   HWND   hwIcn;
   UINT   uRslt;
                             
   switch (msg) {
   	case WM_INITDIALOG:
        	SetDlgItemText(hDlg, IDC_APPTITLE, szAppName);
      	wsprintf(Buf, "Version: %s", (LPSTR)VerStr);
        	SetDlgItemText(hDlg, ID_VERSTR, Buf);
        	CenterOnParent(hDlg);    
        
        	// find out where Icon is
        	hwIcn = GetDlgItem(hDlg, IDC_MMICON);
        	GetWindowRect(hwIcn, &rc);
        	ScreenToClient(hDlg, (LPPOINT)&rc.left);
         x = rc.left;
         y = rc.top;
         
        	// create a timer - to arrive here
        	uRslt = SetTimer(hDlg, 1, 100, NULL);
        	break;       
        	
    	case WM_TIMER:
         if (wParam == 1) {
            HDC hdc = GetDC(hDlg);
            curIcon = ++curIcon % NUMICONS;                        
            if (hdc) {               
               if (GetMapMode(hdc) != MM_TEXT)
                  SetMapMode(hdc, MM_TEXT);
      		   DrawIcon(hdc, x, y, hIconList[curIcon]);
    				ReleaseDC(hDlg, hdc);
               }
            }
         break;
         
    	case WM_COMMAND:
    	  	KillTimer(hDlg, 1);
        	EndDialog(hDlg, TRUE);
        	break;

    	default:
        	return FALSE;
        	break;
    	}
    return TRUE;
}
