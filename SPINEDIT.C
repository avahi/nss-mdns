/*
 * SPINEDIT.C
 *
 * Contains the main window procedure of the MicroScroll control
 * that handles mouse logic, and Windows messages.
 *     
 * Version 1.0 March 1993 Jamie O'Connell
 */

#include <windows.h>
#include "midimon.h"
#include "mscroll.h"
#include "spinedit.h"

char szPropName[] = "SpinEdPropLs";
FARPROC lpfnWP = NULL; 
int     wUsageCt = 0;

typedef struct tagPROPVAL {
  HWND    hDad;
  HWND    hEdt;
  HWND    hSpn;
  WORD    idEdt;
  WORD    idSpn;
  BOOL    fNtfy;
  WNDPROC OldEditWndProc;
  } PROPVAL;
  
typedef PROPVAL *LPPROPVAL;

// Setup and SubClass the Edit Control

BOOL SetupSpinEdit(HWND hParent, HINSTANCE hInst, UINT idEditCtl, 
                   UINT idSpinCtl, WORD msMin, WORD msMax,  
                   WORD msDft, BOOL fNotify) {
	HWND      hEdit;
	HWND      hSpin;
    LPPROPVAL hMem;
    char      szNum[5];
    
    hEdit = GetDlgItem(hParent, idEditCtl);
    hSpin = GetDlgItem(hParent, idSpinCtl); 
    
    hMem = (LPPROPVAL)LocalAlloc(LPTR, sizeof(PROPVAL));
    hMem->hDad = hParent;
    hMem->hEdt  = hEdit;
    hMem->hSpn  = hSpin;
    hMem->idEdt = idEditCtl;
    hMem->idSpn = idSpinCtl;
    hMem->fNtfy = fNotify;
    hMem->OldEditWndProc = (WNDPROC)GetWindowLong(hEdit, GWL_WNDPROC);
    
    if (!SetProp(hEdit, (LPCSTR)szPropName, (HANDLE)hMem))
      return(FALSE);
    
    // Initialize the spinner   
    MSHwndAssociateSet(hSpin, hEdit);
    MSDwRangeSet(hSpin, msMin, msMax);
    MSWCurrentPosSet(hSpin, msDft);

    // Initialize the edit control
    wsprintf(szNum, "%d", msDft);
    SendMessage(hEdit, WM_SETTEXT, 0, (LPARAM)(LPCSTR)szNum);
    
    // Now SubClass it
    if (wUsageCt == 0)
        lpfnWP = MakeProcInstance((FARPROC)SpinEditWndProc, hInst);
    SetWindowLong(hEdit, GWL_WNDPROC, (LONG)lpfnWP);
    ++wUsageCt;
    return TRUE;
    }


/*
 * SpinEditWndProc
 *
 * Purpose:
 *  Window class procedure. SubClasses Edit
 *
 * Parameters:
 *  The standard.  See Section 2.4 Windows SDK Guide to Programming,
 *  page 2-4.
 *
 * Return Value:
 *  See Parameters, above.
 *
 */

long FAR PASCAL _export SpinEditWndProc(HWND hWnd, UINT iMessage,
			       WPARAM wParam, LPARAM lParam) {
    short       wPos;
    char        szNum[5];
    DWORD       dwRange;
    short       wNum;
    short       wMax;
    short       wMin;
    BOOL        bTranslated; 
    BOOL        fCallBCWndProc = FALSE;
    LONG        lResult = 0;
    LPPROPVAL   hMem;
    WPARAM      wNParm;
    
    hMem = (LPPROPVAL)GetProp(hWnd, (LPCSTR)szPropName);
    
    switch (iMessage) {
        case WM_DESTROY:
            {
            RemoveProp(hWnd, szPropName);
            SetWindowLong(hWnd, GWL_WNDPROC, (LONG)hMem->OldEditWndProc);
            LocalFree((HLOCAL)hMem);
            if (--wUsageCt == 0)   // Free Ourselves
               FreeProcInstance(lpfnWP);
            }
            break;

        case WM_COMMAND:
            switch (wParam) {
                case IDM_EXIT:
                    PostMessage(hWnd, WM_CLOSE, 0, 0L);
                    break;
                }
            break;

        case WM_VSCROLL:
            //For vertical scrolling we implement a spin button.

            //Ignore what comes from MSM_WCURRENTPOSSET
            if (wParam==SB_THUMBTRACK)
                break;

            SetFocus(hWnd);

            if ((HWND)HIWORD(lParam) == hMem->hSpn) {
                wPos=LOWORD(lParam);

                /*
                 * The code between here and the wsprintf case where
                 * we change the edit control's text is entirely to
                 * support the case where the use might have typed a
                 * different value into the edit control.
                 */

                dwRange=SendMessage(hMem->hSpn, MSM_DWRANGEGET, 0, 0L);
                wMax=HIWORD(dwRange);
                wMin=LOWORD(dwRange);

                //Get the number in the control.
                wNum=GetDlgItemInt(hMem->hDad, hMem->idEdt, &bTranslated, TRUE);

                /*
                 * Check if we got a valid value from the control. Otherwise
                 * use the current position.
                 */
                if (bTranslated) {
                    /*
                     * If we are decrementing the value and wNum-1==wPos,
                     * then we don't need to modify anything.  Otherwise,
                     * wPos must become wNum-1 if that is >= minimum.
                     */
                    switch (wParam) {
                      case SB_LINEDOWN:
                        wPos =  (wNum > wMin) ? wNum-1 : wMin;
                        break;
                        
                      case SB_LINEUP:
                        wPos = (wNum < wMax) ? wNum+1 : wMax;
                        break;
                        
                      case SB_PAGEDOWN:
                        wPos =  (wNum-8 > wMin) ? wNum-8 : wMin;
                        break;
                        
                      case SB_PAGEUP:
                        wPos = (wNum+8 < wMax) ? wNum+8 : wMax; 
                        break;
                        
                      case SB_TOP:
                        wPos = wMin;
                        break;
                        
                      case SB_BOTTOM:
                        wPos = wMax; 
                        break;
                      }
                    }
                 
                //Update the current position if it changed.
                if (wPos!=(short)LOWORD(lParam))
                    SendMessage(hMem->hSpn, MSM_WCURRENTPOSSET, wPos, 0L);
      
                //Only change the control if we have to.
                if (wPos!=wNum) {
                    //Convert the value and put it in the control.
                    wsprintf(szNum, "%d", wPos);
                    SendMessage(hWnd, WM_SETTEXT, 0, (LPARAM)(LPCSTR)szNum);
                    if (hMem->fNtfy)
                        SendMessage(hMem->hDad, MSM_NOTIFY, wNum, 0L);
                      
                    }

                /*
                 * We always want to do this in case the user typed something but we
                 * could not scroll (like they typed in the max), in which case the
                 * selection went away.
                 */
                SendMessage(hWnd, EM_SETSEL, 0, MAKELONG(0, 32767));
                }
            break;
            
        case WM_CHAR:
            switch(wParam) {         /* virtual-key code */
              case VK_ADD:
              case VK_SUBTRACT:  
                break;   
              default:
                fCallBCWndProc = TRUE;
              }
              break;
              
        case WM_KEYDOWN:
            switch(wParam) {         /* virtual-key code */
              case VK_UP:
              case VK_ADD:
                wNParm = SB_LINEUP;
                break;   
              case VK_DOWN:
              case VK_SUBTRACT:  
                wNParm = SB_LINEDOWN;
                break;   

              case VK_PRIOR:
                wNParm = SB_PAGEUP;
                break;   

              case VK_NEXT:
                wNParm = SB_PAGEDOWN;
                break;   

              case VK_HOME:
                wNParm = SB_TOP;
                break;   

              case VK_END:
                wNParm = SB_BOTTOM;
                break;   

              default: 
                wNParm = 0; 
                fCallBCWndProc = TRUE;
                break;
              }
            if (!fCallBCWndProc) 
               SendMessage(hWnd, WM_VSCROLL, wNParm, MAKELONG(0, hMem->hSpn));
            break;
        default:
            fCallBCWndProc = TRUE;
        }
     
    if (fCallBCWndProc) {
      // Call the base class window procedure and return its result 
      // to the caller.
      
      lResult = CallWindowProc(hMem->OldEditWndProc,
                                hWnd, iMessage, wParam, lParam);
      }

    return(lResult);
    }
