/*
 * CTLDLG.C
 *
 * Routines to interface the DLL custom control to
 * the Dialog Editor.
 *
 * Version 1.1, October 1991, Kraig Brockschmidt
 */


#include <windows.h>
#include "mscrdll.h"


/*
 * Globals for use in the Style Dialog.
 */

HANDLE      hStyleMem;
LPFNSTRTOID lpStrToId;
LPFNIDTOSTR lpIdToStr;

extern HINSTANCE ghInst;

WORD PASCAL WFormStyleFlags(HWND);
BOOL PASCAL FRangePositionCheck(HWND hDlg);



/*
 * HCtlInfo
 *
 * Purpose:
 *  Provides basic information about the control to the caller, which
 *  is usually the Dialog Editor or any other possible future program
 *  that edits dialog tempaltes and needs to know about controls.
 *
 *  The information is contained in a global memory object of type
 *  INFO.  This memory object becomes the responsibility of the
 *  caller.
 *
 * Parameters:
 *  none
 *
 * Return Value:
 *  HANDLE      Handle to a Global memory object or NULL if it cannot
 *              be allocated.  The caller must free the memory.
 *              ALLOCATE WITH GMEM_DDESHARE!
 *
 */

HANDLE FAR PASCAL HCtlInfo(void)
    {
    HANDLE      hMem;
    LPCTLINFO   pCtlInfo;

    //Allocate a INFO struct
    hMem=GlobalAlloc(GMEM_MOVEABLE, sizeof(CTLINFO));

    if (hMem==NULL)
        return NULL;

    //Get the pointers we need.
    pCtlInfo=(LPCTLINFO)GlobalLock(hMem);

    if (pCtlInfo==NULL)
        {
        GlobalFree(hMem);
        return NULL;
        }

    //Set the overall control info.
    pCtlInfo->wVersion=0100;
    pCtlInfo->wCtlTypes=2;
    LoadString(ghInst, IDS_CLASSNAME, pCtlInfo->szClass, CTLCLASS);
    LoadString(ghInst, IDS_FULLNAME,  pCtlInfo->szTitle, CTLTITLE);

    //Set the types
    pCtlInfo->Type[0].wType  =0;
    pCtlInfo->Type[0].wWidth =11;
    pCtlInfo->Type[0].wHeight=20;
    pCtlInfo->Type[0].dwStyle=WS_CHILD | WS_VISIBLE | MSS_VERTICAL;
    LoadString(ghInst, IDS_VERTICAL, pCtlInfo->Type[0].szDescr, CTLDESCR);

    //Set the types
    pCtlInfo->Type[1].wType  =0;
    pCtlInfo->Type[1].wWidth =21;
    pCtlInfo->Type[1].wHeight=12;
    pCtlInfo->Type[1].dwStyle=WS_CHILD | WS_VISIBLE | MSS_HORIZONTAL;
    LoadString(ghInst, IDS_HORIZONTAL, pCtlInfo->Type[1].szDescr, CTLDESCR);

    //Give the memory to the Dialog Editor.
    GlobalUnlock(hMem);
    return hMem;
    }




/*
 * WTranslateCtlFlags
 *
 * Purpose:
 *  Translates the class style flags into a text string to be used in the
 *  output of the Dialog Editor in a CONTROL statement of a dialog script
 *  (i.e. SS_ICON or BS_OWNERDRAW).  The same text as used in the
 *  incldue file should be used here.
 *
 *  Null-terminate the string for safety since we don't know what the
 *  Dialog Editor might do.
 *
 * Parameters:
 *  dwStyle     DWORD containing the style bits.
 *  psz         LPSTR pointer to string to receive the style text.
 *  cchMax      WORD maximum length of the string.
 *
 * Return Value:
 *  WORD        Number of characters filled in the buffer.  0 on an error.
 *
 */

WORD FAR PASCAL WTranslateCtlFlags(DWORD dwStyle, LPSTR psz, WORD cchMax)
    {
    WORD        cch=0;
    LPSTR       pszT;

    pszT=psz;

    //Use one of these two exclusive styles.
    if (dwStyle & MSS_HORIZONTAL)
        cch=LoadString(ghInst, IDS_MSS_HORIZONTAL, pszT, cchMax);
    else
        cch=LoadString(ghInst, IDS_MSS_VERTICAL, pszT, cchMax);

    //Adjust remaining number of characters we can store.
    cchMax-=cch;
    pszT+=cch;

    //Any of these stings can be concatenated.
    if (MSS_TEXTHASRANGE & dwStyle)
        {
        cch=LoadString(ghInst, IDS_MSS_TEXTHASRANGE, pszT, cchMax);
        pszT+=cch;
        cchMax-=cch;
        }

    if (MSS_NOPEGSCROLL & dwStyle)
        {
        cch=LoadString(ghInst, IDS_MSS_NOPEGSCROLL, pszT, cchMax);
        pszT+=cch;
        cchMax-=cch;
        }

    if (MSS_INVERTRANGE & dwStyle)
        {
        cch=LoadString(ghInst, IDS_MSS_INVERTRANGE, pszT, cchMax);
        pszT+=cch;
        cchMax-=cch;
        }

    /*
     * Chop off the string 2 characters from the end since we have an extra
     * '| 'there.
     */
    cch=lstrlen(psz)-2;
    *(psz+cch)=0;

    return cch;
    }




/*
 * FShowCtlStyleDlg
 *
 * Purcdctl.cpose:
 *  Requests the control library to display a dialog box that
 *  allows editing of the control's styles.  The fields in a SYTLE
 *  structure must be set according to what the window is and what
 *  it contains.
 *
 * Parameters:
 *  hWnd        HWND to the control.
 *  hMem        HANDLE to global memory of the STYLE structure.
 *  lpfnStrToId LPFNSTRTOID pointer to Dialog Editor function that
 *              returns the include file symbol for a given ID.
 *  lpfnIdToStr LPFNIDTOSTR pointer to Dialog Edit function that
 *              returns the ID of a given symbol.
 *
 * Return Value:
 *  BOOL        TRUE if the STYLE structure was changed, FALSE
 *              otherwise.
 */

BOOL FAR PASCAL FShowCtlStyleDlg(HWND hWnd, HANDLE hMem,
                                 LPFNSTRTOID lpfnStrToId,
                                 LPFNIDTOSTR lpfnIdToStr)
    {
    FARPROC     lpStyleDlgProc;
    BOOL        bReturn;

    //Save the vital information for the dialog.
    hStyleMem=hMem;
    lpStrToId=lpfnStrToId;
    lpIdToStr=lpfnIdToStr;

    //Show dialog box
    lpStyleDlgProc=MakeProcInstance((FARPROC)FCtlStyleDlgProc, ghInst);

    bReturn=DialogBox(ghInst, (LPCSTR)MAKEINTRESOURCE(IDD_STYLEDIALOG),
                      hWnd, (DLGPROC)lpStyleDlgProc);

    FreeProcInstance(lpStyleDlgProc);

    return bReturn;
    }





/*
 * FCtlStyleDlgProc
 *
 * Purpose:
 *  The dialog function for the dialog box displayed when the XXXXStyle
 *  function is called.  This is a normal dialog box proc in all respects.
 *
 * Parameters:
 *  standard
 *
 * Return Value:
 *  BOOL        Standard for a dialog box.
 */

BOOL FAR PASCAL FCtlStyleDlgProc(HWND hDlg, WORD wMessage, WORD wParam, LONG lParam)
    {
    LPCTLSTYLE      lpCtlStyle;
    char            szTemp[32];
    DWORD           dwID;
    WORD            wStyle;
    WORD            wWinStyle;

    switch (wMessage)
        {
        case WM_INITDIALOG:
            lpCtlStyle=(LPCTLSTYLE)GlobalLock(hStyleMem);

            if (lpCtlStyle==NULL)
                return FALSE;

            (*lpIdToStr)(lpCtlStyle->wId, (LPSTR)szTemp, 32);
            SetDlgItemText(hDlg, ID_IDEDIT, szTemp);
            SetDlgItemText(hDlg, ID_TEXTEDIT, lpCtlStyle->szTitle);

            wStyle=LOWORD(lpCtlStyle->dwStyle);

            //There's gotta be a better way to do this.
            if (wStyle & MSS_VERTICAL)
                CheckRadioButton(hDlg, ID_RADIOVERTICAL,
                                 ID_RADIOHORIZONTAL, ID_RADIOVERTICAL);

            if (wStyle & MSS_HORIZONTAL)
                CheckRadioButton(hDlg, ID_RADIOVERTICAL,
                                 ID_RADIOHORIZONTAL, ID_RADIOHORIZONTAL);

            if (wStyle & MSS_TEXTHASRANGE)
                CheckDlgButton(hDlg, ID_CHECKTEXTHASRANGE, 1);

            if (wStyle & MSS_NOPEGSCROLL)
                CheckDlgButton(hDlg, ID_CHECKNOPEGSCROLL, 1);

            if (wStyle & MSS_INVERTRANGE)
                CheckDlgButton(hDlg, ID_CHECKINVERTRANGE, 1);

            GlobalUnlock(hStyleMem);
            break;


        case WM_COMMAND:
            switch (wParam)
                {
                /*
                 * Check for valid range text in the Text field if the
                 * Text Has Range box is checked.
                 */

                case ID_CHECKTEXTHASRANGE:
                    if (HIWORD(lParam)==BN_CLICKED)
                        {
                        if (IsDlgButtonChecked(hDlg, wParam))
                            FRangePositionCheck(hDlg);
                        }
                    break;


                case IDOK:
                    //Verify the range text again.
                    if (IsDlgButtonChecked(hDlg, ID_CHECKTEXTHASRANGE))
                        {
                        if (!FRangePositionCheck(hDlg))
                            return TRUE;
                        }

                    //Make sure the identifier works.
                    GetDlgItemText(hDlg, ID_IDEDIT, szTemp, 32);
                    dwID=(*lpStrToId)(szTemp);


                    if (LOWORD(dwID))
                        {
                        lpCtlStyle=(LPCTLSTYLE)GlobalLock(hStyleMem);

                        if (lpCtlStyle!=NULL)
                            {
                            //Save the Style, ID, and text.
                            wStyle=WFormStyleFlags(hDlg);
                            wWinStyle=HIWORD(lpCtlStyle->dwStyle);
                            lpCtlStyle->dwStyle=MAKELONG(wStyle, wWinStyle);

                            lpCtlStyle->wId=HIWORD(dwID);
                            GetDlgItemText(hDlg, ID_TEXTEDIT, lpCtlStyle->szTitle, CTLTITLE);

                            GlobalUnlock(hStyleMem);
                            EndDialog(hDlg, TRUE);
                            }
                        else
                            EndDialog(hDlg, FALSE);
                        }

                    break;

                case IDCANCEL:
                    EndDialog(hDlg, FALSE);
                    break;

                default:
                    break;
                }
            break;

        default:
            return FALSE;
        }

    return TRUE;
    }







/*
 * WFormStyleFlags
 *
 * Purpose:
 *  Returns a WORD with flags set to whatever options are checked in
 *  the dialog box.  It is up to the implementer of the dialog box to
 *  code the exact bit fields in this function.
 *
 * Parameters:
 *  hDlg        HWND of the style dialog.
 *
 * Return Value:
 *  WORD        Style Flags value.
 */

WORD PASCAL WFormStyleFlags(HWND hDlg)
    {
    WORD    wStyle=0;

    if (IsDlgButtonChecked(hDlg, ID_RADIOVERTICAL))
        wStyle |= MSS_VERTICAL;
    else
        wStyle |= MSS_HORIZONTAL;

    if (IsDlgButtonChecked(hDlg, ID_CHECKTEXTHASRANGE))
        wStyle |= MSS_TEXTHASRANGE;

    if (IsDlgButtonChecked(hDlg, ID_CHECKNOPEGSCROLL))
        wStyle |= MSS_NOPEGSCROLL;

    if (IsDlgButtonChecked(hDlg, ID_CHECKINVERTRANGE))
        wStyle |= MSS_INVERTRANGE;

    return wStyle;
    }





/*
 * FRangePositionCheck
 *
 * Purpose:
 *  Checks if the control text contains a valid string and that
 *  the initial position is within the given range.
 *
 * Parameters:
 *  hDlg            HWND of the style dialog.
 *
 * Return Value:
 *  BOOL            TRUE if the text is valid, FALSE otherwise.
 *
 */

BOOL PASCAL FRangePositionCheck(HWND hDlg)
    {
    HWND        hEdit;
    char        szTemp1[60];
    char        szTemp2[60];
    BOOL        fTextOK;
    int         iMin;
    int         iMax;
    int         iPos;

    /*
     * We checked the MSS_TEXTHASRANGE box, so verify that there
     * is valid text in the Text edit control.  If not, just
     * cue the user with a beep and a SetFocus.
     */
    hEdit=GetDlgItem(hDlg, ID_TEXTEDIT);
    GetWindowText(hEdit, szTemp1, 60);

    fTextOK=FTextParse(szTemp1, &iMin, &iMax, &iPos);

    if (fTextOK && (iPos < iMin || iPos > iMax))
        {
        LoadString(ghInst, IDS_CLASSNAME,  szTemp1, 60);
        LoadString(ghInst, IDS_RANGEERROR, szTemp2, 60);

        MessageBox(hDlg, szTemp2, szTemp1, MB_OK | MB_ICONEXCLAMATION);
        SetFocus(hEdit);
        SendMessage(hEdit, EM_SETSEL, 0, MAKELONG(0, 32767));
        }

    if (!fTextOK)
        {
        MessageBeep(0);
        SetFocus(hEdit);
        SendMessage(hEdit, EM_SETSEL, 0, MAKELONG(0, 32767));
        }

    return fTextOK;
    }
