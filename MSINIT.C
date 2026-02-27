/*
 * INIT.C
 *
 * LibMain entry point and initialization code for the MicroScroll
 * custom control DLL that is likely to be used once or very
 * infrequently.
 *
 * Version 1.1, October 1991, Kraig Brockschmidt
 */


#include <windows.h>
#include "mscrdll.h"


/*
 * MMRegisterControl
 *
 * Purpose:
 *  Registers the MicroScroll control class, including CS_GLOBALCLASS
 *  to make the control available to all applications in the system.
 *
 * Parameters:
 *  hInstance       HANDLE Instance of the application or DLL that will
 *                  own this class.
 *
 * Return Value:
 *  BOOL            TRUE if the class is registered, FALSE otherwise.
 *                  TRUE is also returned if the class was already
 *                  registered.
 */


BOOL FAR PASCAL MMRegisterControl(HINSTANCE hInstance)
    {
    static BOOL     fRegistered=FALSE;
    WNDCLASS        wc;

    if (!fRegistered)
        {
        wc.lpfnWndProc   = MMMScrollWndProc;
        wc.cbClsExtra    = CBCLASSEXTRA;
        wc.cbWndExtra    = CBWINDOWEXTRA;
        wc.hInstance     = hInstance;
        wc.hIcon         = NULL;
        wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE+1);
        wc.lpszMenuName  = NULL;
        wc.lpszClassName = MMSCROLLNAME;
        wc.style         = CS_DBLCLKS | CS_VREDRAW | CS_HREDRAW | W16CS_GLOBALCLASS; 

        fRegistered=RegisterClass(&wc);
        }

    return fRegistered;
    }



/*
 * LMicroScrollCreate
 *
 * Purpose:
 *  Handles both WM_NCCREATE and WM_CREATE messages:
 *    WM_NCCREATE:  Allocate control MUSCROLL structure.  Any sort
 *                  of initialization that should force the create
 *                  to fail should be included in this case.
 *
 *    WM_CREATE:    Fill the MUSCROLL structure; parse the text
 *                  for initial min, max, and position for the
 *                  MSS_TEXTHASRANGE style; clear all states;
 *                  set the expansion handle to NULL.
 *
 * Parameters:
 *  hWnd            HWND handle to the control window.
 *  iMsg            WORD message, either WM_NCCREATE or WM_CREATE.
 *  pMS             PMUSCROLL pointer to existing MUSCROLL structure.
 *
 * Return Value:
 *  LONG            0L if memory could not be allocated on WM_NCCREATE.
 *                  1L in all other cases.
 */

LONG FAR PASCAL LMicroScrollCreate(HWND hWnd, UINT iMsg, PMUSCROLL pMS,
                               LPCREATESTRUCT lpCreate)
    {
    HLOCAL          hMem;
    BOOL            fTextRange;
    int             iMin, iMax, iPos;


    if (WM_NCCREATE==iMsg)
        {
        /*
         * Allocate extra FIXED memory for the control's MUSCROLL
         * structure and store that handle in the minimal window
         * extra bytes allocated for the control.
         *
         * Note that LPTR includes LMEM_ZEROINIT, so all fields are
         * initially zero.
         */
        
        hMem=LocalAlloc(LPTR, CBMUSCROLL);

        if (NULL==hMem)
            return 0L;

#ifdef _WIN32
        SetWindowLong(hWnd, GWL_MUSCROLLHMEM, (LONG)hMem);
#else
        SetWindowWord(hWnd, GWW_MUSCROLLHMEM, (WORD)hMem);
#endif
        }

    if (WM_CREATE==iMsg)
        {
        //Our associate is the parent by default.
#ifdef _WIN32
        pMS->hWndAssociate=(HWND)GetWindowLong(hWnd, GWL_HWNDPARENT);
#else
        pMS->hWndAssociate=(HWND)GetWindowWord(hWnd, GWW_HWNDPARENT);
#endif

        //Copy styles
        pMS->dwStyle  =lpCreate->style;

        /*
         * Enforce exclusive MSS_VERTICAL and MSS_HORIZONTAL,
         * defaulting to MSS_VERTICAL.
         */
        if ((MSS_VERTICAL & pMS->dwStyle) && (MSS_HORIZONTAL & pMS->dwStyle))
            pMS->dwStyle &= ~MSS_HORIZONTAL;

        //Either parse the text or use defaults for initial range.
        fTextRange=FALSE;

        if (MSS_TEXTHASRANGE & pMS->dwStyle)
            {
            fTextRange=FTextParse((LPSTR)lpCreate->lpszName,
                                  &iMin, &iMax, &iPos);

            /*
             * Verify that the position is in the given range.  If
             * the position is outside the range, force it to the
             * middle.
             */
            if (fTextRange)
                {
                if (iPos < iMin || iPos > iMax)
                    iPos=(iMin + iMax) >> 1;
                }
            }



        /*
         * Use defaults if we never had MSS_TEXTHASRANGE or
         * FTextParse failed.
         */
        pMS->iMin=(fTextRange ? iMin : IDEFAULTMIN);
        pMS->iMax=(fTextRange ? iMax : IDEFAULTMAX);
        pMS->iPos=(fTextRange ? iPos : IDEFAULTPOS);

        //Clear out all initial states.
        StateClear(pMS, MUSTATE_ALL);

        //Indicate that all colors are defaults.
        for (iMin=0; iMin < CCOLORS; iMin++)
            pMS->rgCr[iMin]=(COLORREF)-1L;
        }

    return 1L;
    }



/*
 * FTextParse
 *
 * Purpose:
 *  Parses window text for a valid range and initial position.
 *  This function is used when creating the control or setting the
 *  window text to set the initial range and position but is also
 *  used to validate text entered in the Style dialog in the Dialog
 *  Editor interface if the MSM_TEXTHASRANGE style is selected.
 *
 *  The range and position must all be valid for any change to
 *  occur in piMin, piMax, and piPos.
 *
 * Parameters:
 *  psz             LPSTR pointer to the window text to parse out
 *                  the range and the position.
 *  piMin           LPINT pointer to location to store minimum.
 *  piMax           LPINT pointer to location to store maximum.
 *  piPos           LPINT pointer to location to store position.
 *
 * Return Value:
 *  BOOL            TRUE if the function successfully initializes
 *                  the range and position. FALSE if any part of
 *                  the text is not a valid number between comma
 *                  delimeters.
 */

BOOL FAR PASCAL FTextParse(LPSTR psz, LPINT piMin, LPINT piMax, LPINT piPos)
    {
    int          iMin;
    int          iMax;
    int          iCur;

    if (psz==NULL)
        return FALSE;

    /*
     * Parse off the bottom of the range.  Note that we depend
     * on WTranslateUpToChar to modify psz to point to the character
     * after the delimeter which is why we pass &psz.
     */
    iMin=WTranslateUpToChar(&psz, ',');

    //Check for valid value AND that there's text remaining.
    if (-1==iMin || 0==*psz)
        return FALSE;

    //Parse off the top of the range.
    iMax=WTranslateUpToChar(&psz, ',');

    //Check for valid value AND that there's text remaining.
    if (-1==iMax || 0==*psz)
        return FALSE;

    //Parse off the position and validate it.
    iCur=WTranslateUpToChar(&psz, ',');

    if (-1==iCur)
        return FALSE;

    //Store the parsed values in the return locations.
    *piMin=iMin;
    *piMax=iMax;
    *piPos=iCur;

    return TRUE;
    }

/*
 * WTranslateUpToChar
 *
 * Purpose:
 *  Scans a string for digits, converting the series of digits to
 *  an integer value as the digits are scanned.  Scanning stops
 *  at chDelimeter or the end of the string.
 *
 *  If the scan sees a non-digit character, -1 is returned to indicate
 *  error.  If the scan sees a null-terminator before any text, we
 *  return 0.
 *
 * Parameters:
 *  ppsz            LPSTR * pointer to pointer to the string to scan.
 *                  On return, the pointer will point to the character
 *                  after the delimeter OR the NULL terminator.
 *
 *                  We want a pointer to the pointer so we can modify
 *                  that pointer for the calling function since we are
 *                  using the return value for the parsed value
 *
 *  chDelimiter     char delimeter at which the scanning stops.
 *
 * Return Value:
 *  WORD            -1 if the string contains non-digits excluding
 *                  the comma.  Otherwise the converted value is
 *                  returned and the pointer to the address after
 *                  the comma is stored at ppsz.
 */

WORD FAR PASCAL WTranslateUpToChar(LPSTR FAR *ppsz, char chDelimeter)
    {
    WORD    wRet=0;
    char    ch;
    LPSTR   psz;

    psz=*ppsz;

    //Fail if there's no more string to parse.
    if (0==*psz)
	return ((WORD)-1);

    //Scan string, stopping at 0 or chDelimeter
    while (ch=*psz)
        {
        if (ch==chDelimeter)
            {
            psz++;  //Skip delimeter
            break;
            }

        //Check for digits, returning -1 on a non-digit.
        ch-='0';

        if (ch < 0 || ch > 9)
	    return ((WORD)-1);

        //Add up the value as we scan.
        wRet=(wRet*10) + (WORD)ch;

        /*
         * We increment psz here so if we hit a null-terminator
         * psz is always valid.  If we incremented in the while
         * statement then psz might be past the null-terminator
         * and possibly invalid.
         */
        psz++;
        }

    /*
     * Store the new pointer and the value.  Note that the *psz++
     * already incremented psz past the delimeter AND the zero.
     */
    *ppsz=psz;
    return wRet;
    }
