/*
 * MSAPI.C
 *
 * Contains the API implementation of the MicroScroll custom
 * control, including functional messages and function message
 * equivalents.
 *
 * Version 1.1, October 1991, Kraig Brockschmidt
 */


#include <windows.h>
#include "mscrdll.h"


/*
 * LMicroScrollAPI
 *
 * Purpose:
 *  Processes any control-specific function messages for the
 *  MicroScroll control.
 *
 * Parameters:
 *  hWnd            HWND handle to the control window.
 *  iMsg            WORD message identifier.
 *  wParam          WORD parameter of the message.
 *  lParam          LONG parameter of the message.
 *  pMS             PMUSCROLL pointer to control-specific data.
 *
 * Return Value:
 *  LONG            Varies with the message.
 *
 */



LONG FAR PASCAL LMicroScrollAPI(HWND hWnd, UINT iMsg, WPARAM wParam,
                            LPARAM lParam, PMUSCROLL pMS)
    {
    DWORD           dwT;
    COLORREF        cr;
    HWND            hWndT;
    WORD            iMin, iMax;
    WORD            iPos;
    WORD            wID;

    switch (iMsg)
        {
        case MSM_HWNDASSOCIATESET:
            //Change the associate window of this control.
            if (!IsWindow((HWND)wParam))
                return -1;

            //Save old window handle.
            hWndT=pMS->hWndAssociate;

            //Get our ID value, then send WM_COMMAND notifications.
#ifdef _WIN32
            wID=(WORD)GetWindowLong(hWnd, GWL_ID);
#else
            wID=GetWindowWord(hWnd, GWW_ID);
#endif
            SendMessage(hWndT, WM_COMMAND, wID,
                        MAKELONG(hWnd, MSN_ASSOCIATELOSS));

            pMS->hWndAssociate=(HWND)wParam;

            SendMessage(pMS->hWndAssociate, WM_COMMAND, wID,
                        MAKELONG(hWnd, MSN_ASSOCIATEGAIN));

            return MAKELONG(hWndT, 0);


        case MSM_HWNDASSOCIATEGET:
            return MAKELONG(pMS->hWndAssociate, 0);


        case MSM_DWRANGESET:
            /*
             * Set the new range, sending the appropriate notifications.
             * Also send a scroll message if the position has to change.
             * If the minimum is greater than the max, return error.
             */
            if ((short)LOWORD(lParam) >= (short)HIWORD(lParam))
                return -1L;

#ifdef _WIN32
            wID=(WORD)GetWindowLong(hWnd, GWL_ID);
#else
            wID=GetWindowWord(hWnd, GWW_ID);
#endif

            SendMessage(pMS->hWndAssociate, WM_COMMAND, wID,
                        MAKELONG(hWnd, MSN_RANGECHANGE));

            //Save old values.
            iMin=pMS->iMin;
            iMax=pMS->iMax;

            pMS->iMin=(short)LOWORD(lParam);
            pMS->iMax=(short)HIWORD(lParam);

            /*
             * If current position is outside of new range, force it to
             * the average of the range, otherwise leave it be.
             */
            if ((pMS->iMin >= pMS->iPos) ||
                (pMS->iMax <= pMS->iPos))
                {
                pMS->iPos=(pMS->iMin + pMS->iMax)/2;

                //Send a scroll message if we change position.
                iMsg=(MSS_VERTICAL & pMS->dwStyle) ? WM_VSCROLL : WM_HSCROLL;
                wParam=SB_THUMBTRACK;
                lParam=MAKELONG(pMS->iPos, 0);

                SendMessage(pMS->hWndAssociate, iMsg, wParam, lParam);
                }

            //Return old range.
            return MAKELONG(iMin, iMax);

        case MSM_DWRANGEGET:
            return MAKELONG(pMS->iMin, pMS->iMax);


        case MSM_WCURRENTPOSSET:
            /*
             * Set the new position if it falls within the valid range,
             * sending the appropriate scroll message.
             */

            //Save current position
            iPos=pMS->iPos;

            if ((pMS->iMin <= (short)wParam) && (pMS->iMax >= (short)wParam))
                {
                pMS->iPos=(short)wParam;
                iMsg=(MSS_VERTICAL & pMS->dwStyle) ? WM_VSCROLL : WM_HSCROLL;
                wParam=SB_THUMBTRACK;
                lParam=MAKELONG(pMS->iPos, 0);

                SendMessage(pMS->hWndAssociate, iMsg, wParam, lParam);

                //Return old position.
                return MAKELONG(iPos, 0);
                }

            //Invalid position.
            return -1;

        case MSM_WCURRENTPOSGET:
            return MAKELONG(pMS->iPos, 0);


        case MSM_FNOPEGSCROLLSET:
            /*
             * Set the MSS_NOPEGSCROLL style to the value in
             * lParam which is zero or MSS_NOPEGSCROLL.
             */
            dwT=pMS->dwStyle & MSS_NOPEGSCROLL;

            //Either set of clear the style.
            if ((BOOL)wParam)
                pMS->dwStyle |= MSS_NOPEGSCROLL;
            else
                pMS->dwStyle &= ~MSS_NOPEGSCROLL;

            //Return TRUE or FALSE if the bit was or wasn't set
            return (dwT ? 1L : 0L);

        case MSM_FNOPEGSCROLLGET:
            return (pMS->dwStyle & MSS_NOPEGSCROLL);


        case MSM_FINVERTRANGESET:
            /*
             * Set the MSS_INVERTRANGE style to the value in
             * lParam which is zero or MSS_INVERTRANGE.
             */
            dwT=pMS->dwStyle & MSS_INVERTRANGE;

            //Either set of clear the style.
            if ((BOOL)wParam)
                pMS->dwStyle |= MSS_INVERTRANGE;
            else
                pMS->dwStyle &= ~MSS_INVERTRANGE;

            //Return TRUE or FALSE if the bit was or wasn't set
            return (dwT ? 1L : 0L);


        case MSM_FINVERTRANGEGET:
            return (pMS->dwStyle & MSS_INVERTRANGE);


        case MSM_CRCOLORSET:
            if (wParam >= CCOLORS)
                return 0L;

            cr=pMS->rgCr[wParam];

            //If -1 is set in rgCr the paint procedure uses a default.
            pMS->rgCr[wParam]=(COLORREF)lParam;

            //Force repaint since we changed a state.
            InvalidateRect(hWnd, NULL, TRUE);
            UpdateWindow(hWnd);

            //Return the old color.
            return (LONG)cr;

        case MSM_CRCOLORGET:
            if (wParam >= CCOLORS)
                return 0L;

            return (LONG)pMS->rgCr[wParam];
        }
    return 0L;
    }




/*
 * Message API Functions
 *
 * The advantage of using a function instead of SendMessage is that
 * you get type checking on the parameters and the return value.'
 *
 * Header comments are provided on these functions in pairs.  All
 * functions take hWnd (control handle), and the Set functions
 * usually take an extra paarameter containing the new value.
 *
 */


/*
 * MSHwndAssociateSet
 * MSHwndAssociateGet
 *
 * Purpose:
 *  Change or retrieve the associate window of the control.
 *
 * Parameters:
 *  hWnd            HWND of the control window.
 *
 * Set Parameters:
 *  hWndAssociate   HWND of new associate.
 *
 * Return Value:
 *  HWND            Handle of previous associate (set) or current
 *                  associate (set).
 */

HWND FAR PASCAL MSHwndAssociateSet(HWND hWnd, HWND hWndAssociate)
    {
    return (HWND)SendMessage(hWnd, MSM_HWNDASSOCIATESET,
                             (WORD)hWndAssociate, 0L);
    }

HWND FAR PASCAL MSHwndAssociateGet(HWND hWnd)
    {
    return (HWND)SendMessage(hWnd, MSM_HWNDASSOCIATEGET, 0, 0L);
    }


/*
 * MSRangeSet
 * MSRangeGet
 *
 * Purpose:
 *  Change or retrieve the range of the control.
 *
 * Parameters:
 *  hWnd            HWND of the control window.
 *
 * Set Parameters:
 *  iMin            WORD new minimum of the range.
 *  iMax            WORD new maximum of the range.
 *
 * Return Value:
 *  DWORD           Low-order word contains the previous (set) or
 *                  current (get) minimum, high-order word contains
 *                  the previous or current maximum.
 */

DWORD FAR PASCAL MSDwRangeSet(HWND hWnd, WORD iMin, WORD iMax)
    {
    return (DWORD)SendMessage(hWnd, MSM_DWRANGESET, 0, MAKELONG(iMin, iMax));
    }

DWORD FAR PASCAL MSDwRangeGet(HWND hWnd)
    {
    return (DWORD)SendMessage(hWnd, MSM_DWRANGEGET, 0, 0L);
    }


/*
 * MSWCurrentPosSet
 * MSWCurrentPosGet
 *
 * Purpose:
 *  Change or retrieve the current position of the control.
 *
 * Parameters:
 *  hWnd            HWND of the control window.
 *
 * Set Parameters:
 *  iPos            WORD new position to set.
 *
 * Return Value:
 *  WORD            Previous (set) or current (get) position.
 *
 */

WORD FAR PASCAL MSWCurrentPosSet(HWND hWnd, WORD iPos)
    {
    return (WORD)SendMessage(hWnd, MSM_WCURRENTPOSSET, iPos, 0L);
    }

WORD FAR PASCAL MSWCurrentPosGet(HWND hWnd)
    {
    return (WORD)SendMessage(hWnd, MSM_WCURRENTPOSGET, 0, 0L);
    }




/*
 * MSFNoPegScrollSet
 * MSFNoPegScrollGet
 *
 * Purpose:
 *  Change or retrieve the state of the MSS_NOPEGSCROLL style bit.
 *
 * Parameters:
 *  hWnd            HWND of the control window.
 *
 * Set Parameters:
 *  fNoPegScroll    BOOL flag to set (TRUE) or clear (FALSE) the style.
 *
 * Return Value:
 *  BOOL            Previous (set) or current (get) state of this
 *                  style bit, either TRUE for on, FALSE for off.
 */

BOOL FAR PASCAL MSFNoPegScrollSet(HWND hWnd, BOOL fNoPegScroll)
    {
    return (BOOL)SendMessage(hWnd, MSM_FNOPEGSCROLLSET, fNoPegScroll, 0L);
    }

BOOL FAR PASCAL MSFNoPegScrollGet(HWND hWnd)
    {
    return (BOOL)SendMessage(hWnd, MSM_FNOPEGSCROLLGET, 0, 0L);
    }



/*
 * MSFInvertRangeSet
 * MSFInvertRangeGet
 *
 * Purpose:
 *  Change or retrieve the state of the MSS_INVERTRANGE style bit.
 *
 * Parameters:
 *  hWnd            HWND of the control window.
 *
 * Set Parameters:
 *  fInvertRange    BOOL flag to set (TRUE) or clear (FALSE) the style.
 *
 * Return Value:
 *  BOOL            Previous (set) or current (get) state of this
 *                  style bit, either TRUE for on, FALSE for off.
 */

BOOL FAR PASCAL MSFInvertRangeSet(HWND hWnd, BOOL fInvertRange)
    {
    return (BOOL)SendMessage(hWnd, MSM_FINVERTRANGESET, fInvertRange, 0L);
    }

BOOL FAR PASCAL MSFInvertRangeGet(HWND hWnd)
    {
    return (BOOL)SendMessage(hWnd, MSM_FINVERTRANGEGET, 0, 0L);
    }



/*
 * MSCrColorSet
 * MSCrColorGet
 *
 * Purpose:
 *  Change or retrieve a configurable color.
 *
 * Parameters:
 *  hWnd            HWND of the control window.
 *  iColor          WORD index to the control to modify or retrieve.
 *
 * Set Parameters:
 *  cr              COLORREF new value of the color.
 *
 * Return Value:
 *  COLORREF        Previous (set) or current (get) color value.
 *
 */

COLORREF FAR PASCAL MSCrColorSet(HWND hWnd, WORD iColor, COLORREF cr)
    {
    return (BOOL)SendMessage(hWnd, MSM_CRCOLORSET, iColor, (LONG)cr);
    }

COLORREF FAR PASCAL MSCrColorGet(HWND hWnd, WORD iColor)
    {
    return (COLORREF)SendMessage(hWnd, MSM_CRCOLORGET, iColor, 0L);
    }
