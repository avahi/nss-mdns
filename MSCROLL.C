/*
 * MUSCROLL.C
 *
 * Contains the main window procedure of the MicroScroll control
 * that handles mouse logic, and Windows messages.
 *
 * Version 1.1, October 1991, Kraig Brockschmidt
 */

#include <windows.h>
#include "mscrdll.h"

/*
 * MicroScrollWndProc
 *
 * Purpose:
 *  Window Procedure for the MicroScroll custom control.  Handles all
 *  messages like WM_PAINT just as a normal application window would.
 *  Any message not processed here should go to DefWindowProc.
 *
 * Parameters:
 *  hWnd            HWND handle to the control window.
 *  iMsg            WORD message identifier.
 *  wParam          WORD parameter of the message.
 *  lParam          LONG parameter of the message.
 *
 * Return Value:
 *  LONG            Varies with the message.
 *
 */

LONG FAR PASCAL MMMScrollWndProc(HWND hWnd, UINT iMsg,
				   WPARAM wParam, LPARAM lParam)
    {
    PMUSCROLL       pMS;
    POINT           pt;
    RECT            rect;
    UINT            x, y;
    UINT            cx, cy;
    WORD            wState;


    /*
     * Get a pointer to the MUSCROLL structure for this control.
     * Note that if we do this before WM_NCCREATE where we allocate
     * the memory, pMS will be NULL, which is not a problem since
     * we do not access it until after WM_NCCREATE.
     */
#ifdef _WIN32
    pMS=(PMUSCROLL)GetWindowLong(hWnd, GWL_MUSCROLLHMEM);
#else
    pMS=(PMUSCROLL)GetWindowWord(hWnd, GWW_MUSCROLLHMEM);
#endif

    //Let the API handler process WM_USER+xxxx messages
    if (iMsg >= WM_USER)
        return LMicroScrollAPI(hWnd, iMsg, wParam, lParam, pMS);


    //Handle standard Windows messages.
    switch (iMsg)
        {
        case WM_NCCREATE:
        case WM_CREATE:
            return LMicroScrollCreate(hWnd, iMsg, pMS, (LPCREATESTRUCT)lParam);

        case WM_NCDESTROY:
            //Free the control's memory.
            LocalFree((HANDLE)pMS);
            break;

        case WM_ERASEBKGND:
            /*
             * Eat this message to avoid erasing portions that
             * we are going to repaint in WM_PAINT.  Part of a
             * change-state-and-repaint strategy is to rely on
             * WM_PAINT to do anything visual, which includes
             * erasing invalid portions.  Letting WM_ERASEBKGND
             * erase the background is redundant.
             */
            break;


        case WM_PAINT:
            return LMicroScrollPaint(hWnd, pMS);


        case WM_ENABLE:
            /*
             * Handles disabling/enabling case.  Example of a
             * change-state-and-repaint strategy since we let the
             * painting code take care of the visuals.
             */
            if (wParam)
                StateClear(pMS, MUSTATE_GRAYED);
            else
                StateSet(pMS, MUSTATE_GRAYED);

            //Force a repaint since the control will look different.
            InvalidateRect(hWnd, NULL, TRUE);
            UpdateWindow(hWnd);
            break;


        case WM_SHOWWINDOW:
            /*
             * Set or clear the hidden flag. Windows will
             * automatically force a repaint if we become visible.
             */
            if (wParam)
                StateClear(pMS, MUSTATE_HIDDEN);
            else
                StateSet(pMS, MUSTATE_HIDDEN);

            break;


        case WM_CANCELMODE:
            /*
             * IMPORTANT MESSAGE!  WM_CANCELMODE means that a
             * dialog or some other modal process has started.
             * we must make sure that we cancel any clicked state
             * we are in, kill the timers, and release the capture.
             */
            StateClear(pMS, MUSTATE_DOWNCLICK | MUSTATE_UPCLICK);
            KillTimer(hWnd, IDT_FIRSTCLICK);
            KillTimer(hWnd, IDT_HOLDCLICK);
            ReleaseCapture();
            break;


        case WM_TIMER:
            /*
             * We run two timers:  the first is the initial delay
             * after the first click before we begin repeating, the
             * second is the repeat rate.
             */
            if (wParam==IDT_FIRSTCLICK)
                {
                KillTimer(hWnd, wParam);
                SetTimer(hWnd, IDT_HOLDCLICK, CTICKS_HOLDCLICK, NULL);
                }

            /*
             * Send a new scroll message if the mouse is still in the
             * originally clicked area.
             */
            if (!StateTest(pMS, MUSTATE_MOUSEOUT))
                PositionChange(hWnd, pMS);

            break;


        case WM_LBUTTONDBLCLK:
        case WM_LBUTTONDOWN:
            /*
             * When we get a mouse down message, we know that the mouse
             * is over the control.  We then do the following steps
             * to set up the new state:
             *  1.  Hit-test the coordinates of the click to
             *      determine in which half the click occurred.
             *  2.  Set the appropriate MUSTATE_*CLICK state
             *      and repaint that clicked half.  This is another
             *      example of a change-state-and-repaint strategy.
             *  3.  Send an initial scroll message.
             *  4.  Set the mouse capture.
             *  5.  Set the initial delay timer before repeating
             *      the scroll message.
             *
             * A WM_LBUTTONDBLCLK message means that the user clicked
             * the control twice in succession which we want to treat
             * like WM_LBUTTONDOWN.  This is safe since we will receive
             * WM_LBUTTONUP before the WM_LBUTTONDBLCLK.
             */

            //Get the mouse coordinates.
            x=LOWORD(lParam);
            y=HIWORD(lParam);


            /*
             * Only need to hit-test the upper half for a vertical
             * control or the left half for a horizontal control.
             */
            GetClientRect(hWnd, &rect);
            cx=rect.right  >> 1;
            cy=rect.bottom >> 1;

            if (MSS_VERTICAL & pMS->dwStyle)
                wState=(y > cy) ? MUSTATE_DOWNCLICK : MUSTATE_UPCLICK;
            else
                wState=(x > cx) ? MUSTATE_RIGHTCLICK : MUSTATE_LEFTCLICK;

            //Change-state-and-repaint
            StateSet(pMS, wState);
            ClickedRectCalc(hWnd, pMS, &rect);
            InvalidateRect(hWnd, &rect, TRUE);
            UpdateWindow(hWnd);

            PositionChange(hWnd, pMS);
            SetCapture(hWnd);
            SetTimer(hWnd, IDT_FIRSTCLICK, CTICKS_FIRSTCLICK, NULL);
            break;


        case WM_MOUSEMOVE:
            /*
             * On WM_MOUSEMOVE messages we want to know if the mouse
             * has moved out of the control when the control is in
             * a clicked state.  If the control has not been clicked,
             * then we have nothing to do.  Otherwise we want to set
             * the MUSTATE_MOUSEOUT flag and repaint so the button
             * visually comes up.
             */
            if (!StateTest(pMS, MUSTATE_CLICKED))
                break;


            //Get the area we originally clicked and the new POINT
            ClickedRectCalc(hWnd, pMS, &rect);
#ifdef _WIN32
				pt.x = (LONG)LOWORD(lParam);  // horizontal position of cursor 
            pt.y = (LONG)HIWORD(lParam);  // vertical position of cursor 
#else
            pt=MAKEPOINT(lParam);
#endif
            wState=pMS->wState;

            //Hit-Test the rectange and change the state if necessary.
            if (PtInRect(&rect, pt))
                StateClear(pMS, MUSTATE_MOUSEOUT);
            else
                StateSet(pMS, MUSTATE_MOUSEOUT);

            /*
             * If the state changed, repaint the appropriate part of
             * the control.
             */
            if (wState!=pMS->wState)
                {
                InvalidateRect(hWnd, &rect, TRUE);
                UpdateWindow(hWnd);
                }

            break;


        case WM_LBUTTONUP:
            /*
             * A mouse button up event is much like WM_CANCELMODE since
             * we have to clean out whatever state the control is in:
             *  1.  Kill any repeat timers we might have created.
             *  2.  Release the mouse capture.
             *  3.  Clear the clicked states and repaint, another example
             *      of a change-state-and-repaint strategy.
             */
            KillTimer(hWnd, IDT_FIRSTCLICK);
            KillTimer(hWnd, IDT_HOLDCLICK);

            ReleaseCapture();



            /*
             * Repaint if necessary, only if we are clicked AND the mouse
             * is still in the boundaries of the control.
             */
            if (StateTest(pMS, MUSTATE_CLICKED) &&
                StateTest(pMS, ~MUSTATE_MOUSEOUT))
                {
                //Calculate the rectangle before clearing states.
                ClickedRectCalc(hWnd, pMS, &rect);

                //Clear the states so we repaint properly.
                StateClear(pMS, MUSTATE_MOUSEOUT);
                StateClear(pMS, MUSTATE_CLICKED);


                InvalidateRect(hWnd, &rect, TRUE);
                UpdateWindow(hWnd);
                }

            //Insure that we clear out the states.
            break;


        default:
            return DefWindowProc(hWnd, iMsg, wParam, lParam);
        }

    return 0L;
    }






/*
 * ClickedRectCalc
 *
 * Purpose:
 *  Calculates the rectangle of the clicked region based on the
 *  state flags MUSTATE_UPCLICK, MUSTATE_DOWNCLICK, MUSTATE_LEFTCLICK,
 *  and MUSTATE_RIGHTLICK, depending on the style.
 *
 * Parameter:
 *  hWnd            HWND handle to the control window.
 *  lpRect          LPRECT rectangle structure to fill.
 *
 * Return Value:
 *  void
 *
 */

void FAR PASCAL ClickedRectCalc(HWND hWnd, PMUSCROLL pMS, LPRECT lpRect)
    {
    UINT       cx, cy;

    GetClientRect(hWnd, lpRect);
    cx=lpRect->right  >> 1;
    cy=lpRect->bottom >> 1;

    if (MSS_VERTICAL & pMS->dwStyle)
        {
        if (StateTest(pMS, MUSTATE_DOWNCLICK))
            lpRect->top=cy;

        if (StateTest(pMS, MUSTATE_UPCLICK))
            lpRect->bottom=1+cy;
        }
    else
        {
        //MSS_HORIZONTAL
        if (StateTest(pMS, MUSTATE_RIGHTCLICK))
            lpRect->left=cx;

        if (StateTest(pMS, MUSTATE_LEFTCLICK))
            lpRect->right=1+cx;
        }

    return;
    }





/*
 * PositionChange
 *
 * Purpose:
 *  Checks what part of the control is clicked, modifies the current
 *  position accordingly (taking MSS_INVERTRANGE into account) and
 *  sends an appropriate message to the associate.  For MSS_VERTICAL
 *  controls we send WM_VSCROLL messages and for MSS_HORIZONTAL controls
 *  we send WM_HSCROLL.
 *
 *  The scroll code in the message is always SB_LINEUP for the upper
 *  or left half of the control (vertical and horizontal, respectively)
 *  and SB_LINEDOWN for the bottom or right half.
 *
 *  This function does not send a message if the position is pegged
 *  on the minimum or maximum of the range if MSS_NOPEGSCROLL is
 *  set in the style bits.
 *
 * Parameters:
 *  hWnd            HWND of the control.
 *  pMS             PMUSCROLL pointer to control data structure.
 *
 * Return Value:
 *  void
 */

void FAR PASCAL PositionChange(HWND hWnd, PMUSCROLL pMS)
    {
    WORD         wScrollMsg;
    WORD         wScrollCode;
    BOOL         fPegged=FALSE;

    if (StateTest(pMS, MUSTATE_UPCLICK | MUSTATE_LEFTCLICK))
        wScrollCode=SB_LINEUP;

    if (StateTest(pMS, MUSTATE_DOWNCLICK | MUSTATE_RIGHTCLICK))
        wScrollCode=SB_LINEDOWN;

    wScrollMsg=(MSS_VERTICAL & pMS->dwStyle) ? WM_VSCROLL : WM_HSCROLL;

    /*
     * Modify the current position according to the following rules:
     *
     * 1. On SB_LINEUP with an inverted range, increment the position.
     *    If the position is already at the maximum, set the pegged flag.
     *
     * 2. On SB_LINEUP with an normal range, decrement the position.
     *    If the position is already at the minimum, set the pegged flag.
     *
     * 3. On SB_LINEDOWN with an inverted range, treat like SB_LINEUP
     *    with a normal range.
     *
     * 4. On SB_LINEDOWN with an normal range, treat like SB_LINEUP
     *    with an inverted range.
     */

    if (wScrollCode==SB_LINEUP)
        {
        if (MSS_INVERTRANGE & pMS->dwStyle)
            {
            if (pMS->iPos==pMS->iMax)
                fPegged=TRUE;
            else
                pMS->iPos++;
            }
        else
            {
            if (pMS->iPos==pMS->iMin)
                fPegged=TRUE;
            else
                pMS->iPos--;
            }
        }
    else
        {
        if (MSS_INVERTRANGE & pMS->dwStyle)
            {
            if (pMS->iPos==pMS->iMin)
                fPegged=TRUE;
            else
                pMS->iPos--;
            }
        else
            {
            if (pMS->iPos==pMS->iMax)
                fPegged=TRUE;
            else
                pMS->iPos++;
            }
        }


    /*
     * Send a message if we changed and are not pegged, or did not change
     * and MSS_NOPEGSCROLL is clear.
     */
    if (!fPegged || !(MSS_NOPEGSCROLL & pMS->dwStyle))
        {
        SendMessage(pMS->hWndAssociate, wScrollMsg,
                    wScrollCode, MAKELONG(pMS->iPos, hWnd));
        }

    return;
    }
