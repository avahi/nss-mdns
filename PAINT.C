/*
 * PAINT.C
 *
 * Contains any code related to MicroScroll visuals, primarily
 * the WM_PAINT handler.
 *
 * Version 1.1, October 1991, Kraig Brockschmidt
 */


#include "windows.h"
#include "mscrdll.h"

//Array of default colors, matching the order of MSCOLOR_* values.
static const int rgColorDef[CCOLORS]={
                         COLOR_BTNFACE,
                         COLOR_BTNTEXT,
                         COLOR_BTNSHADOW,
                         -1,
                         COLOR_WINDOWFRAME
                         };
static const int rgNone = -1;

/*
 * LMicroScrollPaint
 *
 * Purpose:
 *  Handles all WM_PAINT messages for the control and paints
 *  the control for the current state, whether it be clicked
 *  or disabled.
 *
 *  PLEASE NOTE!
 *  This painting routine makes no attempt at optimizations
 *  and is intended for demonstration and education.
 *
 * Parameters:
 *  hWnd            HWND Handle to the control.
 *  pMS             PMUSCROLL control data pointer.
 *
 * Return Value:
 *  LONG            0L.
 */

LONG FAR PASCAL LMicroScrollPaint(HWND hWnd, PMUSCROLL pMS)
    {
    PAINTSTRUCT ps;
    LPRECT      lpRect;
    RECT        rect;
    HDC         hDC;
    COLORREF    rgCr[CCOLORS];
    HPEN        rgHPen[CCOLORS];
    WORD        iColor;

    HBRUSH      hBrushArrow;
    HBRUSH      hBrushFace;
    HBRUSH      hBrushBlack;

    POINT       rgpt1[3];
    POINT       rgpt2[3];

    WORD        xAdd1=0, yAdd1=0;
    WORD        xAdd2=0, yAdd2=0;

    WORD        cx,  cy;    //Whole dimensions
    WORD        cx2, cy2;   //Half dimensions
    WORD        cx4, cy4;   //Quarter dimensions

#ifdef _WIN32
    POINT       pt;
#endif

    lpRect=&rect;

    hDC=BeginPaint(hWnd, &ps);
    GetClientRect(hWnd, lpRect);

    /*
     * Get colors that we'll need.  We do not want to cache these
     * items since we may our top-level parent window may have
     * received a WM_WININICHANGE message at which time the control
     * is repainted.  Since this control never sees that message,
     * we cannot assume that colors will remain the same throughout
     * the life of the control.
     *
     * We use the system color if pMS->rgCr[i] is -1, otherwise we
     * use the color in pMS->rgCr[i].
     */

    for (iColor=0; iColor < CCOLORS; iColor++)
        {
        if (pMS->rgCr[iColor] == -1L)
            {
            //HACK:  Windows 3.0 has no system color for button highlight
            if (rgColorDef[iColor] == rgNone)
                rgCr[iColor]=RGB(255, 255, 255);
            else
                rgCr[iColor]=GetSysColor(rgColorDef[iColor]);
            }
        else
            rgCr[iColor]=pMS->rgCr[iColor];

        rgHPen[iColor]=CreatePen(PS_SOLID, 1, rgCr[iColor]);
        }

    hBrushFace =CreateSolidBrush( rgCr[MSCOLOR_FACE] );
    hBrushArrow=CreateSolidBrush( rgCr[MSCOLOR_ARROW] );
    hBrushBlack = (HBRUSH)GetStockObject( BLACK_BRUSH );

    /*
     * These values are extremely cheap to calculate for the amount
     * we are going to use them.
     */
    cx =(WORD)(lpRect->right  - lpRect->left);
    cy =(WORD)(lpRect->bottom - lpRect->top);
    cx2=cx  >> 1;
    cy2=cy  >> 1;
    cx4=cx2 >> 1;
    cy4=cy2 >> 1;


    /*
     * If one half is depressed, set the x/yAdd varaibles that we use
     * to shift the small arrow image down and right.
     */
    if (!StateTest(pMS, MUSTATE_MOUSEOUT))
        {
        if (StateTest(pMS, MUSTATE_UPCLICK | MUSTATE_LEFTCLICK))
            {
            xAdd1=1;
            yAdd1=1;
            }

        if (StateTest(pMS, MUSTATE_DOWNCLICK | MUSTATE_RIGHTCLICK))
            {
            xAdd2=1;
            yAdd2=1;
            }
        }


    //Draw the face color and the outer frame
    SelectObject(hDC, hBrushFace);
    SelectObject(hDC, rgHPen[MSCOLOR_FRAME]);
    Rectangle(hDC, lpRect->left, lpRect->top, lpRect->right, lpRect->bottom);


    //Draw the arrows depending on the orientation.
    if (MSS_VERTICAL & pMS->dwStyle)
        {
        //Draw the horizontal center line.
		  MOVETO(hDC, 0,  cy2, &pt);
        LineTo(hDC, cx, cy2);

        /*
         * We do one of three modifications for drawing the borders:
         *  1) Both halves un-clicked.
         *  2) Top clicked,   bottom unclicked.
         *  3) Top unclicked, bottom clicked.
         *
         * Case 1 is xAdd1==xAdd2==0
         * Case 2 is xAdd1==1, xAdd2=0
         * Case 3 is xAdd1==0, xAdd2==1
         *
         */

        //Draw top and bottom buttons borders.
        Draw3DButtonRect(hDC, rgHPen[MSCOLOR_HIGHLIGHT],
                         rgHPen[MSCOLOR_SHADOW],
                         0,  0,(WORD)(cx-1), cy2, (BOOL)xAdd1);

        Draw3DButtonRect(hDC, rgHPen[MSCOLOR_HIGHLIGHT],
                         rgHPen[MSCOLOR_SHADOW],
                         0, cy2, (WORD)(cx-1),(WORD)(cy-1),(BOOL)xAdd2);


        //Select default line color.
        SelectObject(hDC, rgHPen[MSCOLOR_ARROW]);

        //Draw the arrows depending on the enable state.
        if (StateTest(pMS, MUSTATE_GRAYED))
            {
            /*
             * Draw arrow color lines in the upper left of the
             * top arrow and on the top of the bottom arrow.
             * Pen was already selected as a default.
             */
            MOVETO(hDC, cx2,   cy4-2,     &pt);      //Top arrow
            LineTo(hDC, cx2-3, cy4+1);
            MOVETO(hDC, cx2-3, cy2+cy4-2, &pt);  //Bottom arrow
            LineTo(hDC, cx2+3, cy2+cy4-2);

            /*
             * Draw highlight color lines in the bottom of the
             * top arrow and on the ;pwer right of the bottom arrow.
             */
            SelectObject(hDC, rgHPen[MSCOLOR_HIGHLIGHT]);
            MOVETO(hDC,   cx2-3, cy4+1,     &pt);      //Top arrow
            LineTo(hDC,   cx2+3, cy4+1);
            MOVETO(hDC,   cx2+3, cy2+cy4-2, &pt);  //Bottom arrow
            LineTo(hDC,   cx2,   cy2+cy4+1);
            SetPixel(hDC, cx2,   cy2+cy4+1, rgCr[MSCOLOR_HIGHLIGHT]);
            }
        else
            {
            //Top arrow polygon
            rgpt1[0].x=xAdd1+cx2;
            rgpt1[0].y=yAdd1+cy4-2;
            rgpt1[1].x=xAdd1+cx2-3;
            rgpt1[1].y=yAdd1+cy4+1;
            rgpt1[2].x=xAdd1+cx2+3;
            rgpt1[2].y=yAdd1+cy4+1;

            //Bottom arrow polygon
            rgpt2[0].x=xAdd2+cx2;
            rgpt2[0].y=yAdd2+cy2+cy4+1;
            rgpt2[1].x=xAdd2+cx2-3;
            rgpt2[1].y=yAdd2+cy2+cy4-2;
            rgpt2[2].x=xAdd2+cx2+3;
            rgpt2[2].y=yAdd2+cy2+cy4-2;

            //Draw the arrows
            SelectObject(hDC, hBrushArrow);
            Polygon(hDC, (LPPOINT)rgpt1, 3);
            Polygon(hDC, (LPPOINT)rgpt2, 3);
            }
        }
    else
        {
        //Draw the vertical center line, assume the frame color is selected.
        MOVETO(hDC, cx2, 0, &pt);
        LineTo(hDC, cx2, cy);

        /*
         * We do one of three modifications for drawing the borders:
         *  1) Both halves un-clicked.
         *  2) Left clicked,   right unclicked.
         *  3) Left unclicked, right clicked.
         *
         * Case 1 is xAdd1==xAdd2==0
         * Case 2 is xAdd1==1, xAdd2=0
         * Case 3 is xAdd1==0, xAdd2==1
         *
         */

        //Draw left and right buttons borders.
        Draw3DButtonRect(hDC, rgHPen[MSCOLOR_HIGHLIGHT],
                         rgHPen[MSCOLOR_SHADOW],
                         0,   0, cx2,(WORD)(cy-1), (BOOL)xAdd1);

        Draw3DButtonRect(hDC, rgHPen[MSCOLOR_HIGHLIGHT],
                         rgHPen[MSCOLOR_SHADOW],
                         cx2, 0, (WORD)(cx-1),(WORD)(cy-1), (BOOL)xAdd2);


        //Select default line color.
        SelectObject(hDC, rgHPen[MSCOLOR_ARROW]);

        //Draw the arrows depending on the enable state.
        if (StateTest(pMS, MUSTATE_GRAYED))
            {
            /*
             * Draw arrow color lines in the upper left of the
             * left arrow and on the left of the right arrow.
             * Pen was already selected as a default.
             */
            MOVETO(hDC, cx4-2,     cy2,   &pt);        //Left arrow
            LineTo(hDC, cx4+1,     cy2-3);
            MOVETO(hDC, cx2+cx4-2, cy2-3, &pt);      //Right arrow
            LineTo(hDC, cx2+cx4-2, cy2+3);

            /*
             * Draw highlight color lines in the bottom of the
             * top arrow and on the ;pwer right of the bottom arrow.
             */
            SelectObject(hDC, rgHPen[MSCOLOR_HIGHLIGHT]);
            MOVETO(hDC, cx4+1,     cy2-3, &pt);
            LineTo(hDC, cx4+1,     cy2+3);
            MOVETO(hDC, cx2+cx4+1, cy2,   &pt);
            LineTo(hDC, cx2+cx4-2, cy2+3);
            }
        else
            {
            //Left arrow polygon
            rgpt1[0].x=xAdd1+cx4-2;
            rgpt1[0].y=yAdd1+cy2;
            rgpt1[1].x=xAdd1+cx4+1;
            rgpt1[1].y=yAdd1+cy2+3;
            rgpt1[2].x=xAdd1+cx4+1;
            rgpt1[2].y=yAdd1+cy2-3;

            //Right arrow polygon
            rgpt2[0].x=xAdd2+cx2+cx4+1;
            rgpt2[0].y=yAdd2+cy2;
            rgpt2[1].x=xAdd2+cx2+cx4-2;
            rgpt2[1].y=yAdd2+cy2+3;
            rgpt2[2].x=xAdd2+cx2+cx4-2;
            rgpt2[2].y=yAdd2+cy2-3;

            //Draw the arrows
            SelectObject(hDC, hBrushArrow);
            Polygon(hDC, (LPPOINT)rgpt1, 3);
            Polygon(hDC, (LPPOINT)rgpt2, 3);
            }
        }

    //Clean up
    EndPaint(hWnd, &ps);

    DeleteObject(hBrushFace);
    DeleteObject(hBrushArrow);

    for (iColor=0; iColor < CCOLORS; iColor++)
        DeleteObject(rgHPen[iColor]);

    return 0L;
    }




/*
 * Draw3DButtonRect
 *
 * Purpose:
 *  Draws the 3D button look within a given rectangle.  This rectangle
 *  is assumed to be bounded by a one pixel black border, so everything
 *  is bumped in by one.
 *
 * Parameters:
 *  hDC         DC to draw to.
 *  hPenHigh    HPEN highlight color pen.
 *  hPenShadow  HPEN shadow color pen.
 *  x1          WORD Upper left corner x.
 *  y1          WORD Upper left corner y.
 *  x2          WORD Lower right corner x.
 *  y2          WORD Lower right corner y.
 *  fClicked    BOOL specifies if the button is down or not (TRUE==DOWN)
 *
 * Return Value:
 *  void
 *
 */

void FAR PASCAL Draw3DButtonRect(HDC hDC, HPEN hPenHigh, HPEN hPenShadow,
                             WORD x1, WORD y1, WORD x2, WORD y2,
                             BOOL fClicked)
    {
    HPEN        hPenOrg;

#ifdef _WIN32
    POINT       pt;
#endif

    //Shrink the rectangle to account for borders.
    x1+=1;
    x2-=1;
    y1+=1;
    y2-=1;

    hPenOrg = (HPEN)SelectObject( hDC, hPenShadow );

    if (fClicked)
        {
        //Shadow on left and top edge when clicked.
        MOVETO(hDC, x1, y2, &pt);
        LineTo(hDC, x1, y1);
        LineTo(hDC, x2+1, y1);
        }
    else
        {
        //Lowest shadow line.
        MOVETO(hDC, x1, y2, &pt);
        LineTo(hDC, x2, y2);
        LineTo(hDC, x2, y1-1);

        //Upper shadow line.
        MOVETO(hDC, x1+1, y2-1, &pt);
        LineTo(hDC, x2-1, y2-1);
        LineTo(hDC, x2-1, y1);

        SelectObject( hDC, hPenHigh );

        //Upper highlight line.
        MOVETO(hDC, x1,   y2-1, &pt);
        LineTo(hDC, x1,   y1);
        LineTo(hDC, x2,   y1);
        }

    SelectObject( hDC, hPenOrg );
    return;
    }
