/* midimonx.c - WinMain() and WndProc() functions for MIDIMon, along
 *      with some initialization and error reporting functions.
 *
 * MIDIMon is a Windows with Multimedia application that records and displays 
 *  incoming MIDI information.  It uses a low-level callback function to 
 *  get timestamped MIDI input.  The callback function puts the incoming
 *  MIDI event information (source device, timestamp, and raw MIDI
 *  data) in a circular input buffer and notifies the application by posting 
 *  a MM_MIDIINPUT message.  When the application processes the MM_MIDIINPUT
 *  message, it removes the MIDI event from the input buffer and puts it in
 *  a display buffer.  Information in the display buffer is converted to
 *  text and displayed in a scrollable window.  Incoming MIDI data can be sent
 *  to the MIDI Mapper if the user chooses.  Filtering is provided for the
 *  display buffer, but not for data sent to the Mapper.
 *
 *    (C) Copyright Microsoft Corp. 1991.  All rights reserved.
 *
 *    You have a royalty-free right to use, modify, reproduce and 
 *    distribute the Sample Files (and/or any modified version) in 
 *    any way you find useful, provided that you agree that 
 *    Microsoft has no warranty obligations or liability for any 
 *    Sample Application Files which are modified. 
 *
 *  MODIFICATIONS:
 *         
 *  921017 by Jamie O'Connell: The program now uses a dialog
 *      To select input and output MIDI Devices.
 *  921114 by JWO: Added Control Panel Dialog.
 *  921125 JWO:    Added system menu
 *  950403 JWO:    Begin adding support for SysEx (has it been this long?)
 *  960205 JWO:    Use static CTL3D
 */

#include <windows.h>
#include <mmsystem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "midimon.h"
#include "circbuf.h"
#include "syxbuf.h"
#include "display.h"
#include "filter.h"
#include "prefer.h"
#include "logfile.h"
#include "mstatus.h"
#include "instdata.h"
#include "midimcbk.h"
#include "piano.h"
#include "file.h"
#ifndef _WIN32
#include "ctl3d.h"
#endif

char VerStr[]    = "3.00.001";

#define ID_SYSEX_TIMER 1

const char szRelease[] = "&Release MIDI";
const char szAttach[]  = "&Attach MIDI";
const char szOnTop[]   = "Always &On Top";

HINSTANCE   hInst;                      // Instance handle for application
char        szAppName[32];              // Application name
HICON       hIconList[NUMICONS];        // List of Icons to display
HWND        hMainWnd;                   // Main window handle
HWND        hCtlDlg = NULL;             // Handle to Control panel
HWND        hMStat  = NULL;             // Handle to MIDI Status
HWND        hKeybdDlg = NULL;           // Handle to Keyboard
HWND        hActiveDlg = NULL;          // Handle to Active modelesss dlg
HMIDIOUT    hMOut   = NULL;             // Handle to MIDI Output
WORD wNumInDevices  = 0;                // Number of MIDI input devices
WORD wNumOutDevices = 0;                // Number of MIDI input devices
BOOL bRecordingEnabled = TRUE;          // Enable/disable recording flag
BOOL bThruOn     = FALSE;
BOOL bOnTop      = FALSE;
BOOL bPassSysEx  = FALSE;
BOOL bOpenPorts  = TRUE;
short nNumBufferLines = 0;              // Number of lines in display buffer
RECT rectScrollClip;                    // Clipping rectangle for scrolling
WORD wDefInst = 0x0FF;
WORD bufSize;                                                
WORD numSxBuf;

LPSYSEXBUFFER    lpSXOut = NULL;        // Sysex buffer chain
LPCIRCULARBUFFER lpInputBuffer;         // Input buffer structure
LPDISPLAYBUFFER  lpDisplayBuffer;       // Display buffer structure
PREFERENCES      preferences;           // User preferences structure
LOGFILE          logInfo;

MIDIINCAPS  midiInCaps[MAX_NUM_DEVICES];// Device capabilities structures
HMIDIIN     hMidiIn[MAX_NUM_DEVICES];   // MIDI input device handles
char        ReturnBuffer[256];          // Device Names
MIDIOUTCAPS midiOutCaps[MAX_NUM_DEVICES];// Device capabilities structures
UINT        wOutID = 0xFFFF;
LPSTR       lpBuf  = ReturnBuffer;
NMBLK       szInDev;
UINT        nDevInOpen = 0;
char        szOutDevNm[40];
UINT        wMapperID = 0;
HMENU       hSysMenu;
short       iconH, iconW;
DLGPROC     ctldlgprc;
DLGPROC     mstatusprc;
BOOL        fMIDIFree   = FALSE;  
char        szErrorText[256];
FARPROC     MIDIin;
HHOOK       hFilterHook;                // handle to keyboard hook process
#ifndef _WIN32
HOOKPROC    lpFilterProc;               // message filter procedure
DLGPROC     KeybdDlgProc;               // keyboard procedure
#endif
#ifdef _WIN32
ATOM        a1;                         // global atom for instance detection
#endif
// Callback instance data pointers
LPCALLBACKINSTANCEDATA lpCallbackInstanceData[MAX_NUM_DEVICES];

// Virtual key to scroll message translation structure
const KEYTOSCROLL keyToScroll [] = { 
            { VK_HOME,  WM_VSCROLL, SB_TOP      },
            { VK_END,   WM_VSCROLL, SB_BOTTOM   },
            { VK_PRIOR, WM_VSCROLL, SB_PAGEUP   },
            { VK_NEXT,  WM_VSCROLL, SB_PAGEDOWN },
            { VK_UP,    WM_VSCROLL, SB_LINEUP   },
            { VK_DOWN,  WM_VSCROLL, SB_LINEDOWN },
            { VK_LEFT,  WM_HSCROLL, SB_LINEUP   },
            { VK_RIGHT, WM_HSCROLL, SB_LINEDOWN }};

#define NUMKEYS 8

// Display filter structure
static LPFILTER filter = NULL;

static BOOL OpenInDev(HWND hWnd);
static BOOL OpenOutDev(HWND hWnd, UINT ID);
static BOOL CloseDev(HWND hWnd);
void  MIDIErr(MMRESULT code, LPSTR szName, BOOL in); //static 
static void  ReOpenPorts(HWND hWnd);
static LPFILTER CreateFilter(void);
static void  DisposeFilter(LPFILTER lpFilter);
static COLORREF GetEventColor(WORD type, DWORD dwData);
static void  DisplayDevice(HWND hWnd);


/* ********************************************************************
 *  ** Saved because it's a nifty way to activate the first instance **
 *         
 *  hMainWnd = FindWindow(szAppName, NULL);
 *  PostMessage(hMainWnd, WM_ACTIVATEFIRST, 0, 0);
 *  return 0;        
 */

/* WinMain - Entry point for MIDIMon.
 */
int PASCAL WinMain(HINSTANCE hInstance,
                   HINSTANCE hPrevInstance,
                   LPSTR lpszCmdLine,
                   int cmdShow) {
    MSG       msg;
    WORD      wRtn;
    WORD      ii;
    char      szWrk[8];
    WORD      x, y;
#ifndef _WIN32    
    HMODULE   hiCM;
#endif

    hInst = hInstance;

    /* Get preferred user setup.
     */    
    preferences.nInDev      = MAX_NUM_DEVICES;
    preferences.lpIDN       = &szInDev;
    preferences.lpszOutDev  = szOutDevNm;
    if ((filter = CreateFilter()) == NULL) {
       Error("No Memory to create filter!");
       return 1;
       }
    preferences.lpFilter = filter;
    preferences.lpszLogFile = logInfo.szLogFile;
    getPreferences(hInst, &preferences);

    logInfo.bEnabled = preferences.bLogEnabled;
    logInfo.bAppend  = preferences.bLogAppend;

    /* Initialize application.
     */
    LoadString(hInstance, IDS_APPNAME, szAppName, sizeof(szAppName)); 

// previous instance always NULL in Win32
#ifdef _WIN32 
    if(GlobalFindAtom(szAppName))  //already in atom table
       bOpenPorts = FALSE;        // Don't open devices immediately
    a1 = GlobalAddAtom(szAppName);//add to atom table or bump count
    //alternate approach below, but subject to race condition
    //if (FindWindow(szAppName, NULL) // Don't open devices immediately
    //   bOpenPorts = FALSE;   
#else
    if (hPrevInstance)      // Don't open devices immediately
       bOpenPorts = FALSE;   
#endif
    if( !hPrevInstance ) //always inits in Win32
       if( !InitFirstInstance(hInstance) ) {
          Error("InitFirstInstance failed!");
          return FALSE;
       }

    for (ii = 0; ii < NUMICONS; ++ii) { // Load up Icon Array for later
       wsprintf(szWrk, "MM%d", ii+1);  // Numbered 1 - 16
       hIconList[ii] = LoadIcon(hInstance, szWrk);
       }
    
    /* Create a display window.
     */
     
    x = hPrevInstance ? CW_USEDEFAULT : preferences.iInitialX;
    y = hPrevInstance ? CW_USEDEFAULT : preferences.iInitialY;
    
    hMainWnd = CreateWindow(szAppName,
                        szAppName,
                        WS_OVERLAPPEDWINDOW | WS_HSCROLL | WS_VSCROLL,
                        x,
                        y,
                        preferences.iInitialW,
                        preferences.iInitialH,
                        (HWND)NULL,
                        (HMENU)NULL,
                        hInstance,
                        (LPSTR)NULL);

    if (hMainWnd == NULL) {
       Error("Create Main Window Failed!");
       return 1;
       }
      
    // Set default display octave
    SetOctave(preferences.nOctave);     
    DoMenuItemCheck(hMainWnd, preferences.nOctave+OCTVBASE, TRUE);

    if (logInfo.bEnabled) {
      InitLog(&logInfo);
      DoMenuItemCheck(hMainWnd, IDM_LOGFILE, TRUE);
      }
      
    /* Hide scroll bars for now.
     */
    SetScrollRange(hMainWnd, SB_VERT, 0, 0, FALSE);
    SetScrollRange(hMainWnd, SB_HORZ, 0, 0, FALSE);
    
    /* Show the display window.
     */
    ShowWindow(hMainWnd, cmdShow);
    
    /* Get the number of MIDI input devices.  Then get the capabilities of
     * each device.  We don't use the capabilities information right now,
     * but we could use it to report the name of the device that received
     * each MIDI event.
     */

    wNumInDevices = midiInGetNumDevs();
    if (!wNumInDevices) 
       Error("There are no MIDI input devices.");

    if (wNumInDevices > MAX_NUM_DEVICES)
       wNumInDevices = MAX_NUM_DEVICES;

    for (ii=0; ii < wNumInDevices; ii++) {
       if (wRtn = midiInGetDevCaps(ii, (LPMIDIINCAPS) &midiInCaps[ii],
                                sizeof(MIDIINCAPS))) {
          MIDIErr(wRtn, "DevCaps In", TRUE);   
          }
       hMidiIn[ii] = 0;
       }

    // Now enumerate output devices

    wNumOutDevices = midiOutGetNumDevs();
    if (!wNumOutDevices) 
       Error("There are no MIDI output devices.");

    if (wNumOutDevices > MAX_NUM_DEVICES)
       wNumOutDevices = MAX_NUM_DEVICES;

    if (*szOutDevNm == '\0') // No Output device
       preferences.bThruOn = FALSE;
    bThruOn = preferences.bThruOn;
    hMOut = 0;
    
    for (ii=0; ii < wNumOutDevices; ii++) {
       if (wRtn = midiOutGetDevCaps(ii, (LPMIDIOUTCAPS) &midiOutCaps[ii],
                                sizeof(MIDIOUTCAPS))) {
          MIDIErr(wRtn, "DevCaps Out", FALSE); 
          }
       if (bThruOn && (STRICMP(szOutDevNm, midiOutCaps[ii].szPname) == 0))
          wOutID = ii;
       }
    wMapperID = wNumOutDevices++; // Make Mapper last device
    lstrcpy(midiOutCaps[wMapperID].szPname,
            "MIDI Mapper");
    if (bThruOn && (STRICMP(szOutDevNm, "MIDI Mapper") == 0))
       wOutID = wMapperID;

    /* Allocate a circular buffer for low-level MIDI input.  This buffer
     * is filled by the low-level callback function and emptied by the
     * application when it receives MM_MIDIINPUT messages.
     */
    lpInputBuffer = AllocCircularBuffer(
                        (DWORD)(INPUT_BUFFER_SIZE * sizeof(EVENT)));
    if (lpInputBuffer == NULL) {
       Error("Not enough memory available for input buffer.");
       return 1;
       }

    /* Allocate a display buffer.  Incoming events from the circular input
         * buffer are put into this buffer for display.
     */
    lpDisplayBuffer = AllocDisplayBuffer((DWORD)(DISPLAY_BUFFER_SIZE));
    if (lpDisplayBuffer == NULL) {
       Error("Not enough memory available for display buffer.");
       FreeCircularBuffer(lpInputBuffer);
       return 1;
       }

    /* Open all MIDI input devices after allocating and setting up
     * instance data for each device.  The instance data is used to
     * pass buffer management information between the application and
     * the low-level callback function.  It also includes a device ID,
     * a handle to the MIDI Mapper, and a handle to the application's
     * display window, so the callback can notify the window when input
     * data is available.  A single callback function is used to service
     * all opened input devices.
     */

#ifndef _WIN32    
    if ((hiCM = LoadLibrary("MIDIMCBK.DLL")) < HINSTANCE_ERROR) {
       wsprintf(szErrorText, 
       "LoadLibrary: MIDIMCBK.DLL Failed! Code: %d", 
       (short)hiCM);
       Error(szErrorText);
       PostQuitMessage(1);
       }                                                        
       
    if ((MIDIin = GetProcAddress(hiCM, "midiInputHandler")) == NULL) {
       Error("GetProcAddress: midiInputHandler failed!");
       PostQuitMessage(1);
       }

#else // it's right here -- no DLL
    InitInstance(hInstance); // this sets up the spin ctrl, 
                             // it's called by LibMain in win 3.1
    MIDIin = (FARPROC)midiInputHandler;
#endif

    nDevInOpen = preferences.nInDev;
    bPassSysEx = (BOOL)preferences.bPasSX;
    numSxBuf   = preferences.nSxBuf;
    bufSize    = preferences.bufSize;
    DoMenuItemCheck(hMainWnd, IDM_PASSX, bPassSysEx);

    if (bOpenPorts && OpenInDev(hMainWnd)) {
       if (bThruOn)
          OpenOutDev(hMainWnd, wOutID);
       }
    else {
       bThruOn = FALSE;
       wOutID = (WORD)-1;
       bOpenPorts = FALSE;
       }

#ifndef _WIN32
    // New 3D DLL
    Ctl3dRegister(hInstance);
    Ctl3dAutoSubclass(hInstance);
#endif

    // Add Release MIDI Item to System menu
    hSysMenu = GetSystemMenu(hMainWnd, FALSE);
    AppendMenu(hSysMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hSysMenu, MF_STRING, IDM_ONTOP, szOnTop);
    AppendMenu(hSysMenu, MF_STRING, IDM_FREEMIDI, szRelease);

    iconH = GetSystemMetrics(SM_CYICON);
    iconW = GetSystemMetrics(SM_CXICON);

    if (preferences.bOnTop)     // make topmost
       PostMessage(hMainWnd, WM_SYSCOMMAND, IDM_ONTOP, 0L); 
    
    if (!bOpenPorts) // query for ports initially
       PostMessage(hMainWnd, WM_COMMAND, IDM_MDEVDLG, 0L); 

    /* Standard Windows message processing loop.  We don't drop out of
     * this loop until the user quits the application.
     * Note: hActiveDlg is the handle to the active modeless dlg
     * set when each dlg activates or set to NULL when de-activates
     */
    while (GetMessage(&msg, NULL, 0, 0)) {
       if (hActiveDlg == NULL || !IsDialogMessage(hActiveDlg, &msg)) {
          TranslateMessage(&msg);
          DispatchMessage(&msg);
          }
       }                 
       
    CloseDev(NULL); // Free up MIDI devices
#ifndef _WIN32
    Ctl3dUnregister(hInstance);
    FreeLibrary(hiCM);
#endif

    if (IsLogOpen())
       CloseLog();

#ifdef _WIN32
    GlobalDeleteAtom(a1); //decrements count or removes if count is 0
#endif
    
    /* Free input and display buffers.
     */
    DisposeFilter(filter);
    FreeCircularBuffer(lpInputBuffer);
    FreeDisplayBuffer(lpDisplayBuffer);

    for (ii = 0; ii < NUMICONS; ++ii)
        DestroyIcon(hIconList[ii]);
    
    return (msg.wParam);
    }

/* WndProc - Main window procedure function.
 */
long FAR PASCAL _export WndProc(HWND hWnd, 
                                UINT message,
                                WPARAM wParam,
                                LPARAM lParam) {
   static BOOL  bWindowCreated = 0;
   static HFONT hFont;
   static int   nChrW, nChrH;
   static int   nTopHt;
   static int   maxClientWidth;
   static short nClientW, nClientH;
   static short nVscrollMax = 0;
   static short nHscrollMax = 0;
   static short nVscrollPos = 0;
   static short nHscrollPos = 0;
   static short nNumCharsPerLine = 0;
   static short nNumDisplayLines = 0;
   static short nNumDisplayChars = 0;
   static int   icnIdx = 0;
   LPCSTR lpszmi;

   RECT   rct;
   HDC    hDC;
   short  nVscrollInc, nHscrollInc;
   UINT   i;
   BOOL   calldef = FALSE;
   long   lresult = 0L;
   SIZE   size;

   switch(message) {
      case WM_CREATE:   
         {
         TEXTMETRIC tm;
         WORD instCount;
         char szTitle[24];
            
         hDC = GetDC(hWnd);

         /* Set the font we want to use.
          */
         if ((hFont = (HFONT)GetStockObject(preferences.iFixFont)) == NULL)
            hFont = (HFONT)GetStockObject(SYSTEM_FIXED_FONT);            
         SelectObject(hDC, hFont);
            
         /* Get text metrics and calculate the number of characters
          * per line and the maximum width required for the client area.
          */
         GetTextMetrics(hDC, &tm);
         nChrW  = tm.tmAveCharWidth;
         nChrH  = tm.tmHeight + tm.tmExternalLeading;
         nTopHt = nChrH;   // 1 lines of text for top label
         nNumCharsPerLine = sizeof(LABEL) - 1;
         GetTextExtentPoint(hDC,
                LABEL,
                sizeof LABEL,
                &size);
         maxClientWidth = size.cx;
         ReleaseDC(hWnd, hDC);

         // add an ID for the Window
         if ((instCount = getInstCount()) > 1) {
            wsprintf(szTitle, "%s:%d", (LPSTR)szAppName, instCount);
            SetWindowText(hWnd, szTitle);
            }      
            
         bWindowCreated = 1;
         }
         break;

      case WM_SIZE:
         nClientH = HIWORD(lParam);
         nClientW = LOWORD(lParam);

         /* Get new client area and adjust scroll clip rectangle.
          */
         GetClientRect(hWnd, (LPRECT)&rectScrollClip);
         rectScrollClip.top += nTopHt;
            
         /* Calculate new display metrics.  We subtract 1 from
          * nNumDisplayLines to allow room for the label line.
          */
         nNumDisplayLines = (nClientH / nChrH) - 1;
         nNumDisplayChars = nClientW / nChrW;

         /* Calculate and set new scroll bar calibrations.
          */
         nVscrollMax = max(0, nNumBufferLines - nNumDisplayLines);
         nVscrollPos = min(nVscrollPos, nVscrollMax);
         nHscrollMax = max(0, nNumCharsPerLine - nNumDisplayChars);
         nHscrollPos = min(nHscrollPos, nHscrollMax);
         SetScrollRange(hWnd, SB_VERT, 0, nVscrollMax, FALSE);
         SetScrollPos(hWnd, SB_VERT, nVscrollPos, TRUE);
         SetScrollRange(hWnd, SB_HORZ, 0, nHscrollMax, FALSE);
         SetScrollPos(hWnd, SB_HORZ, nHscrollPos, TRUE);
         break;

      case WM_GETMINMAXINFO:
         /* Limit the maximum width of the window.
          */
         if (bWindowCreated) {
            LPMINMAXINFO lpmmi = (LPMINMAXINFO)lParam;
            lpmmi->ptMaxTrackSize.x = 
                        maxClientWidth 
                        + (2 * GetSystemMetrics(SM_CXFRAME)) 
                        + (GetSystemMetrics(SM_CXVSCROLL));
            }
         break;
            
      case WM_COMMAND:
         /* Process menu messages. 
          */
         CommandMsg(hWnd, wParam, lParam); 
         break;


      case WM_VSCROLL:
         /* Determine how much to scroll vertically.
          */

         switch (wParam) {
            case SB_TOP:
               nVscrollInc = -nVscrollPos;
               break;
                    
            case SB_BOTTOM:
               nVscrollInc = nVscrollMax - nVscrollPos;
               break;

            case SB_LINEUP:
               nVscrollInc = -1;
               break;

            case SB_LINEDOWN:
               nVscrollInc = 1;
               break;

            case SB_PAGEUP:
               nVscrollInc = min (-1, -nNumDisplayLines);
               break;

            case SB_PAGEDOWN:
               nVscrollInc = max(1, nNumDisplayLines);
               break;

            case SB_THUMBTRACK:
               nVscrollInc = LOWORD(lParam) - nVscrollPos;
               break;

            default:
               nVscrollInc = 0;
            
            }
            
         /* Limit the scroll range and do the scroll.  We use the
          * rectScrollClip rectangle because we don't want to scroll
          * the entire window, only the part below the display label line.
          */
         if (nVscrollInc = max(-nVscrollPos, 
                             min(nVscrollInc, nVscrollMax - nVscrollPos))) {
            nVscrollPos += nVscrollInc;
            ScrollWindow(hWnd, 0, -nChrH * nVscrollInc,
                              (LPRECT)&rectScrollClip,
                              (LPRECT)&rectScrollClip);
            // UpdateWindow(hWnd);
            SetScrollPos(hWnd, SB_VERT, nVscrollPos, TRUE);
            }
         break;

     case WM_HSCROLL:
         /* Determine how much to scroll horizontally.
          */

         switch (wParam) {
            case SB_LINEUP:
               nHscrollInc = -1;
               break;

            case SB_LINEDOWN:
               nHscrollInc = 1;
               break;

            case SB_PAGEUP:
               nHscrollInc = min (-1, -nNumDisplayChars);
               break;

            case SB_PAGEDOWN:
               nHscrollInc = max(1, nNumDisplayChars);
               break;

            case SB_THUMBTRACK:
               nHscrollInc = LOWORD(lParam) - nHscrollPos;
               break;

            default:
               nHscrollInc = 0;
            }
            
         /* Limit the scroll range and to the scroll.
          */
         if (nHscrollInc = max(-nHscrollPos,
                          min(nHscrollInc, nHscrollMax - nHscrollPos))) {
            nHscrollPos += nHscrollInc;
            ScrollWindow(hWnd, -nChrW * nHscrollInc, 0, NULL, NULL);
            // UpdateWindow(hWnd);
            SetScrollPos(hWnd, SB_HORZ, nHscrollPos, TRUE);
            }
         break;

      case WM_KEYDOWN:
            /* Translate keystrokes to scroll message.
                         */
         calldef = TRUE;
         for (i = 0; i < NUMKEYS; i++)
             if (wParam == keyToScroll[i].wVirtKey) {
                PostMessage(hWnd, keyToScroll[i].iMessage,
                            keyToScroll[i].wRequest, 0L);
                calldef = FALSE;
                break;
             }
         break;
            
      case WM_QUERYDRAGICON:
         lresult = MAKELONG(hIconList[icnIdx], 0);
         break;

      case WM_ERASEBKGND: // looks better without it
         lresult = TRUE;
         break;

      case MM_ANIMATEICON:
         {
         HICON  hIconCur;
         WORD   OldMode;
         WORD   OldBkMode;
         short  icnX, icnY;

         if ((HINSTANCE)wParam != hInst) // only do this for ourselves
            break;
         hIconCur = hIconList[icnIdx];
         if (++icnIdx == NUMICONS)
            icnIdx = 0;
#ifdef _WIN32 // this is different in Win32
         SetClassLong(hWnd, GCL_HICON, (LONG)hIconCur);
#else
         SetClassWord(hWnd, GCW_HICON, (WORD)hIconCur);
#endif
         GetClientRect(hWnd, &rct);
         hDC = GetWindowDC(hWnd);
         OldMode = SetMapMode(hDC, MM_TEXT);                
         icnX = (rct.right - iconW) >> 1;
         icnY = (rct.bottom - iconH) >> 1;            
          
         OldBkMode = SetBkMode(hDC, TRANSPARENT);
         DrawIcon(hDC, icnX, icnY, hIconCur);
         if (OldMode != MM_TEXT)
            SetMapMode(hDC, OldMode);
         if (OldBkMode != TRANSPARENT)
            SetBkMode(hDC, OldBkMode);
         ReleaseDC(hWnd, hDC);
         }
         break;
            
      case WM_PAINT: 
         {           
         PAINTSTRUCT ps;
         HBRUSH   hbBrush;
         HBRUSH   hBrush; 
         COLORREF colorEvent;        
         HFONT    oldFont;
         int      xVal, yVal;
         UINT     nPaintBeg, nPaintEnd;
         short    nTxtLen;
         char     szDisplayTextBuffer[132];
         EVENT    incomingEvent;         // Incoming MIDI event structure
         LPEVENT  lpEvnt = &incomingEvent;
         BeginPaint(hWnd, &ps);
               
           /* Set up text attributes.
            */
             

           /* Put up the display label if we're asked to repaint the
            * top line of the screen.
            */
   
         oldFont = (HFONT)SelectObject(ps.hdc, hFont);           
          
         hbBrush = CreateSolidBrush(preferences.colBkGd);
         if (ps.rcPaint.top < nTopHt) { 
            FillRect(ps.hdc, &ps.rcPaint, hbBrush);
            hBrush = CreateSolidBrush(preferences.colLblBkGd);
            rct.left   = nChrW * (0 - nHscrollPos);
            rct.top    = 0;
            rct.right  = nClientW;
            rct.bottom = nTopHt;
            FillRect(ps.hdc, &rct, hBrush);
            DeleteObject(hBrush);
            SetTextColor(ps.hdc, preferences.colLblText);
            SetBkMode(ps.hdc, TRANSPARENT);
            TextOut(ps.hdc, nChrW * (0 - nHscrollPos),
                        0, szDisplayTextBuffer,
                        wsprintf(szDisplayTextBuffer, LABEL));
            ps.rcPaint.top = nTopHt;
            }
                
         /* Calculate the beginning and ending line numbers that we need
          * to paint.  These line numbers refer to lines in the display
          * buffer, not to lines in the display window.
          */

         if (GetTextColor(ps.hdc) != preferences.colText)
            SetTextColor(ps.hdc, preferences.colText);

         if (GetBkColor(ps.hdc) != preferences.colBkGd)
            SetBkColor(ps.hdc, preferences.colBkGd);

         SetBkMode(ps.hdc, OPAQUE);
         nPaintBeg = max (0, nVscrollPos + (ps.rcPaint.top / nChrH) - 1);
         nPaintEnd = min(nNumBufferLines,
                              nVscrollPos + (ps.rcPaint.bottom / nChrH) + 1);

         /* Get the appropriate events from the display buffer, convert
          * to a text string and paint the text on the display.
          */

         xVal = nChrW * (0 - nHscrollPos); // calc outside loop
         rct.left   = xVal;
         rct.right  = nClientW;
         for (i = nPaintBeg; i < nPaintEnd; i++) {
            GetDisplayEvent(lpDisplayBuffer, lpEvnt, i);
            nTxtLen = GetDisplayText(szDisplayTextBuffer, lpEvnt);              
            colorEvent = GetEventColor(incomingEvent.wDevice, incomingEvent.data);
            if (GetTextColor(ps.hdc) != colorEvent)
            SetTextColor(ps.hdc, colorEvent);
            yVal = nChrH * (1 - nVscrollPos + i);
            rct.top    = yVal;
            rct.bottom = yVal + nTopHt;
            ExtTextOut(ps.hdc,
                       xVal,
                       yVal,
                       ETO_CLIPPED | ETO_OPAQUE,
                       &rct,
                       szDisplayTextBuffer, 
                       nTxtLen,
                       NULL);
            }
         // Paint final line (if any)
         rct.left  = xVal;
         rct.top   = nChrH * (1 - nVscrollPos + i);
         rct.right = nClientW;
         rct.bottom = nClientH;
         FillRect(ps.hdc, &rct, hbBrush);
         SelectObject(ps.hdc, oldFont);
         DeleteObject(hbBrush);
         EndPaint(hWnd, &ps);
         }
         break;

      case WM_SYSCOMMAND:
         switch(wParam) {
            case IDM_FREEMIDI:
               if (fMIDIFree) { // We attach Devices
                  if (OpenInDev(hWnd)) { // Open Devices
                     fMIDIFree = FALSE;
                     if (bThruOn)
                        OpenOutDev(hWnd, wOutID);
                     }
                  }
               else if (CloseDev(hWnd)) // Release Devices
                  fMIDIFree = TRUE;
               lpszmi = fMIDIFree ? szAttach : szRelease;
               ModifyMenu(hSysMenu, IDM_FREEMIDI,
                            (MF_BYCOMMAND | MF_STRING), 
                            IDM_FREEMIDI, lpszmi);
               InvalidateRect(hWnd, NULL, TRUE);
               break;
               
            case IDM_ONTOP:
               bOnTop = !bOnTop;
               SetWindowPos(hWnd, (bOnTop ? HWND_TOPMOST : HWND_NOTOPMOST), 
                                     0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);  
               CheckMenuItem(hSysMenu, IDM_ONTOP, (bOnTop ? MF_CHECKED : MF_UNCHECKED));
               break;
     
            default:   // Pass these on
               calldef = TRUE;
               break;
            }           
         break;

      case WM_ACTIVATEFIRST:  // Sent from subsequent instance
         if (IsIconic(hWnd))
            ShowWindow(hWnd, SW_RESTORE); // Restore
         else
            SetActiveWindow(hWnd);        // Activate
         break;

      case WM_CLOSE: // save state
         SendMessage(hWnd, WM_COMMAND, IDM_SAVESETUP, 0L);
         calldef = TRUE;
         break;

      case WM_DESTROY:
         PostQuitMessage(0);
         break;

         /* The Control Panel */

      case MM_SUICIDE:
         if (wParam == WM_DESTROY) {                    
            if ((HWND)LOWORD(lParam) == hCtlDlg) {
               DestroyWindow(hCtlDlg);
               hCtlDlg = NULL;   /* Allow reselection */
               FreeProcInstance((FARPROC)ctldlgprc);
               EnableMenuItem(GetMenu(hWnd), IDM_CTLDLG,
                                 MF_BYCOMMAND | MF_ENABLED);
               }
            else if ((HWND)LOWORD(lParam) == hMStat) {
               DestroyWindow(hMStat);
               hMStat = NULL;   /* Allow reselection */
               FreeProcInstance((FARPROC)mstatusprc);
               EnableMenuItem(GetMenu(hWnd), IDM_MSTATUS,
                                 MF_BYCOMMAND | MF_ENABLED);
               }
            else if ((HWND)LOWORD(lParam) == hKeybdDlg) {
               DestroyWindow(hKeybdDlg);
               hKeybdDlg = NULL;   /* Allow reselection */
               //Unhook keyboard
               UnhookWindowsHookEx(hFilterHook);
               #ifndef _WIN32
               FreeProcInstance((FARPROC)KeybdDlgProc);
               FreeProcInstance((FARPROC)lpFilterProc);
               #endif
               EnableMenuItem(GetMenu(hWnd), IDM_KYBD,
                              MF_BYCOMMAND | MF_ENABLED);
               DrawMenuBar(hWnd);
               }
            }
         break;

      case MM_ADDBUFFER:
         if (wParam && lParam)  // add the bufferback to the driver
            midiInAddBuffer((HMIDIIN)wParam, (LPMIDIHDR)lParam, 
                                                  sizeof(MIDIHDR));
         break;
            
      case MM_MIDIINPUT:                
         /* This is a custom message sent by the low level callback
          * function telling us that there is at least one MIDI event
          * in the input buffer.  We empty the input buffer, and put
          * each event in the display buffer, if it's not filtered.
          * If the input buffer is being filled as fast we can empty
          * it, then we'll stay in this loop and not process any other
          * Windows messages, or yield to other applications.  We need
          * something to restrict the amount of time we spend here... 
          * done in callback now...  
          *    if (!FilteredEvent((LPEVENT)&incomingEvent, filter)) {
          *                              havevent = true...
          */
         {
         BOOL    havevent = FALSE;
         BOOL    fDoStat  = FALSE;
         EVENT   incomingEvent;         // Incoming MIDI event structure
         LPEVENT lpEvnt = &incomingEvent;
         char    szBuf[80];

         while(GetEvent(lpInputBuffer, lpEvnt)) {
            if (!bRecordingEnabled)
               continue;                                          
               
            fDoStat |= UpdateMStatus(lpEvnt);
            if (!FilteredEvent(lpEvnt, filter)) { 
               havevent = TRUE;
               AddDisplayEvent(lpDisplayBuffer, lpEvnt);
               if (IsLogOpen())  // log events as they come in
                  LogString(szBuf, GetDisplayText(szBuf, lpEvnt));
                  
               ++nNumBufferLines;
               nNumBufferLines = min(nNumBufferLines,
                                     DISPLAY_BUFFER_SIZE);               
               }
            }
            
         /* Recalculate vertical scroll bar range, and force
          * the display to be updated.
          */
         if (havevent) { // Only display if we got something
            nVscrollMax = max(0, nNumBufferLines - nNumDisplayLines);
            nVscrollPos = nVscrollMax;
            SetScrollRange(hWnd, SB_VERT, 0, nVscrollMax, FALSE);
            SetScrollPos(hWnd, SB_VERT, nVscrollPos, TRUE);
            InvalidateRect(hWnd, (LPRECT)&rectScrollClip, TRUE);
            if (IsIconic(hWnd)) { // make system flip icon
               PostMessage(hWnd, MM_ANIMATEICON, (WPARAM)hInst, 0L);
               break;
               }
            // UpdateWindow(hWnd);
            }
            if (fDoStat) // we're watching the state window and have at least 1 event
               PostMessage(hMStat, WM_COMMAND, IDM_UPDATESTATUS, 0L);

         }
         break;

      case MM_ADDTXTMSG:                
         {
         /* This is a custom message sent by the app
          */
         EVENT   incomingEvent;         // Incoming MIDI event structure

         incomingEvent.wDevice   = (WORD)DEVMSG;
         incomingEvent.timestamp = 0L;
         incomingEvent.data      = lParam;
         AddDisplayEvent(lpDisplayBuffer, 
                        (LPEVENT)&incomingEvent);
         ++nNumBufferLines;
         nNumBufferLines = min(nNumBufferLines,
                               DISPLAY_BUFFER_SIZE);               
           
         /* Recalculate vertical scroll bar range, and force
          * the display to be updated.
          */
         nVscrollMax = max(0, nNumBufferLines - nNumDisplayLines);
         nVscrollPos = nVscrollMax;
         SetScrollRange(hWnd, SB_VERT, 0, nVscrollMax, FALSE);
         SetScrollPos(hWnd, SB_VERT, nVscrollPos, TRUE);
         InvalidateRect(hWnd, (LPRECT)&rectScrollClip, TRUE);          
         }
         break;

      case WM_TIMER:                
        if (wParam == ID_SYSEX_TIMER) {
           if(!SendSysexFile(TRUE)) {
              KillTimer(hWnd, ID_SYSEX_TIMER);
              }
        }
        break;

      default:
         calldef = TRUE;
         break;
      }
   if (calldef)
      lresult = DefWindowProc(hWnd, message, wParam, lParam);

   return lresult;
   }


/* CommandMsg - Processes WM_COMMAND messages.
 *
 * Params:  hWnd - Handle to the window receiving the message.
 *          wParam - The WORD parameter of the WM_COMMAND message. 
 *          lParam - The DWORD parameter of the WM_COMMAND message. 
 *
 * Return:  void
 */
void CommandMsg(HWND hWnd,   
                WPARAM wParam,
                LPARAM lParam) {
    RECT    rectWindow;
    WORD    wRslt;
    HMENU   hMenu;
    DLGPROC dlgprc;

    /* Process any WM_COMMAND messages we want */
    switch (wParam) {
        case IDM_LOGFILE:
            dlgprc = (DLGPROC)MakeProcInstance((FARPROC)LogDlgProc, hInst);
            wRslt  = DialogBoxParam(hInst, "LOG", hWnd, dlgprc, 
                                    (LPARAM)(LPLOGFILE)&logInfo);
            FreeProcInstance((FARPROC)dlgprc);
            if (wRslt == IDOK) 
               DoMenuItemCheck(hWnd, IDM_LOGFILE, logInfo.bEnabled);
            break;

        case IDM_ABOUT:
            About(hInst, hWnd);
            break;

        case IDM_EXIT:
            PostMessage(hWnd, WM_CLOSE, 0, 0L);
            break;

        case IDM_CTLDLG:
            /* Create the Control Panel
             */
            if (!hCtlDlg) {
               ctldlgprc  = (DLGPROC)MakeProcInstance((FARPROC)CtlPnl, hInst);
               hCtlDlg = CreateDialog(hInst, "CTLPNL", hWnd, ctldlgprc);
               if (hCtlDlg) {
                   ShowWindow(hCtlDlg, SW_SHOW);
                   EnableMenuItem(GetMenu(hWnd), IDM_CTLDLG,
                                  MF_BYCOMMAND | MF_GRAYED);
                   }
               else
                   FreeProcInstance((FARPROC)ctldlgprc);
               }
            break;

        case IDM_MSTATUS:
            /* Create the MIDI Status Panel
             */
            if (!hMStat) {
               mstatusprc = (DLGPROC)MakeProcInstance((FARPROC)MIDIStatus, hInst);
               hMStat = CreateDialog(hInst,"MSTATUS", hWnd, mstatusprc);
               if (hMStat) {
                   ShowWindow(hMStat, SW_SHOW);
                   EnableMenuItem(GetMenu(hWnd), IDM_MSTATUS,
                                  MF_BYCOMMAND | MF_GRAYED);
                   }
               else
                   FreeProcInstance((FARPROC)mstatusprc);
               }
            break;

        case IDM_FILTERDLG:
            DoFilter(hInst, hWnd, filter);
            break;

        case IDM_MDEVDLG:
            /* We use hMOut as a toggle between sending events to the
             * Mapper and not sending events.
             */
            dlgprc = (DLGPROC) MakeProcInstance((FARPROC) MDevDlgProc, hInst);
            wRslt  = DialogBox(hInst, "MDevDlg", hWnd, dlgprc);
            FreeProcInstance((FARPROC) dlgprc);
            if (wRslt == IDOK)
               ReOpenPorts(hWnd);
            break;
        
        case IDM_OCT3:            
        case IDM_OCT4:            
        case IDM_OCT5:
        case IDM_OCT6:
            DoMenuItemCheck(hWnd, IDM_OCT3, FALSE); // treat as radio button
            DoMenuItemCheck(hWnd, IDM_OCT4, FALSE);
            DoMenuItemCheck(hWnd, IDM_OCT5, FALSE);
            DoMenuItemCheck(hWnd, IDM_OCT6, FALSE);         
            DoMenuItemCheck(hWnd, wParam, TRUE);         
            SetOctave(wParam-OCTVBASE);
            break;
                
        case IDM_SAVESETUP:
            /* Save the current location and size of the display window
             * in the MIDIMON.INI file.
             */
            GetWindowRect(hWnd, (LPRECT)&rectWindow);
            preferences.iInitialX   = rectWindow.left;
            preferences.iInitialY   = rectWindow.top;
            preferences.iInitialW   = rectWindow.right - rectWindow.left;
            preferences.iInitialH   = rectWindow.bottom - rectWindow.top;
            preferences.bThruOn     = bThruOn;
            preferences.bOnTop      = bOnTop;
            preferences.bPasSX      = bPassSysEx;
            preferences.lpIDN       = &szInDev;
            preferences.nInDev      = nDevInOpen;
            preferences.lpszOutDev  = szOutDevNm;
            preferences.nOctave     = GetOctave();
            preferences.nSxBuf      = numSxBuf;
            preferences.bufSize     = bufSize;
            preferences.lpFilter    = filter;
            preferences.bLogEnabled = logInfo.bEnabled;
            preferences.bLogAppend  = logInfo.bAppend;
            preferences.lpszLogFile = logInfo.szLogFile;
            setPreferences((LPPREFERENCES) &preferences);
            break;

        case IDM_DSDEVICE:
            DisplayDevice(hWnd);
            break;

        case IDM_STARTSTOP:
            /* Toggle between recording into the display buffer and not
             * recording.  Toggle the menu item between "Start" to "Stop"
             * accordingly.
             */
            hMenu = GetMenu(hWnd);
            if(bRecordingEnabled) {
                ModifyMenu(hMenu, IDM_STARTSTOP, MF_BYCOMMAND, IDM_STARTSTOP,
                           "&Start!");
                bRecordingEnabled = FALSE;
                }
            else {
                ModifyMenu(hMenu, IDM_STARTSTOP, MF_BYCOMMAND, IDM_STARTSTOP,
                           "&Stop!");
                bRecordingEnabled = TRUE;
                }
            DrawMenuBar(hWnd);
            break;

        case IDM_CLEAR:
            /* Reset the display buffer, recalibrate the scroll bars,
             * and force an update of the display.
             */
            ResetDisplayBuffer(lpDisplayBuffer);
            nNumBufferLines = 0;
            SetScrollRange(hWnd, SB_VERT, 0, 0, FALSE);

            InvalidateRect(hWnd, NULL, TRUE); // force repainting
            // UpdateWindow(hWnd);
            break;           

        case IDM_PASSX:
            bPassSysEx = !bPassSysEx;
            DoMenuItemCheck(hWnd, wParam, bPassSysEx);
            ReOpenPorts(NULL);
            break;

        case IDM_KYBD:    
            if (hKeybdDlg == NULL) {
               //start dialog and set hook
             #ifndef _WIN32
               HTASK hTask;
          
               lpFilterProc = (HOOKPROC)MakeProcInstance((FARPROC)KeyboardHookProc, hInst);               
               hTask = GetWindowTask(hWnd);
               hFilterHook = SetWindowsHookEx(WH_MSGFILTER, lpFilterProc, hInst, hTask);
               ASSERT(hFilterHook);

               KeybdDlgProc = (DLGPROC)MakeProcInstance((FARPROC)KeyboardDlgProc, hInst);               
               hKeybdDlg = CreateDialog(hInst, "Keyboard", hWnd, KeybdDlgProc);
               ASSERT(hKeybdDlg);
             #else //WIN32
               hFilterHook = SetWindowsHookEx(WH_MSGFILTER, (HOOKPROC)KeyboardHookProc,
                                      (HINSTANCE) NULL, GetCurrentThreadId());
               ASSERT(hFilterHook);
               hKeybdDlg = CreateDialog(hInst, "Keyboard", hWnd, KeyboardDlgProc);
               ASSERT(hKeybdDlg);
             #endif

               if (hKeybdDlg != NULL && hFilterHook != NULL) {
                  //following not necessary -- dlg has WS_VISIBLE style
                  //ShowWindow(hKeybdDlg, SW_SHOW);
                  EnableMenuItem(GetMenu(hWnd), IDM_KYBD,
                                 MF_BYCOMMAND | MF_GRAYED);
                  DrawMenuBar(hWnd);
                  }
               else {
                  //NULL dialog handle!
                  UnhookWindowsHookEx(hFilterHook);
                #ifndef _WIN32
                  FreeProcInstance((FARPROC)lpFilterProc);
                  FreeProcInstance((FARPROC)KeybdDlgProc);
                #endif
                  }
            } //KeybdDlg
            break;

        case IDM_SYSEXFILE:
            if(SendSysexFile(TRUE))
               if(!SetTimer(hWnd, ID_SYSEX_TIMER, GetSysexDelayPreference(), NULL)) {
                   Error("No timers for sysex file!");
                   SendSysexFile(FALSE);
                   }
            break;
               
        default:
            break;
        } //switch(wParam)
    }//commandMsg

/* ************************************************************************ */

void ReOpenPorts(HWND hWnd) {     
    CloseDev(NULL); // Close Open MIDI devices
            
    if (OpenInDev(hWnd)) {
       ModifyMenu(hSysMenu, IDM_FREEMIDI,
                 (MF_BYCOMMAND | MF_STRING), 
                 IDM_FREEMIDI, szRelease);
       fMIDIFree = FALSE;                        
       if (bThruOn)
          OpenOutDev(hWnd, wOutID);
       }
    else {
       bThruOn = FALSE;
       wOutID = 0xFFFF;
       }
    InvalidateRect(hWnd, NULL, TRUE);
    }
    
/* ************************************************************************ */

BOOL OpenInDev(HWND hWnd) {
    UINT ii, jj;
    BOOL found;
    LPHMIDIIN lphmi;
    DWORD     dwMII, dwCID;
    MMRESULT  wRtn;
    BOOL      bHaveIn;
    LPSYSEXBUFFER lpsxbuf;
    LPSYSEXBUFFER lpTmp;    
    LPMIDIHDR     lpMH;    
    
    for (ii = 0; ii < wNumInDevices; ii++) {
       found = FALSE;
       for (jj = 0; (jj < nDevInOpen) && !found; ++jj) {
          if (strcmp(szInDev.Nm[jj], midiInCaps[ii].szPname) == 0)
             found = TRUE;
          }
       if (found) {
          if ((lpCallbackInstanceData[ii] = AllocCallbackInstanceData())
                     == NULL) {
             Error("Not enough memory available.");
             FreeCircularBuffer(lpInputBuffer);
             FreeDisplayBuffer(lpDisplayBuffer);
             hMidiIn[ii] = 0;
             return FALSE;
             }
          lpCallbackInstanceData[ii]->hWnd    = hMainWnd;         
          lpCallbackInstanceData[ii]->wDevice = ii;
          lpCallbackInstanceData[ii]->lpBuf   = lpInputBuffer;
          lpCallbackInstanceData[ii]->hMOut   = hMOut;
          lpCallbackInstanceData[ii]->filter  = filter;
          lpCallbackInstanceData[ii]->lpSxOut = NULL;
          lpCallbackInstanceData[ii]->lpSxIn  = NULL;
        
          lphmi = &hMidiIn[ii];
          dwMII = (DWORD)MIDIin;
          dwCID = (DWORD)lpCallbackInstanceData[ii];
          wRtn  = midiInOpen(lphmi,
                             ii,
                             dwMII,
                             dwCID,
                             CALLBACK_FUNCTION);
          if (wRtn) {
             FreeCallbackInstanceData(lpCallbackInstanceData[ii]);
             lpCallbackInstanceData[ii] = NULL;
             hMidiIn[ii] = 0;
             MIDIErr(wRtn, midiInCaps[ii].szPname, TRUE);
             } 
          if (bPassSysEx) {
             for (jj = 0; jj < numSxBuf; ++jj) {
                if ((lpsxbuf = AllocSysExBuffer(bufSize)) == NULL) {
                   Error("Not enough memory available for SysEx Buffer.");
                   break;
                   }
                lpMH = &lpsxbuf->mhdr;
                if ((wRtn = midiInPrepareHeader(hMidiIn[ii], lpMH, 
                                        sizeof(MIDIHDR))) != 0) {
                   MIDIErr(wRtn, midiInCaps[ii].szPname, TRUE);
                   break;
                   }
                if ((wRtn = midiInAddBuffer(hMidiIn[ii], lpMH, 
                                     sizeof(MIDIHDR))) != 0) {
                   MIDIErr(wRtn, midiInCaps[ii].szPname, TRUE);             
                   break;
                   }
                lpTmp = lpCallbackInstanceData[ii]->lpSxIn;
                lpCallbackInstanceData[ii]->lpSxIn = lpsxbuf;
                lpsxbuf->lpSxNext = lpTmp;
                }
             }
          }
       else {  // Don't open this one
          hMidiIn[ii] = 0; 
          lpCallbackInstanceData[ii] = 0;
          }
       }
    /* Start MIDI input.
     */
    bHaveIn = FALSE;
    for (ii=0; ii < wNumInDevices; ii++) {
       if (hMidiIn[ii] && lpCallbackInstanceData[ii]) {
          bHaveIn = TRUE;       // atleast 1 device
          midiInStart(hMidiIn[ii]);
          if (wDefInst == 0xFF) // Set default
             wDefInst = ii;
          }
       }
    if (hWnd && bHaveIn)
       SendMessage(hWnd, MM_ADDTXTMSG, 0, (LPARAM)(LPCSTR)"Opened MIDI Input");
    return bHaveIn;
    }

/* ====================================================================== */    

BOOL OpenOutDev(HWND hWnd, UINT ID) {
    UINT  ii;
    UINT  wRtn;
    LPSYSEXBUFFER lpsxbuf;
    LPSYSEXBUFFER lpTmp;    
    LPMIDIHDR     lpMH;    

     if (ID == (UINT)-1) {
        lstrcpy(szErrorText, "System Error: Invalid Out ID");
        Error(szErrorText);
        hMOut = 0;
        }

     if (ID == wMapperID) // Last device is always mapper
        ID = (WORD)MIDI_MAPPER;

     wRtn = midiOutOpen((LPHMIDIOUT) &hMOut, ID, 0L, 0L, 0L);       
     if (wRtn != 0) {             // error opening Output
        MIDIErr(wRtn, szOutDevNm, FALSE);     
        hMOut = 0;
        }
     else {
        for (ii = 0; ii < 16; ++ii) { // Send all notes off on all channels
           midiOutShortMsg(hMOut, (DWORD)MAKELONG(
                             ((MCV_ALLOFF << 8) | (MC_CONTROLLER | ii)), 0));
           }  
        if (bPassSysEx) {
           for (ii = 0; ii < numSxBuf; ++ii) {
              if ((lpsxbuf = AllocSysExBuffer(bufSize)) == NULL) {
                 Error("Not enough memory available for SysEx Buffer.");
                 break;
                 }
              lpMH = &lpsxbuf->mhdr;
              if ((wRtn = midiOutPrepareHeader(hMOut, lpMH, 
                                          sizeof(MIDIHDR))) != 0) {
                 MIDIErr(wRtn, szOutDevNm, FALSE);
                 break;
                 }                       
              // It seems that Prepare resets the DONE Flag!!! (we need it set)
              lpMH->dwFlags |= MHDR_DONE;
              lpTmp = lpSXOut;
              lpSXOut = lpsxbuf;
              lpsxbuf->lpSxNext = lpTmp;
              }
           }
        ResetMStatus(); // clear the MIDI status array
        if (hMStat)
           InitDisplay(hMStat);
        }

     for (ii=0; ii < wNumInDevices; ii++) {
        if (hMidiIn[ii] && lpCallbackInstanceData[ii]) {
           lpCallbackInstanceData[ii]->hMOut   = hMOut;
           lpCallbackInstanceData[ii]->lpSxOut = lpSXOut;
           }
        }

    if (hWnd && hMOut) 
       SendMessage(hWnd, MM_ADDTXTMSG, 0, (LPARAM)(LPCSTR)"Opened MIDI Output");

     return (hMOut == 0) ? FALSE : TRUE;
     }

/* ====================================================================== */    

BOOL CloseDev(HWND hWnd) {
    UINT ii;
    WORD wRtn = 0;
    BOOL fClosed = FALSE;
    
    /* Stop, reset, close MIDI input.  Free callback instance data.
     */
    for (ii = 0; ii < wNumInDevices; ii++) {
       if (hMidiIn[ii] && (lpCallbackInstanceData[ii] != NULL)) {
          midiInStop(hMidiIn[ii]);
          midiInReset(hMidiIn[ii]);
          UnPrepIn(hMidiIn[ii], lpCallbackInstanceData[ii]->lpSxIn);
          midiInClose(hMidiIn[ii]);
          FreeSXChain(lpCallbackInstanceData[ii]->lpSxIn); 
          lpCallbackInstanceData[ii]->lpSxIn = NULL;
          FreeCallbackInstanceData(lpCallbackInstanceData[ii]);
          fClosed = TRUE; // closed one
          }
       lpCallbackInstanceData[ii] = NULL;
       hMidiIn[ii] = NULL;
       }
    wDefInst = 0xFF; //?????

    if (hWnd && fClosed) 
       SendMessage(hWnd, MM_ADDTXTMSG, 0, (LPARAM)(LPCSTR)"Closed MIDI Input");

    /* Close the MIDI Output, if it's open.
     */
    if (hMOut) {
       wRtn = midiOutReset(hMOut);
       UnPrepOut(hMOut, lpSXOut);
       wRtn = midiOutClose(hMOut);
       FreeSXChain(lpSXOut);
       if (hWnd) 
          SendMessage(hWnd, MM_ADDTXTMSG, 0, (LPARAM)(LPCSTR)"Closed MIDI Output");
       }

    hMOut   = 0;
    lpSXOut = NULL;
    
    return ((wRtn == 0) ? TRUE : FALSE);
    }       

/////////////////////////////////////////////////////////////////////
// Display the attached devices

void DisplayDevice(HWND hWnd) {
   UINT ii;
   char Buf[40];

   if (fMIDIFree)
      return;

   for (ii = 0; ii < nDevInOpen; ++ii) {
      wsprintf(Buf, "IN:  %s", (LPSTR)szInDev.Nm[ii]);
      SendMessage(hWnd, MM_ADDTXTMSG, 0, (LPARAM)(LPCSTR)Buf);
      }

   if (hMOut) { // output is open
      wsprintf(Buf, "OUT: %s", (LPSTR)szOutDevNm);
      SendMessage(hWnd, MM_ADDTXTMSG, 0, (LPARAM)(LPCSTR)Buf);
      }
   }

///////////////////////////////////////////////////////////////////////////////////    

BOOL FAR PASCAL _export MDevDlgProc(HWND hDlg, 
                                    UINT msg,
                                    WPARAM wParam, 
                                    LPARAM lParam) {
   BOOL   fProcessed = TRUE;
   UINT   i, nitem;
   long   newItem;
   static HWND hinLBox, houtLBox;
   static long curItem = -1;
   
   switch (msg) {

      case WM_INITDIALOG:
          // Set up List boxes and Defaults
          hinLBox = GetDlgItem(hDlg, ID_INLBOX);
          SendMessage(hinLBox, LB_RESETCONTENT, 0, 0);
          for (i=0; i < wNumInDevices; i++) {
              SendMessage(hinLBox, LB_ADDSTRING, 0,
                         (LONG) (LPSTR) midiInCaps[i].szPname);
              if (hMidiIn[i] && (lpCallbackInstanceData[i] != NULL))
                 SendMessage(hinLBox, LB_SETSEL, TRUE, MAKELPARAM(i, 0));

              }
          // Do output box
          houtLBox = GetDlgItem(hDlg, ID_OUTLBOX);
          SendMessage(houtLBox, LB_RESETCONTENT, 0, 0);
          for (i=0; i < wNumOutDevices; i++) {
              SendMessage(houtLBox, LB_ADDSTRING, 0,
                         (LONG) (LPSTR) midiOutCaps[i].szPname);
              if ((wOutID == i) && hMOut && bThruOn) {
                 SendMessage(houtLBox, LB_SETCURSEL, i, 0L);
                 curItem = i;
                 }
              }
          break;

      case WM_COMMAND:
         switch (LOWORD(wParam)) {
            case IDOK:              
               nitem = 0;
               for (i=0; i < wNumInDevices; i++) {
                  if (SendMessage(hinLBox, LB_GETSEL, i, 0L)) 
                     lstrcpy(szInDev.Nm[nitem++], midiInCaps[i].szPname);
                  }
               nDevInOpen = nitem;
               if ((nitem = (UINT)SendMessage(houtLBox, LB_GETCURSEL, 0, 0L)) 
                                              != LB_ERR) { 
                   lstrcpy(szOutDevNm, midiOutCaps[nitem].szPname);
                   bThruOn = TRUE;
                   wOutID = nitem;
                   }
               else {
                   bThruOn = FALSE;
                   wOutID = (WORD)-1;
                   }
               InvalidateRect(hMainWnd, NULL, TRUE);
               EndDialog(hDlg, wParam);
               break;

            case IDCANCEL:
               EndDialog(hDlg, wParam);
               break;

            case ID_OUTLBOX:
               {
#ifdef _WIN32 // look at _this_ shit!!!
               WORD wMsg = HIWORD(wParam);
               HWND hwndLB = (HWND)lParam;
#else
               WORD wMsg = HIWORD(lParam);
               HWND hwndLB = (HWND)LOWORD(lParam);
#endif
               switch(wMsg) {
                  case LBN_SELCHANGE:
                     newItem = SendMessage(hwndLB, LB_GETCURSEL, 0, 0L);
                     if ((DWORD)newItem != LB_ERR) { // i.e. there is a selection
                        if (newItem == curItem) {      // remove selection
                           SendMessage((HWND)LOWORD(lParam), LB_SETCURSEL, (WORD)-1, 0L);
                           curItem = -1L;
                           } 
                        else           
                           curItem = newItem;
                        }
                     break;                                               
                  }
               }

            default:
               fProcessed = FALSE;
               break;
            }
         break;

      default:
         fProcessed = FALSE;
         break;
      }
   return(fProcessed);
   }

/* ====================================================================== */    
/* InitFirstInstance - Performs initializaion for the first instance 
 *      of the application.
 *
 * Params:  hInstance - Instance handle.
 *
 * Return:  Returns 1 if there were no errors.  Otherwise, returns 0.
 */
BOOL InitFirstInstance(HINSTANCE hInstance) {
    WNDCLASS wc;
    
    /* Define the class of window we want to register.
     */
    wc.lpszClassName    = szAppName;
    wc.style            = CS_HREDRAW | CS_VREDRAW;
    wc.hCursor          = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon            = LoadIcon(hInstance, "MM1");    
    wc.lpszMenuName     = "Menu";
    wc.hbrBackground    = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.hInstance        = hInstance;
    wc.lpfnWndProc      = WndProc;
    wc.cbClsExtra       = 0;
    wc.cbWndExtra       = 0;
    
    if(!RegisterClass(&wc))
        return FALSE;

    return TRUE;
}

/////////////////////////////////////////////////////////////////////////
/* DoMenuItemCheck - Checks and unchecks menu items.
 *
 * Params:  hWnd - Window handle for window associated with menu items.
 *          wMenuItem - The menu ID for the menu item.
 *          newState - The new checked/unchecked state of the menu item.
 *
 * Return:  void
*/
void DoMenuItemCheck(HWND hWnd, UINT wMenuItem, BOOL newState) {
    HMENU hMenu;
    
    hMenu = GetMenu(hWnd);
    CheckMenuItem(hMenu, wMenuItem, (newState ? MF_CHECKED: MF_UNCHECKED));
    }

/////////////////////////////////////////////////////////////////////////
// So the callback can get the instance data
LPCALLBACKINSTANCEDATA FAR PASCAL DefInstData(VOID) {
    LPCALLBACKINSTANCEDATA lpid = NULL;

    if (wDefInst != 0x0FF)
       lpid = lpCallbackInstanceData[wDefInst];
    return(lpid);
    }


/* Error - Beeps and shows an error message.
 *
 * Params:  szMsg - Points to a NULL-terminated string containing the
 *              error message.
 *
 * Return:  Returns the return value from the MessageBox() call.
 *          Since this message box has only a single button, the
 *          return value isn't too meaningful.
 */
int Error(LPSTR szMsg) {
    MessageBeep(MB_OK);
    return MessageBox(hMainWnd, szMsg, szAppName, MB_OK);
    }

/* ************************************************************************ */

void MIDIErr(MMRESULT code, LPSTR szName, BOOL in) {
    char szErrorText[256];
    char szErrorMsg[256];
    
    if (in)
       midiInGetErrorText(code, (LPSTR)szErrorText, sizeof(szErrorText));
    else
       midiOutGetErrorText(code, (LPSTR)szErrorText, sizeof(szErrorText));
    wsprintf(szErrorMsg, "%s: %s", (LPSTR)szName, (LPSTR)szErrorText);
    Error(szErrorMsg);
    }

/* ************************************************************************ */

void CenterOnParent(HWND hDlg) {
   RECT rc1, rc2;
   HWND hPar;
   
   hPar = GetParent(hDlg);
   GetClientRect(hPar, &rc1);
   ClientToScreen(hPar, (LPPOINT)&rc1.left);
   ClientToScreen(hPar, (LPPOINT)&rc1.right);
   GetWindowRect(hDlg, &rc2);
   SetWindowPos(hDlg, NULL, 
       rc1.left + (((rc1.right - rc1.left) - (rc2.right - rc2.left)) >> 1), 
       rc1.top +  (((rc1.bottom - rc1.top) - (rc2.bottom - rc2.top)) >> 1),
       0, 0, SWP_NOSIZE | SWP_NOACTIVATE);
   }

///////////////////////////////////////////////////////////////////////////

static HGLOBAL  hFiltMem   = NULL;

LPFILTER CreateFilter(void) {
    LPFILTER lpFilter;
    
    hFiltMem = GlobalAlloc(GMEM_SHARE | GMEM_MOVEABLE,
                           (DWORD)sizeof(FILTER));
    if(hFiltMem == NULL)
        return NULL;
    
    lpFilter = (LPFILTER)GlobalLock(hFiltMem);
    if(lpFilter == NULL){
       GlobalFree(hFiltMem);
       return NULL;
       }
    
    /* Page lock the memory.
     */

    GlobalPageLock((HGLOBAL)HIWORD(lpFilter));     // note: no effect for win32
    MEMSET(lpFilter, 0, sizeof(FILTER));
    return lpFilter;
    }

///////////////////////////////////////////////////////////////////////////
                                         
void DisposeFilter(LPFILTER lpFilter) {
    GlobalPageUnlock((HGLOBAL)HIWORD(lpFilter));   // no effect for win32
    GlobalUnlock(hFiltMem);
    GlobalFree(hFiltMem);
    }

///////////////////////////////////////////////////////////////////////////

COLORREF GetEventColor(WORD wType, DWORD dwData) {
   BYTE bStatus =  LOBYTE(LOWORD(dwData)) & (BYTE) 0xf0;
   BYTE bData1  =  HIBYTE(LOWORD(dwData));
   COLORREF textColor;
   
   if (wType == (WORD)DEVMSG)
      return preferences.colText;   // text

   switch(bStatus) {
      // Three byte events 
      case NOTEOFF: 
         textColor = preferences.clrNoteOff;
         break;
         
      case NOTEON:
         // A note on with a velocity of 0 is a note off
         {
         BYTE bData2  =  LOBYTE(HIWORD(dwData));
         textColor = preferences.clrNoteOn;
         if ((bStatus == NOTEON) && (bData2 == 0))
            textColor = preferences.clrNoteOff;
         }
         break;

      case KEYAFTERTOUCH:
      case CHANAFTERTOUCH:
         textColor = preferences.clrAfterT;
         break;
        
      case CONTROLCHANGE:
         textColor = preferences.clrControl;
         break;      
      
      case PITCHBEND:
         textColor = preferences.clrPitchB;
         break;      
      

      // Two byte events 
      case PROGRAMCHANGE:
         textColor = preferences.clrProgram;
         break;      

      /* MIDI system events (0xf0 - 0xff) 
       */
      case SYSTEMMESSAGE:
         textColor = preferences.clrSystem;
         break;      
            
      default:
         textColor = preferences.colText; // unknown
         break;
      }
   return textColor;
   }
