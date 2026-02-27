/*-------------------------------------------------------------------
    piano.c
    keyboard handling: hooking the keyboard for chars we want to
    be MIDI notes and controllers
-------------------------------------------------------------------*/
#include <windows.h>
#include <mmsystem.h>
#include <stdlib.h>
#include "piano.h"
#include "midimon.h"
#include "circbuf.h"
#include "syxbuf.h"
#include "filter.h"
#include "instdata.h"
#include "midimcbk.h"
#include "resource.h"

#define ID_BLINK_TIMER  3  //Timer that blinks the light

extern HWND hMainWnd;
extern HINSTANCE hInst;   //main app instance for resources
extern HHOOK hFilterHook;
extern LPCALLBACKINSTANCEDATA FAR PASCAL DefInstData(VOID);
extern HWND hActiveDlg;

BYTE cChannel = 0;        //channel to send messages on

HWND hChannelBox = NULL;  //global so keyboard hook will let channel ctrl msg through

//The #if 0 stuff takes out custom colors for the dlg
#if 0
COLORREF clDlgBkColor = RGB(128, 128, 128);   //backgound color of dialog
COLORREF clKybdDlgTextColor = RGB(192, 192, 192); //Text color of dialog
COLORREF clKybdDlgChannelBoxBkColor = RGB(192, 192, 192); //bkgnd of editbox
COLORREF clKybdDlgChannelBoxText = RGB(0, 0, 0);          //text of editbox
#endif

BOOL ProcessKeyboardCharacters(LPMSG);
void GetChannelNumber(HWND, WORD);

BOOL CALLBACK KeyboardDlgProc (HWND hDlg, UINT message, WPARAM wParam, 
                              LPARAM lParam)
{
   static HICON hIconOn;
   static HICON hIconOff;
#if 0
   static HBRUSH hDlgBkBrush;
   static HBRUSH hDlgChannelBoxBkBrush;
#endif
   static BOOL bIconOn = TRUE;
   //I know this is not necessary but it doesn't cost much and helps me keep things straight
   static HWND hKybdDlg = NULL;  
    
   switch (message) {

      case WM_INITDIALOG: {
         hKybdDlg = hDlg;
         hChannelBox = GetDlgItem(hKybdDlg, IDC_KYBD_CHANNEL);
         SetDlgItemInt(hKybdDlg, IDC_KYBD_CHANNEL, cChannel + 1, FALSE); 
#if 0
         hDlgBkBrush = CreateSolidBrush (clDlgBkColor);
         hDlgChannelBoxBkBrush = CreateSolidBrush (clKybdDlgChannelBoxBkColor);
#endif
         // just gets handle if already loaded
         hIconOn  = LoadIcon(hInst, MAKEINTRESOURCE(IDI_ON));
         hIconOff = LoadIcon(hInst, MAKEINTRESOURCE(IDI_OFF));

         // create a timer 
         SetTimer(hKybdDlg, ID_BLINK_TIMER, 500, NULL);
         return TRUE;
         //if we want to set the focus ourselves we do it and return FALSE 
         //SetFocus(GetDlgItem(hKybdDlg, IDOK));

      } //INITDIALOG
        
      case WM_TIMER:
         if (wParam == ID_BLINK_TIMER) {
#ifndef _WIN32
            //turns off timer lite if main window has input focus
            //or if app itself loses focus (no active windows)
            if(hMainWnd == GetActiveWindow() ||
               NULL == GetFocus()) {        
               if(bIconOn) {
                  SendDlgItemMessage(hKybdDlg,
                                    IDC_KYBD_LITE,
                                    STM_SETICON,
                                    (WPARAM) hIconOff,
                                    (LPARAM) 0L);
                  }
               break;
            }   
            if(bIconOn) {
                SendDlgItemMessage(hKybdDlg,
                                   IDC_KYBD_LITE,
                                   STM_SETICON,
                                   (WPARAM) hIconOff,
                                   (LPARAM) 0L);
               bIconOn = FALSE;
               }
            else {
                SendDlgItemMessage(hKybdDlg,
                                   IDC_KYBD_LITE,
                                   STM_SETICON,
                                   (WPARAM) hIconOn,
                                   (LPARAM) 0L);
               bIconOn = TRUE;
               }
            return TRUE;
#else //WIN32
            //turns off timer lite if main window has input focus
            //or if app itself loses focus (no active windows)
            if(hMainWnd == GetActiveWindow() ||
               NULL == GetActiveWindow()) {        //GetFocus == NULL ??
               if(bIconOn) {
                  SendDlgItemMessage(hKybdDlg,
                     IDC_KYBD_LITE,
                     STM_SETIMAGE,
                     (WPARAM) IMAGE_ICON,
                     (LPARAM) hIconOff);
                  }
               break;
               }   
            if(bIconOn) {
               SendDlgItemMessage(hKybdDlg,  // dialog box window handle  
                  IDC_KYBD_LITE,             // icon identifier 
                  STM_SETIMAGE,              // message to send
                  (WPARAM) IMAGE_ICON,       // image type 
                  (LPARAM) hIconOff);        // new icon handle
               bIconOn = FALSE;
               }
            else {
               SendDlgItemMessage(hKybdDlg,  // dialog box window handle  
                  IDC_KYBD_LITE, //IDI_ON    // icon identifier 
                  STM_SETIMAGE,              // message to send
                  (WPARAM) IMAGE_ICON,       // image type 
                  (LPARAM) hIconOn);         // new icon handle
               bIconOn = TRUE;
               }
            return TRUE;
#endif
         } //BLINK_TIMER
         break; //TIMER
#if 0         
 #ifndef _WIN32
      case WM_CTLCOLOR:
         switch(HIWORD(lParam)) {
            case CTLCOLOR_EDIT:

               SetTextColor((HDC) wParam, clKybdDlgChannelBoxText);
               SetBkColor((HDC) wParam, clKybdDlgChannelBoxBkColor);
               return (LRESULT)hDlgChannelBoxBkBrush;

            case CTLCOLOR_MSGBOX:
               // For single-line edit controls, this code must be
               // processed so that the background color of the format
               // rectangle will also be painted with the new color.
               return (LRESULT)hDlgChannelBoxBkBrush;
             
            case CTLCOLOR_DLG:
            case CTLCOLOR_STATIC:
               SetBkColor((HDC) wParam, clDlgBkColor);
               SetTextColor((HDC) wParam, clKybdDlgTextColor);
               return (LRESULT)hDlgBkBrush;

            default:
               break;
         }
 #endif  //CTLCOLOR for 16 bit
    
 #ifdef _WIN32    
      case WM_CTLCOLORSTATIC: 
      case WM_CTLCOLORDLG:
         SetBkColor((HDC) wParam, clDlgBkColor);
         SetTextColor((HDC) wParam, clKybdDlgTextColor);
         return (LRESULT)hDlgBkBrush;

      case WM_CTLCOLOREDIT:
      case WM_CTLCOLORMSGBOX:
         SetTextColor((HDC) wParam, clKybdDlgChannelBoxText);
         SetBkColor((HDC) wParam, clKybdDlgChannelBoxBkColor);
         return (LRESULT)hDlgChannelBoxBkBrush;
 #endif
      case WM_PAINT: {
         RECT rect;
         PAINTSTRUCT ps;
         HDC hdc;

         if(GetUpdateRect(hKybdDlg, NULL, FALSE)) {
            hdc = BeginPaint (hKybdDlg, &ps);
            GetClientRect (hKybdDlg, &rect);
            FillRect (hdc, &rect, hDlgBkBrush);

            EndPaint (hKybdDlg, &ps);
            return TRUE;
            }
         break;
      } //PAINT
#endif
    
      case WM_COMMAND: {
         WORD wId;
         WORD wCmd;
         HWND hwndChild;

 #ifdef _WIN32
         wId = LOWORD(wParam);
         wCmd = HIWORD(wParam);
         hwndChild = (HWND)(UINT)lParam;
 #else
         wId = wParam;
         wCmd = HIWORD(lParam);
         hwndChild = (HWND)LOWORD(lParam);
 #endif        
    
         switch (wId) {
            case IDOK:
            case IDCANCEL:
               PostMessage(hKybdDlg, WM_CLOSE, 0, 0L); 
               return TRUE;
            case IDC_KYBD_CHANNEL:
               if(wCmd == EN_CHANGE) {
                  GetChannelNumber(hKybdDlg, wId);
                  return TRUE;
                  }
         }
         break;
      }  //COMMAND

      case WM_CLOSE:
         KillTimer(hKybdDlg, ID_BLINK_TIMER);
         // The documentation says that you should call DestroyIcon()
         // for icons loaded via LoadIcon().  Apparently that is wrong -- you
         // need only call DestroyIcon() for icons created with CreateIcon().  
         // Reference: Microsoft Knowledge Base article Q84779 
         // I'd prefer not to destroy them here if the system will clean up
         // as they may also be loaded somewhere else.
         //DestroyIcon(hLedOn);
         //DestroyIcon(hLedOff);
#if 0
         DeleteObject (hDlgBkBrush);
         DeleteObject (hDlgChannelBoxBkBrush);
#endif
         PostMessage(hMainWnd, MM_SUICIDE, WM_DESTROY,
                        MAKELONG(hKybdDlg, 0));
         return TRUE;

      case WM_ACTIVATE:
#ifndef _WIN32
         if (0 == wParam)             // becoming inactive
            hActiveDlg = NULL;
         else                         // becoming active
            hActiveDlg = hKybdDlg;
#else
         if(LOWORD(wParam) == WA_INACTIVE)
            hActiveDlg = NULL;
         else
            hActiveDlg = hKybdDlg;
#endif
         return TRUE;


   }  // End message switch
   return FALSE;
}

/*-------------------------------------------------------------------
   GetChannelNumber(HWND, WORD)
-------------------------------------------------------------------*/

void GetChannelNumber(HWND hKybdDlg, WORD wCtrlID)
{
   UINT nChannel;
   BOOL bOK;
   BOOL fCorrected = FALSE;
   
   nChannel = GetDlgItemInt(hKybdDlg, wCtrlID, &bOK, FALSE);
   if(bOK) {
      if((nChannel > 16) || (nChannel < 1)) {
         nChannel = 1;
         fCorrected = TRUE;
      }
   }
   else {
      nChannel = 1;
      fCorrected = TRUE;
   }

   cChannel = (BYTE)(nChannel -1);
  
   if (fCorrected)
      // send the changed data to the edit control
      SetDlgItemInt(hKybdDlg, wCtrlID, nChannel, FALSE);
   
   SetFocus(GetDlgItem(hKybdDlg, IDOK));
}


/*-------------------------------------------------------------------
   KeyboardHookProc intercepts dialog messages and determines if
   they are key up or key down messages that should be sent on
   to ProcessKeyboardCharacters for interpretation.

   This function must be EXPORTED in the .def file. (16 bit)
-------------------------------------------------------------------*/

LRESULT CALLBACK KeyboardHookProc(int nCode, WPARAM wParam, LPMSG lpMsg)
{
    // by the book
    if (nCode < 0)
       return CallNextHookEx(hFilterHook, nCode, wParam, (LONG)lpMsg);

    switch (nCode)
    {
        case MSGF_DIALOGBOX:
            //let channel box get kybd input
            if(hChannelBox == lpMsg->hwnd)
                break;
            
            // only interested in key presses and releases
            if ((lpMsg->message == WM_KEYDOWN) ||
                (lpMsg->message == WM_KEYUP))
            {
                if ((lpMsg->message == WM_KEYDOWN) &&
                    (lpMsg->wParam == VK_F1))    //non-zero means already down
                    {
                    //It's irritating that -1 is a valid parameter
                    //yet the function is prototyped as a UINT
                    MessageBeep((UINT)-1);       // for future help implementation
                    return 1;
                    }

                // if ALT or CTRL keys were depressed skip processing    
                if (((lpMsg->lParam & 0x20000000) != 0) ||  //non-zero means ALT key
                    (GetKeyState(VK_CONTROL) < 0))       //Negative means CTRL key
                    break;
                     
                //check for our keyboard chars
                if (ProcessKeyboardCharacters(lpMsg))
                    return TRUE;
                else
                    break;
            }
        
        case MSGF_MENU:
           //TRACE("Hook Proc MENU\n");
           break;

        case MSGF_NEXTWINDOW:
           // This might have been of some value to us but it doesn't work! (Never called)
           // See Jeffrey Richter "Windows 95".
           //TRACE("Hook Proc NEXTWINDOW\n");
           break;

        default:
            break;
            
    }
    return CallNextHookEx(hFilterHook, nCode, wParam, (LONG)lpMsg);
}

/*-------------------------------------------------------------------
    ProcessKeyboardCharacters
-------------------------------------------------------------------*/

BOOL ProcessKeyboardCharacters(LPMSG lpMsg)
{
    UINT uMidiNote;
    BYTE cStatus;
    //BYTE cChannel = 0;
    int cData1;
    int cData2;
    static UINT uOctave;
    static BOOL OctaveHasBeenSet;
    static int nModWheel;
    static int nPitchWheel = 64;
    static int nVelocity = 100;
    UINT uCode;
    
    //special keys
    if (lpMsg->wParam >= VK_PRIOR && lpMsg->wParam < VK_HELP)
    {
        if (lpMsg->message == WM_KEYDOWN)  //skip KEY_UP
        {
            switch (lpMsg->wParam)
            {
            case VK_LEFT:                  //Modulation down
                if (nModWheel == 0)
                    break;
                if (lpMsg->message == WM_KEYDOWN)
                {
                    cStatus = MIDI_CONTROL_CHANGE;
                    if(nModWheel == 127)
                       nModWheel = 112;
                    else {
                       nModWheel = nModWheel - 16;
                       if(nModWheel < 0)
                          nModWheel = 0;
                       }
                    SendShortMessage(cStatus, cChannel, MIDI_MOD_WHEEL,
                                        (BYTE)(nModWheel));
                }
                break;
            
            case VK_UP:                    //Pitch Wheel up
                if (nPitchWheel == 127)
                    break;
                if (lpMsg->message == WM_KEYDOWN)
                {
                    cStatus = MIDI_PITCH_WHEEL;
                    nPitchWheel = nPitchWheel + 8;
                    if (nPitchWheel > 127)
                        nPitchWheel = 127;
                    SendShortMessage(cStatus, cChannel, 0, (BYTE)nPitchWheel);
                }
                break;
            
            case VK_RIGHT:                 //Modulation up
                if (nModWheel == 127)
                    break;
                if (lpMsg->message == WM_KEYDOWN)
                {
                    cStatus = MIDI_CONTROL_CHANGE;
                    nModWheel = nModWheel + 16;
                    if (nModWheel > 127)
                        nModWheel = 127;
                    SendShortMessage(cStatus, cChannel, MIDI_MOD_WHEEL,
                                            (BYTE)(nModWheel));
                }
                break;
            
            case VK_DOWN:                  //Pitch Wheel down
                if (nPitchWheel == 0)
                    break;
                if (lpMsg->message == WM_KEYDOWN)
                {
                    cStatus = MIDI_PITCH_WHEEL;
                    if(nPitchWheel == 127)
                       nPitchWheel = 120;
                    else {
                       nPitchWheel = nPitchWheel - 8;
                       if(nPitchWheel < 0)
                          nPitchWheel = 0;
                       }
                    SendShortMessage(cStatus, cChannel, 0, (BYTE)nPitchWheel);
                }
                break;
            
            case VK_END:                   //Center pitch wheel
                if (nPitchWheel == 64)
                    break;
                cStatus = MIDI_PITCH_WHEEL;
                nPitchWheel = 64;
                SendShortMessage(cStatus, cChannel, 0, (BYTE)nPitchWheel);
                break;
            
            case VK_PRIOR:                 //Velocity up
                if (nVelocity == 127)
                    break;
                if (lpMsg->message == WM_KEYDOWN)
                {
                    nVelocity = nVelocity + 4;
                    if (nVelocity > 127)
                        nVelocity = 127;
                }
                break;
            
            case VK_NEXT:                  //Velocity down
                if (nVelocity == 0)
                    break;
                if (lpMsg->message == WM_KEYDOWN)
                {
                    if(nVelocity == 127)
                       nVelocity = 124;
                    else {
                       nVelocity = nVelocity - 4;
                       if(nVelocity < 0)
                          nVelocity = 0;
                       }
                }
                break;
            
            case VK_HOME:                  //Panic stop
                if (lpMsg->message == WM_KEYDOWN)
                {
                    cStatus = MIDI_CONTROL_CHANGE;
                    SendShortMessage(cStatus, cChannel, MIDI_ALL_NOTES_OFF,
                                        (BYTE)0);
                    SendShortMessage(cStatus, cChannel, MIDI_RESET_ALL_CONTROLLERS,
                                        (BYTE)0);
                    SendShortMessage(cStatus, cChannel, MIDI_SUSTAIN,
                                        (BYTE)0);
                }
                break;
            
            default:
                break;
            }
            return TRUE;
        }
        return TRUE;
    }
    
    // For all the rest of these messages
    // if it's a key down check the previous state bit and
    // don't send another message if the key was already down.
    if ((lpMsg->message == WM_KEYDOWN) &&
       ((lpMsg->lParam & 0x40000000) != 0))    //non-zero means already down
        return TRUE;
            
    if (lpMsg->wParam == VK_SHIFT)
    {   
        cStatus = MIDI_CONTROL_CHANGE;
        if (lpMsg->message == WM_KEYDOWN)
            SendShortMessage(cStatus, cChannel, MIDI_SUSTAIN,
                                        (BYTE)127);
        else
            SendShortMessage(cStatus, cChannel, MIDI_SUSTAIN,
                                        (BYTE)0);
        return TRUE;
    }
    
    //F2-F9 are used to set the octave
    if (lpMsg->wParam > VK_F1 && lpMsg->wParam < VK_F10)
        switch (lpMsg->wParam)
        {
            case VK_F2:
                uOctave = 0;
                OctaveHasBeenSet = TRUE;
                return TRUE;
                 
            case VK_F3:
                uOctave = 1;
                OctaveHasBeenSet = TRUE;
                return TRUE;
                 
            case VK_F4:
                uOctave = 2;
                OctaveHasBeenSet = TRUE;
                return TRUE;
                 
            case VK_F5:
                uOctave = 3;
                OctaveHasBeenSet = TRUE;
                return TRUE;
                 
            case VK_F6:
                uOctave = 4;
                OctaveHasBeenSet = TRUE;
                return TRUE;
                 
            case VK_F7:
                uOctave = 5;
                OctaveHasBeenSet = TRUE;
                return TRUE;
                 
            case VK_F8:
                uOctave = 6;
                OctaveHasBeenSet = TRUE;
                return TRUE;
                 
            case VK_F9:
                uOctave = 7;
                OctaveHasBeenSet = TRUE;
                return TRUE;
                
            default:
                return TRUE;
        }
    // we map here because not all the keys we want to
    // use have VK codes
    uCode = MapVirtualKey((UINT)lpMsg->wParam, 2);
    
    switch (uCode)
    {
        case 'Z':
            uMidiNote=0;
            break;

        case 'S':
            uMidiNote=1;
            break;

        case 'X':
            uMidiNote=2;
            break;

        case 'D':
            uMidiNote=3;
            break;

        case 'C':
            uMidiNote=4;
            break;

        case 'V':
            uMidiNote=5;
            break;

        case 'G':
            uMidiNote=6;
            break;

        case 'B':
            uMidiNote=7;
            break;

        case 'H':
            uMidiNote=8;
            break;

        case 'N':
            uMidiNote=9;
            break;

        case 'J':
            uMidiNote=10;
            break;

        case 'M':
            uMidiNote=11;
            break;
        
        case ',':
            uMidiNote=12;
            break;
        
        case 'Q':
            uMidiNote=12;
            break;

        case '2':
            uMidiNote=13;
            break;

        case 'W':
            uMidiNote=14;
            break;

        case '3':
            uMidiNote=15;
            break;

        case 'E':
            uMidiNote=16;
            break;

        case 'R':
            uMidiNote=17;
            break;

        case '5':
            uMidiNote=18;
            break;

        case 'T':
            uMidiNote=19;
            break;

        case '6':
            uMidiNote=20;
            break;

        case 'Y':
            uMidiNote=21;
            break;

        case '7':
            uMidiNote=22;
            break;

        case 'U':
            uMidiNote=23;
            break;
        
        case 'I':
            uMidiNote=24;
            break;
        
        case '9':
            uMidiNote=25;
            break;

        case 'O':
            uMidiNote=26;
            break;

        case '0':
            uMidiNote=27;
            break;

        case 'P':
            uMidiNote=28;
            break;

        case '[':
            uMidiNote=29;
            break;
        
        case '=':
            uMidiNote=30;
            break;
        
        case ']':
            uMidiNote=31;
            break;
        
        case 'L':
            uMidiNote=13;
            break;

        case '.':
            uMidiNote=14;
            break;

        case ';':
            uMidiNote=15;
            break;
        
        case '/':
            uMidiNote=16;
            break;
        
        default:
            // A code within this range means the user
            // hit a key that is not valid (or it would
            // have been trapped above). We return TRUE
            // to keep the default handler from beeping
            // at us.
            if (uCode > 0x2B && uCode < 0x5E)
                return TRUE;
            else
                return FALSE;
            
    }    
            
    cStatus = MIDI_NOTE_ON;
    
    if (!OctaveHasBeenSet)
        uOctave = 4;      
    
    cData1 = (uMidiNote + (uOctave * 12));  //MIDI note number
    if (cData1 > 127)     //Just a safety valve; should not happen
        cData1 = 127;    
    
    if (lpMsg->message == WM_KEYUP)
        cData2 = 0;          // 0 velocity turns note off
    else
        cData2 = nVelocity;   
    
    SendShortMessage(cStatus, cChannel, (BYTE)cData1, (BYTE)cData2);
     
    return TRUE;
}

void SendShortMessage(BYTE cStatus, BYTE cChannel, BYTE cData1, BYTE cData2)
{
   LPCALLBACKINSTANCEDATA lpid;

   lpid = DefInstData();
   if (lpid == NULL)
      return;
   
   midiMonEvent(lpid, (WORD)cStatus, (WORD)cChannel,
                      (WORD)cData1,  (WORD)cData2);
}