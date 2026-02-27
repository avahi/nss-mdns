#include <windows.h>
#include <mmsystem.h>
#include "midimon.h"
#include "circbuf.h"
#include "syxbuf.h"
#include "filter.h"
#include "instdata.h"
#include "mscroll.h"
#include "midimcbk.h"
#include "spinedit.h"

typedef struct tagEVITEM {
    char Str[16];
    WORD Code;
    } EVITEM;
    
#define MAXEVENTS  26
#define BENDRANGE  128
#define PATCH      129

const EVITEM Event[] = {
    { "Patch Change",  PATCH },
    { "Bank Change MSB",  0 },
    { "Bank Change LSB", 32 },
    { "Modulation",       1 },            
    { "Volume",           7 },
    { "PAN",             10 },
    { "Reverb Depth",    91 },
    { "Tremolo Depth",   92 },        
    { "Chorus Depth",    93 },
    { "Bend Range",      BENDRANGE },
    { "Hold Pedal",      64 },
    { "NRP LSB",         98 },
    { "NRP MSB",         99 },        
    { "Data Entry MSB",   6 },
    { "Data Entry LSB",  38 },        
    { "RPN LSB",        100 },
    { "RPN MSB",        101 },        
    { "Data Increment",  96 },
    { "Data Decrement",  97 },        
    { "Reset Cntrl",    121 },
    { "Local Cntrl",    122 },
    { "All Notes Off",  123 },                
    { "Omni Off",       124 },        
    { "Omni On",        125 },        
    { "Mono On",        126 },        
    { "Poly On",        127 }};                

LPCALLBACKINSTANCEDATA FAR PASCAL DefInstData(VOID);
VOID SendMIDIEvent(WORD wChan, WORD wEvnt, WORD wVal);
VOID SendAllOff( VOID );

extern HWND hMainWnd;
extern HINSTANCE hInst;
extern HWND hActiveDlg;

static WORD wCChan = 0;
static WORD wCMSel = 0;
static WORD wCVal  = 0;
static BOOL bCAuto = TRUE;

BOOL FAR PASCAL _export CtlPnl(HWND hDlg, UINT msg,
                               WPARAM wParam, LPARAM lParam) {
        BOOL   fProcessed = TRUE;
        UINT   i, nitem;
        WORD   wChan, wEvnt, wVal;
        BOOL   bTranslated = FALSE;
        static HWND hEventBox = NULL;

   switch(msg) {
      case WM_INITDIALOG:
                  // Set up List boxes and Defaults
          if (!SetupSpinEdit(hDlg, hInst, ID_CHANNEL, ID_CHANSPIN, 1, 16, 
                             (WORD)(wCChan+1), FALSE))
              break;
          if (!SetupSpinEdit(hDlg, hInst, ID_VALUE, ID_VALSPIN, 0, 127, 
                             wCVal, TRUE))
              break;

          hEventBox = GetDlgItem(hDlg, ID_EVENTBOX);
          SendMessage(hEventBox, CB_RESETCONTENT, 0, 0);
          for (i=0; i < MAXEVENTS; i++) {
              SendMessage(hEventBox, CB_ADDSTRING, 0,
                          (LONG)(LPSTR) Event[i].Str);
              }
          SendMessage(hEventBox, CB_SETCURSEL, wCMSel, 0L);
          CheckDlgButton(hDlg, ID_AUTOSEND, bCAuto);
          break;
        
      case MSM_NOTIFY:
          if (!IsDlgButtonChecked(hDlg, ID_AUTOSEND))
             break;
          wParam = ID_SEND; // Fall through for efficiency
         
      case WM_COMMAND:
         switch (wParam) {

             case ID_SEND:
                if ((nitem = (UINT)SendMessage(hEventBox, 
                                  CB_GETCURSEL, 0, 0L)) != CB_ERR) {
                   wEvnt = Event[nitem].Code;
                   wChan = GetDlgItemInt(hDlg, ID_CHANNEL, 
                                         &bTranslated, FALSE) - 1;
                   wVal  = GetDlgItemInt(hDlg, ID_VALUE, &bTranslated, FALSE);
                   wChan &= 0x0F;
                   wVal  &= 0x7F;
                   SendMIDIEvent(wChan, wEvnt, wVal);
                   }
                break;

             case IDCANCEL:
                PostMessage(hDlg, WM_CLOSE, 0, 0L); 
                break;

             case ID_PANIC:
                SendAllOff();
                break;

                default:
                fProcessed = FALSE;
                break;
             }
         break;

    case WM_CLOSE:
         wCMSel = (WORD)SendMessage(hEventBox, CB_GETCURSEL, 0, 0L);
         wCChan = GetDlgItemInt(hDlg, ID_CHANNEL, 
                                         &bTranslated, FALSE) - 1;
         wCVal  = GetDlgItemInt(hDlg, ID_VALUE, &bTranslated, FALSE);
         wCChan &= 0x0F;
         wCVal  &= 0x7F;
         bCAuto = IsDlgButtonChecked(hDlg, ID_AUTOSEND) ? TRUE : FALSE;
         PostMessage(hMainWnd, MM_SUICIDE, WM_DESTROY,
                                    MAKELONG(hDlg, IDM_CTLDLG));
                 break;

    case WM_ACTIVATE:
#ifndef _WIN32
         if (0 == wParam)             // becoming inactive
            hActiveDlg = NULL;
         else                         // becoming active
            hActiveDlg = hDlg;
#else //WIN32
         if(LOWORD(wParam) == WA_INACTIVE)
            hActiveDlg = NULL;
         else 
            hActiveDlg = hDlg;
#endif
         return TRUE;

     default:
         fProcessed = FALSE;
                 break;
     }
   return(fProcessed);
   }

///////////////////////////////////////////////////////////////

VOID SendMIDIEvent(WORD wChan, WORD wEvnt, WORD wVal) {
        LPCALLBACKINSTANCEDATA lpid;

    lpid = DefInstData();
    if (lpid == NULL)
        return;

    if (wEvnt < 128) 
        midiMonEvent(lpid, MC_CONTROLLER, wChan, wEvnt, wVal);
    else if (wEvnt == PATCH)
        midiMonEvent(lpid, MC_PATCHCHANGE, wChan, wVal, 0);    
    else if (wEvnt == BENDRANGE) {
        midiMonEvent(lpid, MC_CONTROLLER, wChan, MCV_RPNMSB, 0);
        midiMonEvent(lpid, MC_CONTROLLER, wChan, MCV_RPNLSB, 0);
        midiMonEvent(lpid, MC_CONTROLLER, wChan, MCV_DATAMSB, wVal);        
        midiMonEvent(lpid, MC_CONTROLLER, wChan, MCV_DATALSB, 0);        
        }

    return;
    }    

///////////////////////////////////////////////////////////////

VOID SendAllOff() {
    int ii, jj;
    LPCALLBACKINSTANCEDATA lpid;

    lpid = DefInstData();
    if (lpid == NULL)
        return;
    
    for (ii = 15; ii >= 0; --ii) { // do each channel
        midiMonEvent(lpid, MC_CONTROLLER, (WORD)ii, MCV_ALLOFF, 0);        
        midiMonEvent(lpid, MC_PITCHBEND,  (WORD)ii, 0x00, 0x40);
        midiMonEvent(lpid, MC_CONTROLLER, (WORD)ii, MCV_SUSTPEDAL, 0);        
        midiMonEvent(lpid, MC_CONTROLLER, (WORD)ii, MCV_MODWHEEL,  0);
        midiMonEvent(lpid, MC_CONTROLLER, (WORD)ii, MCV_RESETCTL,  0);        
        for (jj = 127; jj >= 0; --jj) {
            midiMonEvent(lpid, MC_NOTEOFF, (WORD)ii, (WORD)jj, 0);
            }
        }
    
    return;
    }
