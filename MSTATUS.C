#include <windows.h>
#include <mmsystem.h>
#include "midimon.h"
#include "circbuf.h"
#include "syxbuf.h"
#include "filter.h"
#include "instdata.h"
#include "mstatus.h"

const char szNA[] = " "; // blank

extern HWND hMainWnd;
extern HWND hMStat;
extern HINSTANCE hInst;
extern HWND hActiveDlg;

static MIDISTATE PrmSt =   // Tracks the permanent MIDI state
      {  -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1
      };

static MIDISTATE TrkSt; 

// Registered Parameter Number
static short wParm[16] = {-1, -1, -1, -1, -1, -1, -1, -1, 
                          -1, -1, -1, -1, -1, -1, -1, -1};

// Non Registered Parameter Number
static short wParmNon[16] = {-1, -1, -1, -1, -1, -1, -1, -1, 
                             -1, -1, -1, -1, -1, -1, -1, -1};

// Parameter Value
static WORD wBndRVal[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

// Reg Parm reception Flags
static PARMFLAG rcv[16]  = {{ 0, 0, 0, 0, 0 }, { 0, 0, 0, 0, 0 },
                            { 0, 0, 0, 0, 0 }, { 0, 0, 0, 0, 0 },
                            { 0, 0, 0, 0, 0 }, { 0, 0, 0, 0, 0 },
                            { 0, 0, 0, 0, 0 }, { 0, 0, 0, 0, 0 },
                            { 0, 0, 0, 0, 0 }, { 0, 0, 0, 0, 0 },
                            { 0, 0, 0, 0, 0 }, { 0, 0, 0, 0, 0 },
                            { 0, 0, 0, 0, 0 }, { 0, 0, 0, 0, 0 },
                            { 0, 0, 0, 0, 0 }, { 0, 0, 0, 0, 0 }};  
    
// Routines

static BOOL isRPNBend(WORD wChan);
static void setParm(short which, WORD wChan, short nData);
static void dataEntry(short which, WORD wChan, short nData);
static void dataIncr(WORD wChan, short nData);
static void dataDecr(WORD wChan, short nData);
static void UpdateDisplay(HWND hDlg);
static void UpdateParm(HWND hDlg, WORD wChan, WORD wParm); 
static int  SetDItem(HWND hDlg, UINT ID, int nVal);
static void QAdd(BYTE bChan, BYTE bParm);
static BOOL QGet(WORD *wChan, WORD *wParm);

///////////////////////////////////
// Update Parm Queue
#define QSIZE  128

static int qIn  = 0;
static int qOut = 0;

static struct {   // circular queue
   BYTE bChan;
   BYTE bParm;
   } q[QSIZE];

///////////////////////////////////

void QAdd(BYTE bChan, BYTE bParm) 
{
   if (++qIn == qOut) { // full => bump tail
      if (++qOut >= QSIZE)
         qOut = 1;
      }
   if (qIn >= QSIZE)
      qIn = 0;
   q[qIn].bChan = bChan;
   q[qIn].bParm = bParm;
   }

///////////////////////////////////

BOOL QGet(WORD *wChan, WORD *wParm) 
{
   if (qOut == qIn)  // empty! 
      return FALSE;

   if (++qOut >= QSIZE)
      qOut = 0;
   *wChan = (WORD)q[qOut].bChan;
   *wParm = (WORD)q[qOut].bParm;
   return TRUE;
   }

///////////////////////////////////////////////////////////////
//
BOOL isRPNBend(WORD wChan) 
{
   return ((RPN == rcv[wChan].nLast) && (BENDRNG == wParm[wChan]));
   }

///////////////////////////////////////////////////////////////
// This clears all the arrays
void FAR PASCAL ResetMStatus(void) 
{
   int ii;

   for (ii = 0; ii < 16; ++ii) { // run through all MIDI channels
      wParm[ii]     = -1;
      wParmNon[ii]  = -1;
      wBndRVal[ii]  = 0;
      rcv[ii].bLSB  = 0;
      rcv[ii].bMSB  = 0;
      rcv[ii].bLSBn = 0;
      rcv[ii].bMSBn = 0;
      rcv[ii].nLast = 0;
      TrkSt.Chan[ii].nPatch   = 0;     // Program change
      TrkSt.Chan[ii].nVol     = 0;     // Volume
      TrkSt.Chan[ii].nPan     = 0;     // Panning L-R value
      TrkSt.Chan[ii].nBend    = 0;     // Pitch Bend
      TrkSt.Chan[ii].nRange   = 0;     // Signed Bend Range
      TrkSt.Chan[ii].nMod     = 0;     // Modulation
      TrkSt.Chan[ii].nReverb  = 0;     // External effects
      TrkSt.Chan[ii].nChorus  = 0;     // Chorus effect
      TrkSt.Chan[ii].nPedal   = 0;     // Pedal sustain
      PrmSt.Chan[ii].nPatch   = -1;    // Program change
      PrmSt.Chan[ii].nVol     = -1;    // Volume
      PrmSt.Chan[ii].nPan     = -1;    // Panning L-R value
      PrmSt.Chan[ii].nBend    = -1;    // Pitch Bend
      PrmSt.Chan[ii].nRange   = -1;    // Signed Bend Range
      PrmSt.Chan[ii].nMod     = -1;    // Modulation
      PrmSt.Chan[ii].nReverb  = -1;    // External effects
      PrmSt.Chan[ii].nChorus  = -1;    // Chorus effect
      PrmSt.Chan[ii].nPedal   = -1;    // Pedal sustain
      }
   }

///////////////////////////////////////////////////////////////
// This analyzes the MIDI Event and updates the Permanent state
// structure.  

BOOL FAR PASCAL UpdateMStatus(LPEVENT lpEvent) 
{
   BYTE  bStatus, bStatusRaw, bChannel, bData1, bData2;
   BYTE  bParm = 0;
   BOOL  fDoStat = FALSE;
   
   bStatusRaw  =  LOBYTE(LOWORD(lpEvent->data));
   bStatus     =  bStatusRaw & (BYTE) 0xF0;
   bChannel    =  bStatusRaw & (BYTE) 0x0F;
   bData1      =  HIBYTE(LOWORD(lpEvent->data));
   bData2      =  LOBYTE(HIWORD(lpEvent->data));

   switch(bStatus) {
      case NOTEOFF:  // Not interested in these (right now)
      case NOTEON:
      case KEYAFTERTOUCH:
      case CHANAFTERTOUCH:
         break;

      // Patch Change
      case PROGRAMCHANGE:
         PrmSt.Chan[bChannel].nPatch = bData1;
         bParm = PPATCH;
         break;

      // Lots of these
      TODO()
      // Should add support for Bank...
      // Reset Controllers
      case CONTROLCHANGE:
         switch(bData1) {
            case CCVOLUME:
               PrmSt.Chan[bChannel].nVol = bData2;
               bParm = PVOLUME;
               break;

            case CCPAN:
               PrmSt.Chan[bChannel].nPan = bData2;
               bParm = PPAN;
               break;

            case CCMODULATION:
               PrmSt.Chan[bChannel].nMod = bData2;
               bParm = PMOD;
               break;

            case CCREVERB:
               PrmSt.Chan[bChannel].nReverb = bData2;
               bParm = PREVERB;
               break;

            case CCCHORUS:
               PrmSt.Chan[bChannel].nChorus = bData2;
               bParm = PCHORUS;
               break;

            case CCPEDAL:
               PrmSt.Chan[bChannel].nPedal = bData2;
               bParm = PPEDAL;
               break;

            // Non-Registered Parameters
            case CCNRPNMSB:
               setParm(NMSB, bChannel, bData2);
               break;

            case CCNRPNLSB:
               setParm(NLSB, bChannel, bData2);
               break;

            // Registered Parameters
            case CCRPNMSB:
               setParm(MSB, bChannel, bData2);
               break;

            case CCRPNLSB:
               setParm(LSB, bChannel, bData2);
               break;
               
            // Data entry (for RPN)
            case CCDEMSB:
               dataEntry(MSB, bChannel, bData2);
               if (isRPNBend(bChannel)) {
                  PrmSt.Chan[bChannel].nRange = 
                        (wBndRVal[bChannel] >> 7) & 0x7F;
                  bParm = PRANGE;
                  }
               break;

            case CCDELSB:
               dataEntry(LSB, bChannel, bData2);
               if (isRPNBend(bChannel)) {
                  PrmSt.Chan[bChannel].nRange = 
                        (wBndRVal[bChannel] >> 7) & 0x7F;
                  bParm = PRANGE;
                  }
               break;

            // Data increment (for RPN)
            case CCINCR:
               dataIncr(bChannel, bData2);
               if (isRPNBend(bChannel)) {
                  PrmSt.Chan[bChannel].nRange = 
                        (wBndRVal[bChannel] >> 7) & 0x7F;
                  bParm = PRANGE;
                  }
               break;

            // Data decrement
            case CCDECR:
               dataDecr(bChannel, bData2);
               if (isRPNBend(bChannel)) {
                  PrmSt.Chan[bChannel].nRange = 
                        (wBndRVal[bChannel] >> 7) & 0x7F;
                  bParm = PRANGE;
                  }
               break;

            default:
               break;
            }
         break;

      case PITCHBEND:
         // msb is shifted by 7 because we've redefined the MIDI pitch bend
         // range of 0 - 0x7f7f to 0 - 3fff by concatenating the two
         // 7-bit values in msb and lsb together
         PrmSt.Chan[bChannel].nBend = (int)(((WORD)bData2) << 7) | bData1;
         bParm = PBEND;
         break;
           
      default:
         break;
      }

   // Insert into display queue 
   // These are pulled out by the window proc
   if (bParm && hMStat) {
      QAdd(bChannel, bParm);
      fDoStat = TRUE;
      }
      
   return fDoStat;
   }    

///////////////////////////////////////////////////////////////
// Registered Parameter Routines
///////////////////////////////////////////////////////////////
// Select the Registered Parameter Number.  The Number is not selected
// initially, until both the MSB and LSB have been recieved.

static void setParm(short which, WORD wChan, short nData) 
{
    nData &= 0x07F;                          // ensure byte size

    switch( which ) {
        case LSB:
            wParm[wChan]    &= 0x03F80;      // retain only upper byte
            wParm[wChan]    |= nData;        // insert LSB
            rcv[wChan].bLSB  = 1;
            rcv[wChan].nLast = (1 == rcv[wChan].bMSB) ? RPN : 0;
            break;

        case MSB:
            wParm[wChan]    &= 0x07F;        // retain only lower 7 bits
            wParm[wChan]    |= (nData << 7); // insert MSB in top byte
            rcv[wChan].bMSB  = 1;
            rcv[wChan].nLast = (1 == rcv[wChan].bLSB) ? RPN : 0;
            break;

        case NLSB:
            wParmNon[wChan] &= 0x03F80;      // retain only upper byte
            wParmNon[wChan] |= nData;        // insert LSB
            rcv[wChan].bLSBn = 1;
            rcv[wChan].nLast = (1 == rcv[wChan].bMSBn) ? NRPN : 0;
            break;

        case NMSB:
            wParmNon[wChan] &= 0x07F;        // retain only lower 7 bits
            wParmNon[wChan] |= (nData << 7); // insert MSB in top byte
            rcv[wChan].bMSBn = 1;
            rcv[wChan].nLast = (1 == rcv[wChan].bLSBn) ? NRPN : 0;
            break;
        }
    }

//////////////////////////////////////////////////////////////////////
// The Data Entry controller value causes the value to be sent to the
// Sound IPD if a Param has been selected

static void dataEntry(short which, WORD wChan, short nData) 
{
   nData &= 0x07F;             // ensure byte size

   switch( rcv[wChan].nLast ) { 
      case RPN:
         switch( wParm[wChan] ) {
            case BENDRNG:
               switch( which ) {
                  case LSB:
                     wBndRVal[wChan] &= 0x03F80;    // retain only upper byte
                     wBndRVal[wChan] |= nData;      // insert LSB
                     break;

                  case MSB:
                     wBndRVal[wChan] &= 0x07F;        // retain only lower 7 bits
                     wBndRVal[wChan] |= (nData << 7); // insert MSB in top 7 bits
                     break;

                  default:
                     break;
                  }  // which
               break;

            default: // not currently handling others
               break;
            }        // wParm[wChan]
         break;

      case NRPN:        // non-registered parms
#if 0         
         switch( wParmNon[wChan] ) {
            default: // this is where we'd handle them
               break;
            }
#endif         
         break;

      default:
         break;
      }                 // rcv[wChan].nLast
   }

///////////////////////////////////////////////////////////////
// The Data Increment controller value causes the incremented value to be
// sent to the Sound IPD if a Param has been selected

static void dataIncr(WORD wChan, short nData) 
{
   nData &= 0x07F;             // ensure byte size

   if (isRPNBend(wChan)) {    // if last was RPN Bend Range
       wBndRVal[wChan] += nData;
       }
   }

//////////////////////////////////////////////////////////////////////
// The Data Decrement controller value causes the decremented value to be
// sent to the Sound IPD if a Param has been selected

static void dataDecr(WORD wChan, short nData) 
{
   nData &= 0x07F;             // ensure byte size

   if (isRPNBend(wChan)) {    // if last was RPN Bend Range
      wBndRVal[wChan] -= nData;
      }
   }

///////////////////////////////////////////////////////////////

BOOL FAR PASCAL _export MIDIStatus
                        (
                           HWND hDlg, 
                           UINT msg,
                           WPARAM wParam, 
                           LPARAM lParam
                        )
{
   BOOL fProcessed = TRUE;
   WORD wParm;
   WORD wChan;
   
   switch(msg) {
      case WM_INITDIALOG:
         // clear the state to force a full update
         InitDisplay(hDlg);
         break;
               
      case WM_COMMAND:
         switch (wParam) {
            case IDM_UPDATESTATUS:
               while (QGet(&wChan, &wParm)) {
                  UpdateParm(hDlg, wChan, wParm);
                  }
               break;

            case IDCANCEL:
               PostMessage(hDlg, WM_CLOSE, 0, 0L); 
               break;
            
            default:
               fProcessed = FALSE;
               break;
            }
         break;

      case WM_CLOSE:
         PostMessage(hMainWnd, MM_SUICIDE, WM_DESTROY,
                               MAKELONG(hDlg, IDM_MSTATUS));
         break;

      case WM_ACTIVATE:
#ifndef _WIN32
         if (0 == wParam)             // becoming inactive
            hActiveDlg = NULL;
         else                         // becoming active
            hActiveDlg = hDlg;
#else
         if(LOWORD(wParam) == WA_INACTIVE)
            hActiveDlg = NULL;
         else
            hActiveDlg = hDlg;
#endif
         break;

      default:
         fProcessed = FALSE;
         break;
      }
   return(fProcessed);
   }

///////////////////////////////////////////////////////////////
// Updates a particular item -- Faster than looping through the
// whole array.  

void UpdateParm(HWND hDlg, WORD wChan, WORD wParm) 
{
   switch(wParm) {
      case PPATCH:
         if (PrmSt.Chan[wChan].nPatch != TrkSt.Chan[wChan].nPatch) 
            TrkSt.Chan[wChan].nPatch = 
                  SetDItem(hDlg, IDC_PATCH1+wChan, PrmSt.Chan[wChan].nPatch);
         break;

      case PVOLUME:
         if (PrmSt.Chan[wChan].nVol != TrkSt.Chan[wChan].nVol) 
            TrkSt.Chan[wChan].nVol = 
                  SetDItem(hDlg, IDC_VOLUME1+wChan, PrmSt.Chan[wChan].nVol);
         break;

      case PPAN:
         if (PrmSt.Chan[wChan].nPan != TrkSt.Chan[wChan].nPan) 
            TrkSt.Chan[wChan].nPan = 
                  SetDItem(hDlg, IDC_PAN1+wChan, PrmSt.Chan[wChan].nPan);
         break;

      case PBEND:
         if (PrmSt.Chan[wChan].nBend != TrkSt.Chan[wChan].nBend) 
            TrkSt.Chan[wChan].nBend = 
                  SetDItem(hDlg, IDC_BEND1+wChan, PrmSt.Chan[wChan].nBend); 
         break;

      case PRANGE:
         if (PrmSt.Chan[wChan].nRange != TrkSt.Chan[wChan].nRange) 
            TrkSt.Chan[wChan].nRange  = 
                  SetDItem(hDlg, IDC_RANGE1+wChan, PrmSt.Chan[wChan].nRange);
         break;

      case PMOD:
         if (PrmSt.Chan[wChan].nMod != TrkSt.Chan[wChan].nMod) 
            TrkSt.Chan[wChan].nMod = 
                  SetDItem(hDlg, IDC_MOD1+wChan, PrmSt.Chan[wChan].nMod);
         break;
         
      case PREVERB:
         if (PrmSt.Chan[wChan].nReverb != TrkSt.Chan[wChan].nReverb) 
            TrkSt.Chan[wChan].nReverb = 
                  SetDItem(hDlg, IDC_REVERB1+wChan, PrmSt.Chan[wChan].nReverb);
         break;
         
      case PCHORUS:
         if (PrmSt.Chan[wChan].nChorus != TrkSt.Chan[wChan].nChorus) 
            TrkSt.Chan[wChan].nChorus = 
                  SetDItem(hDlg, IDC_CHORUS1+wChan, PrmSt.Chan[wChan].nChorus);
         break;

      case PPEDAL:
         if (PrmSt.Chan[wChan].nPedal != TrkSt.Chan[wChan].nPedal) 
            TrkSt.Chan[wChan].nPedal = 
                  SetDItem(hDlg, IDC_PEDAL1+wChan, PrmSt.Chan[wChan].nPedal);             
         break;
      }
   }

///////////////////////////////////////////////////////////////
// Runs through the permanent state structure and updates any
// items needing update.  This is only called when things seem 
// out of sync.
#if 0

void UpdateDisplay(HWND hDlg) 
{
   int ii;

   for (ii = 0; ii < 16; ++ii) {
      if (PrmSt.Chan[ii].nPatch != TrkSt.Chan[ii].nPatch) 
         TrkSt.Chan[ii].nPatch = 
               SetDItem(hDlg, IDC_PATCH1+ii, PrmSt.Chan[ii].nPatch);

      if (PrmSt.Chan[ii].nVol != TrkSt.Chan[ii].nVol) 
         TrkSt.Chan[ii].nVol = 
               SetDItem(hDlg, IDC_VOLUME1+ii, PrmSt.Chan[ii].nVol);
      
      if (PrmSt.Chan[ii].nPan != TrkSt.Chan[ii].nPan) 
         TrkSt.Chan[ii].nPan = 
               SetDItem(hDlg, IDC_PAN1+ii, PrmSt.Chan[ii].nPan);
      
      if (PrmSt.Chan[ii].nBend != TrkSt.Chan[ii].nBend) 
         TrkSt.Chan[ii].nBend = 
               SetDItem(hDlg, IDC_BEND1+ii, PrmSt.Chan[ii].nBend); 

      if (PrmSt.Chan[ii].nRange != TrkSt.Chan[ii].nRange) 
         TrkSt.Chan[ii].nRange  = 
               SetDItem(hDlg, IDC_RANGE1+ii, PrmSt.Chan[ii].nRange);

      if (PrmSt.Chan[ii].nMod != TrkSt.Chan[ii].nMod) 
         TrkSt.Chan[ii].nMod = 
               SetDItem(hDlg, IDC_MOD1+ii, PrmSt.Chan[ii].nMod);
               
      if (PrmSt.Chan[ii].nReverb != TrkSt.Chan[ii].nReverb) 
         TrkSt.Chan[ii].nReverb = 
               SetDItem(hDlg, IDC_REVERB1+ii, PrmSt.Chan[ii].nReverb);
               
      if (PrmSt.Chan[ii].nChorus != TrkSt.Chan[ii].nChorus) 
         TrkSt.Chan[ii].nChorus = 
               SetDItem(hDlg, IDC_CHORUS1+ii, PrmSt.Chan[ii].nChorus);

      if (PrmSt.Chan[ii].nPedal != TrkSt.Chan[ii].nPedal) 
         TrkSt.Chan[ii].nPedal = 
               SetDItem(hDlg, IDC_PEDAL1+ii, PrmSt.Chan[ii].nPedal);             
      }
   }
#endif

///////////////////////////////////////////////////////////////

void FAR PASCAL InitDisplay(HWND hDlg) 
{
   int ii;

   for (ii = 0; ii < 16; ++ii) {
      TrkSt.Chan[ii].nPatch  = SetDItem(hDlg, IDC_PATCH1+ii, PrmSt.Chan[ii].nPatch);
      TrkSt.Chan[ii].nVol    = SetDItem(hDlg, IDC_VOLUME1+ii, PrmSt.Chan[ii].nVol);
      TrkSt.Chan[ii].nPan    = SetDItem(hDlg, IDC_PAN1+ii, PrmSt.Chan[ii].nPan);
      TrkSt.Chan[ii].nBend   = SetDItem(hDlg, IDC_BEND1+ii, PrmSt.Chan[ii].nBend);
      TrkSt.Chan[ii].nRange  = SetDItem(hDlg, IDC_RANGE1+ii, PrmSt.Chan[ii].nRange);
      TrkSt.Chan[ii].nMod    = SetDItem(hDlg, IDC_MOD1+ii, PrmSt.Chan[ii].nMod);
      TrkSt.Chan[ii].nReverb = SetDItem(hDlg, IDC_REVERB1+ii, PrmSt.Chan[ii].nReverb);
      TrkSt.Chan[ii].nChorus = SetDItem(hDlg, IDC_CHORUS1+ii, PrmSt.Chan[ii].nChorus);
      TrkSt.Chan[ii].nPedal  = SetDItem(hDlg, IDC_PEDAL1+ii, PrmSt.Chan[ii].nPedal);
      }
   }

///////////////////////////////////////////////////////////////

int SetDItem(HWND hDlg, UINT ID, int nVal) 
{
   if (-1 == nVal) // uninitted
      SetDlgItemText(hDlg, ID, szNA);
   else  // just update
      SetDlgItemInt(hDlg, ID, nVal, FALSE);
   return nVal;
   }
