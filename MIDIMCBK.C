/* MIDIMCBK.c - Contains the low-level MIDI input callback function for
 *      MIDIMon.  This module also contains the LibMain() and WEP() 
 *      DLL routines, and other functions accessed by the callback.
 *
 *      Because this module contains a low-level callback function,
 *      this entire module must reside in a FIXED code segment in a DLL.
 *      The data segment must be FIXED as well, since it accessed by
 *      the callback.
 */

#include <windows.h>
#include <mmsystem.h>
#include <memory.h>
#include "midimon.h"
#include "circbuf.h"
#include "syxbuf.h"
#include "filter.h"
#include "instdata.h" 
#include "mscrdll.h"
#include "midimcbk.h"
#include "prefer.h"
//#include "debug.h"

#define SXMSG 0x0000F0

WORD        instCount;
HINSTANCE   ghInst = NULL;     //Need this for dialog editor style box.

//static LPMIDIHDR FAR PASCAL FindOutBuffer(LPSYSEXBUFFER lpBuf);

/*
 *  LibMain - Generic for a DLL.  Just initializes a little local memory.
 */

int FAR PASCAL LibMain (HINSTANCE hInstance, 
                        WORD      wDataSeg, 
                        WORD      wHeapSize, 
                        LPSTR     lpCmdLine) {
                        
    // Nothing to do - SDK Libentry does the LocalInit
    instCount  = 0;               
    InitInstance(hInstance);
    return TRUE;    
    }

///////////////////////////////////////////////////////

void FAR PASCAL InitInstance(HINSTANCE hInst) {
   ghInst = hInst; // under WIN32 this will be different for each instance
   MMRegisterControl(hInst);
   }

///////////////////////////////////////////////////////
/*
 *  WEP - Generic for a DLL.  Doesn't do a whole lot.
 */
int FAR PASCAL WEP(WORD wParam) {
   return 0;
   }

///////////////////////////////////////////////////////
// Experimental
void MaybeBumpPriority(void) {
#ifdef _WIN32
   DWORD  dwClsPrty  = NORMAL_PRIORITY_CLASS;
   int    nThrdPrty  = THREAD_PRIORITY_NORMAL;
   BOOL   fAdjust    = TRUE;
   HANDLE hMe;        
      
   hMe = GetCurrentProcess();
   
   switch (GetProfInt("Special", "PriorityClass", -1)) {
      case 0:
         dwClsPrty = IDLE_PRIORITY_CLASS;
         break;

      case 1:
         dwClsPrty = NORMAL_PRIORITY_CLASS;
         break;

      case 2:
         dwClsPrty = HIGH_PRIORITY_CLASS;
         break;

      case 3:
         dwClsPrty = REALTIME_PRIORITY_CLASS;
         break;

      default:
         fAdjust = FALSE;

      }

   if (fAdjust) {
      if (dwClsPrty != GetPriorityClass(hMe))
         SetPriorityClass(hMe, dwClsPrty);
      }

   // now check the thread
   fAdjust = TRUE; 

   switch (GetProfInt("Special", "ThreadPriority", -1)) {
      case 0:
         nThrdPrty = THREAD_PRIORITY_NORMAL;
         break;

      case 1:
         nThrdPrty = THREAD_PRIORITY_ABOVE_NORMAL;
         break;

      case 2:
         nThrdPrty = THREAD_PRIORITY_HIGHEST;
         break;

      case 3:
         nThrdPrty = THREAD_PRIORITY_TIME_CRITICAL;
         break;

      default:
         fAdjust = FALSE;

      }

   if (fAdjust) {
      hMe = GetCurrentThread();
      if (nThrdPrty != GetThreadPriority(hMe))
         SetThreadPriority(hMe, nThrdPrty);
      }
#endif
   }

///////////////////////////////////////////////////////
/* midiInputHandler - Low-level callback function to handle MIDI input.
 *      Installed by midiInOpen().  The input handler takes incoming
 *      MIDI events and places them in the circular input buffer.  It then
 *      notifies the application by posting a MM_MIDIINPUT message.
 *
 *      This function is accessed at interrupt time, so it should be as 
 *      fast and efficient as possible.  You can't make any
 *      Windows calls here, except PostMessage().  The only Multimedia
 *      Windows call you can make are timeGetSystemTime(), midiOutShortMsg().
 *      midiOutLongMsg(JWO)
 *
 * Param:   hMidiIn - Handle for the associated input device.
 *          wMsg - One of the MIM_***** messages.
 *          dwInstance - Points to CALLBACKINSTANCEDATA structure.
 *          dwParam1 - MIDI data.
 *          dwParam2 - Timestamp (in milliseconds)
 *
 * Return:  void
 */     

void CALLBACK midiInputHandler(
                  HMIDIIN hMidiIn, 
                  WORD  wMsg, 
                  DWORD dwInstance, 
                  DWORD dwParam1, 
                  DWORD dwParam2) {
    LPCALLBACKINSTANCEDATA lpInst;
    EVENT event;
    

    switch(wMsg) {
       case MIM_OPEN:
          MaybeBumpPriority();
          break;

        /* The only error possible is invalid MIDI data, so just pass
         * the invalid data on so we'll see it.
         */
       #ifdef _WIN32
       case MIM_MOREDATA:
          TRACE("More Data\n");
       #endif
       case MIM_ERROR:
       case MIM_DATA:
          lpInst = (LPCALLBACKINSTANCEDATA)dwInstance;
          event.wDevice   = lpInst->wDevice;
          event.data      = dwParam1;
          event.timestamp = dwParam2;
            
            /* Send the MIDI event to the MIDI Mapper, put it in the
             * circular input buffer, and notify the application that
             * data was received.
             */  
             
          if ((!lpInst->filter->event.filterData) ||    // let the display decide...
              (!FilteredEvent((LPEVENT)&event, lpInst->filter))) {
             if (lpInst->hMOut)
                midiOutShortMsg(lpInst->hMOut, dwParam1);
             PutEvent(lpInst->lpBuf, (LPEVENT)&event); 
             PostMessage(lpInst->hWnd, MM_MIDIINPUT, 0, 0L);
             break;
             }
             
          break;

       case MIM_LONGDATA:
          if (((LPMIDIHDR)dwParam1)->dwBytesRecorded == 0L) // just returning buffers
                break;            

          lpInst = (LPCALLBACKINSTANCEDATA)dwInstance;

          event.wDevice   = lpInst->wDevice;
          event.data      = SXMSG;
          event.timestamp = dwParam2;
         
          if (lpInst->hMOut) {
             LPMIDIHDR lpMHIn, lpMHOut;    // declare...

             lpMHIn  = (LPMIDIHDR)dwParam1;
             if ((lpMHOut = FindOutBuffer(lpInst->lpSxOut))) {
                MEMCPY(
                   lpMHOut->lpData, 
                   lpMHIn->lpData, 
                   (size_t)lpMHIn->dwBytesRecorded
                   );
                lpMHOut->dwBytesRecorded = lpMHIn->dwBytesRecorded; 
                // Save the length of the buffer, and assign the size based on use
                lpMHOut->dwUser          = lpMHOut->dwBufferLength;
                lpMHOut->dwBufferLength  = lpMHIn->dwBytesRecorded;
                midiOutLongMsg(lpInst->hMOut, lpMHOut, sizeof(MIDIHDR));
             }
             else
                TRACE("No Sysex Outbuffer!\n");
          }                                           

          // ask that the buffer be put back in the queue
          ((LPMIDIHDR)dwParam1)->dwBytesRecorded = 0L; // Mark as used
          midiInAddBuffer(hMidiIn, (LPMIDIHDR)dwParam1, sizeof(MIDIHDR));
 
          // PostMessage(lpInst->hWnd, MM_ADDBUFFER, (WPARAM)hMidiIn, dwParam1);
             
            /* Send the MIDI event to the MIDI Mapper, put it in the
             * circular input buffer, and notify the application that
             * data was received.
             */ 

             
          PutEvent(lpInst->lpBuf, (LPEVENT)&event); 
          PostMessage(lpInst->hWnd, MM_MIDIINPUT, 0, 0L);
          break;

       default:
          break;
       }
   }

/* PutEvent - Puts an EVENT in a CIRCULARBUFFER.  If the buffer is full, 
 *      it sets the wError element of the CIRCULARBUFFER structure 
 *      to be non-zero.
 *
 * Params:  lpBuf - Points to the CIRCULARBUFFER.
 *          lpEvent - Points to the EVENT.
 *
 * Return:  void
*/
void FAR PASCAL PutEvent(LPCIRCULARBUFFER lpBuf, LPEVENT lpEvent) {
    /* If the buffer is full, set an error and return. 
     */
    if(lpBuf->dwCount >= lpBuf->dwSize) {
        lpBuf->wError = 1;
        return;
        }
    
    /* Put the event in the buffer, bump the head pointer and the byte count.
     */
    *lpBuf->lpHead = *lpEvent;
    
    ++lpBuf->lpHead;
    ++lpBuf->dwCount;

    /* Wrap the head pointer, if necessary.
     */
    if (lpBuf->lpHead >= lpBuf->lpEnd)
       lpBuf->lpHead = lpBuf->lpStart;
    }

// Events created by MIDIMon

void FAR PASCAL midiMonEvent(
                    LPCALLBACKINSTANCEDATA lpData,
                    WORD  wStatus,
                    WORD  wChannel,                
                    WORD  wValue1,
                    WORD  wValue2) {
    EVENT event;
    
    event.wDevice = 0xFFFF;
    event.data = MAKELONG((wValue1 << 8 | (wStatus | wChannel)), wValue2);
    event.timestamp = 0L;
            
    /* Send the MIDI event to the MIDI Mapper, put it in the
     * circular input buffer, and notify the application that
     * data was received.
     */
    if (lpData->hMOut)
       midiOutShortMsg(lpData->hMOut, event.data);

    PutEvent(lpData->lpBuf, (LPEVENT)&event); 
    PostMessage(lpData->hWnd, MM_MIDIINPUT, 0, 0L);

    return;
    }

/* FindOutBuffer Locates the next free output buffer in the chain.
 *  A free buffer has the MHDR_DONE bit set and the INQUEUE bit reset.
 *  Polling the bit obviates the need for a low level output callback.
 *
 * Params:  lpBuf - Points to the SYSEXBUFFER chain to start looking
 *
 * Return:  Returns a MIDIHDR pointer if successful, NULL if not 
 */

LPMIDIHDR FAR PASCAL FindOutBuffer(LPSYSEXBUFFER lpBuf) {
    LPMIDIHDR     lpMH;
    LPSYSEXBUFFER lpWrk;
    
    lpWrk = lpBuf;
    while(lpWrk != NULL) {
       lpMH  = &lpWrk->mhdr;   
       if (lpMH->dwFlags & MHDR_DONE) { // our acquiescent state...
          if (lpMH->dwUser > 0L) {      // left over from our mods...
             lpMH->dwBufferLength = lpMH->dwUser;
             lpMH->dwUser = 0L;
             }
          lpMH->dwBytesRecorded = 0L;              
          return lpMH;    // this one can be used
          }
       lpWrk = lpWrk->lpSxNext;
       } 
    TRACE("NULL Outbuffer\n");
    return (LPMIDIHDR)NULL; // didn't find one
    }
                    
/* getInstCount: pseudo IPC call to bump and get number of instances. 
   This will conrinue to increase even if early instances are closed.
 */
                              
WORD FAR PASCAL _loadds getInstCount(void) {
    return ++instCount;
    } 
    