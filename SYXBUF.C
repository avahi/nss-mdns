/*
 * syxbuf.c - Routines to manage the sysex MIDI buffers.
 *      This buffer is filled by the low-level callback function and
 *      emptied by the application.  Since this buffer is accessed
 *      by a low-level callback, memory for it must be allocated
 *      exactly as shown in AllocCircularBuffer().
 *
 * Copyright (c) 1995 by Jamie O'Connell - All Rights Reserved.         
 *
 * Created 950305 by Jamie O'Connell         
 */

#include <windows.h>
#include <mmsystem.h>
#include "midimon.h"
#include "syxbuf.h"

/*
 * AllocSysExBuffer - Allocates memory for a SYSEXBUFFER structure 
 * and a buffer of the specified size.  Each memory block is allocated 
 * with GlobalAlloc() using GMEM_SHARE and GMEM_MOVEABLE flags, locked 
 * with GlobalLock(), and page-locked with GlobalPageLock().
 *
 * Params:  void
 *
 * Return:  A pointer to a SYSEXBUFFER structure identifying the 
 *      allocated display buffer.  NULL if the buffer could not be allocated.
 */
LPSYSEXBUFFER AllocSysExBuffer(WORD bufSize) {
    HANDLE hMem;
    LPSYSEXBUFFER lpBuf;
    LPSTR lpMem;
    
    /* Allocate and lock a CIRCULARBUFFER structure.
     */
    hMem = GlobalAlloc(GMEM_SHARE | GMEM_MOVEABLE,
                       (DWORD)sizeof(SYSEXBUFFER));
    if(hMem == NULL)
        return NULL;

    lpBuf = (LPSYSEXBUFFER)GlobalLock(hMem);
    if(lpBuf == NULL) {
        GlobalFree(hMem);
        return NULL;
        }
    
    /* Page lock the memory.  Global memory blocks accessed by
     * low-level callback functions must be page locked.
     */
#ifndef _WIN32
    GlobalPageLock((HGLOBAL)HIWORD(lpBuf));
#endif

    /* Save the memory handle.
     */
    lpBuf->hSelf = hMem;
    
    /* Allocate and lock memory for the actual buffer.
     */
    hMem = GlobalAlloc(GMEM_SHARE | GMEM_MOVEABLE, bufSize);
    if (hMem == NULL) {
       GlobalPageUnlock((HGLOBAL)HIWORD(lpBuf));
       GlobalUnlock(lpBuf->hSelf);
       GlobalFree(lpBuf->hSelf);
       return NULL;
       }
    
    lpMem = (LPSTR)GlobalLock(hMem);
    if (lpMem == NULL) {
       GlobalFree(hMem);
       GlobalPageUnlock((HGLOBAL)HIWORD(lpBuf));
       GlobalUnlock(lpBuf->hSelf);
       GlobalFree(lpBuf->hSelf);
       return NULL;
       }
    
    /* The memory is page locked when it is prepared.  We don't 
     * need to do it now
     *
     * Set up the SYSEXBUFFER structure.
     */
    
    lpBuf->hBuffer              = hMem;
    lpBuf->mhdr.lpData          = lpMem;   
    lpBuf->mhdr.dwBufferLength  = bufSize;
    lpBuf->mhdr.dwBytesRecorded = 0L;
    lpBuf->mhdr.dwUser          = 0L;
    lpBuf->mhdr.dwFlags         = 0; //docs say this should be set to 0
    //lpBuf->mhdr.dwFlags         = MHDR_DONE; // our normal state
    lpBuf->lpSxNext             = NULL;                                        
    return lpBuf;
}

/* FreeSysExBuffer - Frees the memory for the given CIRCULARBUFFER 
 * structure and the memory for the buffer it references.
 *
 * Params:  lpBuf - Points to the SYSEXBUFFER to be freed.
 *
 * Return:  a pointer to the next one in chain. NULL means none
 */

LPSYSEXBUFFER FreeSysExBuffer(LPSYSEXBUFFER lpBuf) {
    HANDLE        hMem;
    LPSYSEXBUFFER lpNext;
    
    if (!lpBuf)
       return NULL;
       
    /* Free the buffer itself.
     */
    GlobalUnlock(lpBuf->hBuffer);
    GlobalFree(lpBuf->hBuffer);
    
    /* Free the CIRCULARBUFFER structure.
     */
    hMem   = lpBuf->hSelf;
    lpNext = lpBuf->lpSxNext;
    GlobalPageUnlock((HGLOBAL)HIWORD(lpBuf));
    GlobalUnlock(hMem);
    GlobalFree(hMem);
    return lpNext;
    }

/* FreeSXChain - Free the whole chain
 */
void FreeSXChain(LPSYSEXBUFFER lpBuf) {
    while(lpBuf != NULL)
       lpBuf = FreeSysExBuffer(lpBuf);
    }

/* UnPrepIn - Unprepare the whole chain
 */
void UnPrepIn(HMIDIIN hMID, LPSYSEXBUFFER lpBuf) {
    LPMIDIHDR     lpMH;
    LPSYSEXBUFFER lpWrk;
    
    lpWrk = lpBuf;
    while(lpWrk != NULL) {
       lpMH  = &lpWrk->mhdr;   
       midiInUnprepareHeader(hMID, lpMH, sizeof(MIDIHDR));
       lpWrk = lpWrk->lpSxNext;
       } 
    }

/* UnPrepOut - Unprepare the whole chain
 */
void UnPrepOut(HMIDIOUT hMID, LPSYSEXBUFFER lpBuf) {
    LPMIDIHDR     lpMH;
    LPSYSEXBUFFER lpWrk;
    
    lpWrk = lpBuf;
    while(lpWrk != NULL) {
       lpMH  = &lpWrk->mhdr;   
       midiOutUnprepareHeader(hMID, lpMH, sizeof(MIDIHDR));
       lpWrk = lpWrk->lpSxNext;
       } 
    }


