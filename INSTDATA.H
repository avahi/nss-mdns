/*
 * instdata.h
 */

#ifndef _INSTDATA_H
#define _INSTDATA_H

/* Structure to pass instance data from the application
   to the low-level callback function.
 */
typedef struct callbackInstance_tag {
    HWND                hWnd;
    HANDLE              hSelf;  
    WORD                wDevice;
    HMIDIOUT            hMOut;
    LPFILTER            filter;
    LPCIRCULARBUFFER    lpBuf;
    LPSYSEXBUFFER       lpSxIn;
    LPSYSEXBUFFER       lpSxOut;    
    } CALLBACKINSTANCEDATA;
typedef CALLBACKINSTANCEDATA FAR *LPCALLBACKINSTANCEDATA;

/* Function prototypes
 */
LPCALLBACKINSTANCEDATA FAR PASCAL AllocCallbackInstanceData(void);
void FAR PASCAL FreeCallbackInstanceData(LPCALLBACKINSTANCEDATA lpBuf);

#endif
