/*
 *  MIDIMCBK.h
 */
#ifndef _MIDIMCBK_H
#define _MIDIMCBK_H

#ifdef __cplusplus
extern "C" {
#endif

/* Function prototypes
 */
void CALLBACK   midiInputHandler(HMIDIIN, WORD, DWORD, DWORD, DWORD);
void FAR PASCAL PutEvent(LPCIRCULARBUFFER lpBuf, LPEVENT lpEvent);
void FAR PASCAL midiMonEvent(LPCALLBACKINSTANCEDATA, WORD, WORD, WORD, WORD);
WORD FAR PASCAL _loadds getInstCount(void);
LPMIDIHDR FAR PASCAL FindOutBuffer(LPSYSEXBUFFER lpBuf);

#ifdef __cplusplus
}
#endif

#endif

