/*
 *  syxbuf.h
 */

#define SYXBUFSIZE  512  // default
#define NUMSXBUF      8

/* Structure to manage the system exclusive buffers.
 */
typedef struct SysExBuffer_tag {
    MIDIHDR mhdr;           /* The MIDI Header */
    HANDLE  hSelf;          /* handle to this structure */
    HANDLE  hBuffer;        /* MIDI Data buffer handle */
    struct SysExBuffer_tag FAR *lpSxNext;
    } SYSEXBUFFER;
typedef SYSEXBUFFER FAR *LPSYSEXBUFFER;

/* Function prototypes
 */
LPSYSEXBUFFER AllocSysExBuffer(WORD bufSize);
LPSYSEXBUFFER FreeSysExBuffer(LPSYSEXBUFFER lpBuf);
VOID FreeSXChain(LPSYSEXBUFFER lpBuf);  
void UnPrepIn(HMIDIIN hMID, LPSYSEXBUFFER lpBuf);
void UnPrepOut(HMIDIOUT hMID, LPSYSEXBUFFER lpBuf);

