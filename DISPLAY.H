/*
 *  display.h
 */


#define OCTVBASE		100    // Menu offset

/* Format strings used by GetDisplayText()
 */
#define FORMAT3  " %8s   %2d    %02X    %02X    %02X    %2d   --  %-21s "
#define FORMAT2  " %8s   %2d    %02X    %02X    --    %2d   --  %-21s "
#define FORMAT3N " %8s   %2d    %02X    %02X    %02X    %2d  %-2s%1d  %-21s "

#define FORMAT3X " %8s   %2d    %02X    %02X    %02X    --   --  %-21s "
#define FORMAT2X " %8s   %2d    %02X    %02X    --    --   --  %-21s "
#define FORMAT1X " %8s   %2d    %02X    --    --    --   --  %-21s "


/* Data structure to manage a display buffer.
 */
typedef struct displayBuffer_tag {
    HANDLE  hSelf;          /* handle to this structure */
    HANDLE  hBuffer;        /* buffer handle */
    WORD    wError;         /* error flags */
    DWORD   dwSize;         /* buffer size (in EVENTS) */
    DWORD   dwCount;        /* byte count (in EVENTS) */
    LPEVENT lpStart;        /* ptr to start of buffer */
    LPEVENT lpEnd;          /* ptr to end of buffer (last byte + 1) */
    LPEVENT lpHead;         /* ptr to head (next location to fill) */
    LPEVENT lpTail;         /* ptr to tail (next location to empty) */
    } DISPLAYBUFFER;
typedef DISPLAYBUFFER FAR *LPDISPLAYBUFFER;


/* Function prototypes
 */
int   GetDisplayText(LPSTR lpText, LPEVENT lpEvent);
void  AddDisplayEvent(LPDISPLAYBUFFER lpBuf, LPEVENT lpEvent);
void  GetDisplayEvent(LPDISPLAYBUFFER lpBuf, LPEVENT lpEvent, UINT wNum);
LPDISPLAYBUFFER AllocDisplayBuffer(DWORD dwSize);
void  FreeDisplayBuffer(LPDISPLAYBUFFER lpBuf);
void  ResetDisplayBuffer(LPDISPLAYBUFFER lpBuf);
void  SetOctave(int oct);
int   GetOctave(void);
