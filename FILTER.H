/*
 *   filter.h
 */

#ifndef _FILTER_H
#define _FILTER_H

/* Structure to specify a filter for MIDI events.
 */
typedef struct filter_tag
{
    BOOL channel[16];
    struct {
        BOOL noteOn;
        BOOL noteOff;
        BOOL keyAftertouch;
        BOOL controller;
        BOOL progChange;
        BOOL chanAftertouch;
        BOOL pitchBend;
        BOOL channelMode;
    
        BOOL sysEx;
        BOOL sysCommon;
        BOOL sysRealTime;
        BOOL activeSense;
        BOOL pad0;
        BOOL pad1;
        BOOL pad2;
        BOOL filterData;  // whether to filter the actual data
    } event;
} FILTER;

typedef FILTER FAR *LPFILTER;


/* Function prototypes
 */                               

#ifdef __cplusplus
extern "C" {
#endif

void	InitFilter(LPFILTER lpFilter);
void  SaveFilter(LPFILTER lpFilter); 

BOOL  FAR PASCAL FilteredEvent(LPEVENT lpEvent, LPFILTER lpFilter);
int   DoFilter(HINSTANCE hInstance, HWND hWnd, LPFILTER lpFltr);

#ifdef __cplusplus
}
#endif

#endif
