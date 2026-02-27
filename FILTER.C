/*
 * filter.c - Routines to filter MIDI events.
 */

#include <windows.h>
#include "midimon.h"
#include "display.h"
#include "filter.h"

/* CheckEventFilter - Checks the given EVENT against the given FILTER.
 *      
 * Params:  lpEvent - Points to an EVENT.
 *          lpFilter - Points to a FILTER structure.
 *
 * Return:  Returns 1 if the event is filtered, 0 if it is not filtered.
 */

BOOL FAR PASCAL FilteredEvent(LPEVENT lpEvent, LPFILTER lpFilter) {
    BYTE bStatus;
    BYTE bChannel;

    /* Get the essential info from the EVENT.
     */
    bStatus  = LOBYTE(LOWORD(lpEvent->data)) & (BYTE) 0xf0;
    bChannel = LOBYTE(LOWORD(lpEvent->data)) & (BYTE) 0x0f;

    /* Do channel filtering for all but system events.
     */
    if (bStatus != SYSTEMMESSAGE) {
       if (lpFilter->channel[bChannel])
          return 1;
       }

    /* Do event-type filtering.
     */
    switch(bStatus){
        case NOTEOFF:
            if (lpFilter->event.noteOff)
               return 1;
            break;

        case NOTEON:
            /* A note on with a velocity of 0 is a note off.
             */

            if (LOBYTE(HIWORD(lpEvent->data)) == 0){
               if (lpFilter->event.noteOff)
                  return 1;
               break;
               }
            
            if (lpFilter->event.noteOn)
               return 1;
            break;

        case KEYAFTERTOUCH:
            if (lpFilter->event.keyAftertouch)
               return 1;
            break;

        case CONTROLCHANGE:
            if (lpFilter->event.controller)
               return 1;
            
            /* Channel mode messages can be filtered.
             */ 
#if 0 
            if ((HIBYTE(LOWORD(lpEvent->data)) >= 121) && lpFilter->event.channelMode)
               return 1;
#endif
            break;

        case PROGRAMCHANGE:
            if (lpFilter->event.progChange)
               return 1;
            break;

        case CHANAFTERTOUCH:
            if (lpFilter->event.chanAftertouch)
               return 1;
            break;

        case PITCHBEND:
            if (lpFilter->event.pitchBend)
               return 1;
            break;

        case SYSTEMMESSAGE:
            /* System common messages.
             */ 
            { 
            BYTE bStatusRaw = LOBYTE(LOWORD(lpEvent->data));
            
            if ((bStatusRaw < 0xF8) && (lpFilter->event.sysCommon))
               return 1;

            /* Active sensing messages.
             */
            if ((bStatusRaw == 0xFE) && (lpFilter->event.activeSense))
               return 1;

            /* System real time messages (except Active sensing).
             */
            if ((bStatusRaw >= 0xF8 && bStatusRaw != 0xFE) 
                                    && lpFilter->event.sysRealTime)
               return 1;
            }
            break;

        default:
            break;
        }

    return 0;
    }
