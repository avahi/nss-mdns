/*
 * FiltDlg.c - Filter dialog box.
 */

#include <windows.h>
#include "midimon.h"
#include "filter.h"
#include "prefer.h"

const char szChannel[]		 = "Channel";
const char szNoteOff[]		 = "NoteOff";
const char szNoteOn[]       = "NoteOn";
const char szKeyAfter[]     = "KeyAfter";
const char szCtrlChange[]   = "CtrlChange";
const char szProgChange[]   = "ProgChange";
const char szChanAfter[]    = "ChanAfter";
const char szPitchBend[]    = "PitchBend";
const char szChanMode[]		 = "ChannelMode";
const char szSysCommon[]    = "SysCommon";
const char szSysRealTime[]  = "SysRealTime";
const char szActiveSense[]  = "ActiveSense";
const char szFilterData[]   = "FilterData";
const char szFilterSect[]   = "Filter";

/* FiltDlg  - Allows user specification for the filter parameters
 *
 * Params:  hWnd - The application's main window handle.
 *          hInstance - The application's instance handle.
 *
 * Returns: void
 */     
 
int DoFilter(
				HINSTANCE hInstance, 
				HWND hWnd,
				LPFILTER lpFltr
				) 
{
    FARPROC fpDlg;
    int		result;

    fpDlg = MakeProcInstance((FARPROC)FilterDlgProc, hInstance);
    result = DialogBoxParam(
						hInstance, 
						"Filter", 
						hWnd, 
						(DLGPROC)fpDlg, 
						(LPARAM)lpFltr
						);
    FreeProcInstance(fpDlg);
	 return result;
    }


/* FilterDlgProc - The dialog procedure.
 *
 * Params:  hDlg - Specifies the associated dialog box.
 *          msg - Specifies the message from the dialog box.
 *          wParam - 16 bits of message-dependent data.
 *          lParam - 32 bits of message-dependent data.
 *
 * Returns: Non-zero if the message is processed, zero otherwise.
 */
BOOL FAR PASCAL _export FilterDlgProc(HWND hDlg, 
                             UINT msg, 
                             WPARAM wParam, 
                             LPARAM lParam) 
{
	static LPFILTER lpFltr;
	int ii;
                             
   switch (msg) {
   	case WM_INITDIALOG:
			lpFltr = (LPFILTER)lParam;
			CheckDlgButton(hDlg, IDC_NOTEON, lpFltr->event.noteOn);
			CheckDlgButton(hDlg, IDC_NOTEOFF, lpFltr->event.noteOff);
			CheckDlgButton(hDlg, IDC_CONTROLCHANGE, lpFltr->event.controller);
			CheckDlgButton(hDlg, IDC_PROGRAMCHANGE, lpFltr->event.progChange);
			CheckDlgButton(hDlg, IDC_POLYAFTERTOUCH, lpFltr->event.keyAftertouch);
			CheckDlgButton(hDlg, IDC_CHANNELAFTERTOUCH, lpFltr->event.chanAftertouch);
			CheckDlgButton(hDlg, IDC_PITCHBEND, lpFltr->event.pitchBend);
			CheckDlgButton(hDlg, IDC_SYSTEMCOMMON, lpFltr->event.sysCommon);
			CheckDlgButton(hDlg, IDC_SYSTEMREALTIME, lpFltr->event.sysRealTime);
			CheckDlgButton(hDlg, IDC_ACTIVESENSE, lpFltr->event.activeSense);
			CheckDlgButton(hDlg, IDC_FILTERDATA, lpFltr->event.filterData);
			for (ii = 0; ii < 16; ++ii) 
				CheckDlgButton(hDlg, ii+IDC_FILTCHAN0, lpFltr->channel[ii]);

        	CenterOnParent(hDlg);    
        	break;       
        	
    	case WM_COMMAND:
			switch (wParam) {
				case IDOK: 
					lpFltr->event.noteOn				= IsDlgButtonChecked(hDlg, IDC_NOTEON);	
					lpFltr->event.noteOff			= IsDlgButtonChecked(hDlg, IDC_NOTEOFF);
					lpFltr->event.controller		= IsDlgButtonChecked(hDlg, IDC_CONTROLCHANGE);
					lpFltr->event.progChange		= IsDlgButtonChecked(hDlg, IDC_PROGRAMCHANGE);
					lpFltr->event.keyAftertouch	= IsDlgButtonChecked(hDlg, IDC_POLYAFTERTOUCH);
					lpFltr->event.chanAftertouch	= IsDlgButtonChecked(hDlg, IDC_CHANNELAFTERTOUCH);
					lpFltr->event.pitchBend			= IsDlgButtonChecked(hDlg, IDC_PITCHBEND);
					lpFltr->event.sysCommon			= IsDlgButtonChecked(hDlg, IDC_SYSTEMCOMMON);
					lpFltr->event.sysRealTime		= IsDlgButtonChecked(hDlg, IDC_SYSTEMREALTIME);
					lpFltr->event.activeSense		= IsDlgButtonChecked(hDlg, IDC_ACTIVESENSE);
					lpFltr->event.filterData		= IsDlgButtonChecked(hDlg, IDC_FILTERDATA);
					for (ii = 0; ii < 16; ++ii) 
						lpFltr->channel[ii] = IsDlgButtonChecked(hDlg, ii+IDC_FILTCHAN0);
					break;
				
				case IDCANCEL:   
					break;

				default: // don't close except for above
					return FALSE;
				}
        	EndDialog(hDlg, wParam);
        	break;

    	default:
        	return FALSE;
        	break;
    	}
    return TRUE;
}

////////////////////////////////////////////////////////////////////

void InitFilter(LPFILTER lpFltr) 
{
	int ii;
   char Buf[16];

	for (ii = 0; ii < 16; ++ii) 
	{
		wsprintf(Buf, "%s%d", (LPCSTR)szChannel, ii+1);
		lpFltr->channel[ii]	= GetProfInt(szFilterSect, Buf, FALSE);
	}
		
	lpFltr->event.noteOn	= 
				GetProfInt(szFilterSect, szNoteOn, FALSE);
	lpFltr->event.noteOff = 
				GetProfInt(szFilterSect, szNoteOff, FALSE);
	lpFltr->event.controller = 
				GetProfInt(szFilterSect, szCtrlChange, FALSE);
	lpFltr->event.progChange = 
				GetProfInt(szFilterSect, szProgChange, FALSE);
	lpFltr->event.keyAftertouch = 
				GetProfInt(szFilterSect, szKeyAfter, FALSE);
	lpFltr->event.chanAftertouch = 
				GetProfInt(szFilterSect, szChanAfter, FALSE);
	lpFltr->event.pitchBend = 
				GetProfInt(szFilterSect, szPitchBend, FALSE);
	lpFltr->event.sysCommon = 
				GetProfInt(szFilterSect, szSysCommon, FALSE);
	lpFltr->event.sysRealTime = 
				GetProfInt(szFilterSect, szSysRealTime, TRUE);
	lpFltr->event.activeSense = 
				GetProfInt(szFilterSect, szActiveSense, TRUE);
	lpFltr->event.filterData = 
				GetProfInt(szFilterSect, szFilterData, TRUE);
}

////////////////////////////////////////////////////////////////////

void SaveFilter(LPFILTER lpFltr) 
{
	int ii;
   char Buf[16];

	for (ii = 0; ii < 16; ++ii) 
	{
		wsprintf(Buf, "%s%d", (LPCSTR)szChannel, ii+1);
		SetProfInt(szFilterSect, Buf, lpFltr->channel[ii]);
	}
		
	SetProfInt(szFilterSect, szNoteOn, lpFltr->event.noteOn);
	SetProfInt(szFilterSect, szNoteOff, lpFltr->event.noteOff);
	SetProfInt(szFilterSect, szCtrlChange, lpFltr->event.controller);
	SetProfInt(szFilterSect, szProgChange, lpFltr->event.progChange);
	SetProfInt(szFilterSect, szPitchBend, lpFltr->event.pitchBend);
	SetProfInt(szFilterSect, szKeyAfter, lpFltr->event.keyAftertouch);
	SetProfInt(szFilterSect, szChanAfter, lpFltr->event.chanAftertouch);
	SetProfInt(szFilterSect, szSysCommon, lpFltr->event.sysCommon);
	SetProfInt(szFilterSect, szSysRealTime, lpFltr->event.sysRealTime);
	SetProfInt(szFilterSect, szActiveSense, lpFltr->event.activeSense);
	SetProfInt(szFilterSect, szFilterData, lpFltr->event.filterData);
}
