/*
 *  mstatus.h
 */

// parameters for communication with dialog

#define PPATCH			1
#define PVOLUME		2
#define PPAN			3
#define PBEND			4
#define PRANGE			5
#define PMOD			6
#define PREVERB		7
#define PCHORUS		8
#define PPEDAL			9

// Structure to specify a filter for MIDI events.

typedef struct midistate_tag 
{
	struct {
		int nPatch;		// Program change
		int nVol;		// Volume
		int nPan;		// Panning L-R value
		int nBend;		// Pitch Bend
		int nRange;		// Signed Bend Range
		int nMod;		// Modulation
		int nReverb;	// External effects
		int nChorus;	// Chorus effect
		int nPedal;		// Pedal sustain
		} Chan[16];		// one struct for each channel
	} MIDISTATE, FAR *LPMIDISTATE;

 // (non) Registered Parameter Variables

#define LSB		1
#define MSB		2
#define NLSB	3
#define NMSB	4

#define RPN		1
#define NRPN   2

typedef struct _PARMFLAG {			// Keeps track of RPN reception
    BYTE  bMSB;		            // Received Parm Number MSB?
    BYTE  bLSB;				      // Received Parm Number LSB?
    BYTE  bMSBn;		            // Received NRPN Parm Number MSB?
    BYTE  bLSBn;				      // Received NRPN Parm Number LSB?
	 short nLast;						// working on NRPN or RPN?
    } PARMFLAG;

BOOL FAR PASCAL UpdateMStatus(LPEVENT lpEvnt);
void FAR PASCAL ResetMStatus(void);
void FAR PASCAL InitDisplay(HWND hDlg);
 






