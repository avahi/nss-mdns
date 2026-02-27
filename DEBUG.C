
#include <windows.h>
#include <stdarg.h>

#ifndef NDEBUG

/////////////////////////////////////////////////////////////////////////////

void _cdecl _DbugOut(LPSTR lpszFmt, ...)
{
	char		sz[256];
	va_list	va;

	va_start( va, lpszFmt );
	if (wvsprintf( sz, lpszFmt, va ) >= sizeof(sz))
		FatalAppExit( 0, "Stack overwrite in _DbugOut()" );
	va_end( va );

	OutputDebugString( sz );
	}

/////////////////////////////////////////////////////////////////////////////
#define PC_SPEAKER ((UINT)-1)

void _AssertFail(LPSTR szFile, int nLine)
{
	static DWORD	dwNext =  0;

	_DbugOut( "Assertion failed %s %d\r\n", (LPSTR)szFile, nLine );
   
	if (GetTickCount() > dwNext) {
		MessageBeep(PC_SPEAKER);	
		dwNext = GetTickCount() + 1000;	
		}                       
   DebugBreak();
	}

/////////////////////////////////////////////////////////////////////////////

#endif // !NDEBUG
