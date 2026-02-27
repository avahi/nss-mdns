// Debug.h

#ifndef DEBUG_H
#define DEBUG_H

#ifndef NDEBUG
	void _cdecl _DbugOut(LPSTR pcszFmt, ...);
	#define TRACE _DbugOut

	void _AssertFail(LPSTR szFile, int nLine);
	#define ASSERT(exp) ((exp) ? (void)0 : (_AssertFail(__FILE__,__LINE__)))
	#define VERIFY(exp) ((exp) ? TRUE : (_AssertFail(__FILE__,__LINE__),FALSE))
#else
	__inline void _cdecl _DbugOut(LPSTR pcszFmt, ...) { }
	#define TRACE TRUE ? (void)0 : _DbugOut

	#define ASSERT(exp) ((void)0)
	#define VERIFY(exp) (exp)
#endif

#endif // DEBUG_H
