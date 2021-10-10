#pragma once
//antidebug and hwid header library by Manucod
// simple
// header only
// API


//CODEGARBAGEINIT() and CODEGARBAGE();
//AhlIsDebuggerPresent(bool check) // bool will be true if debugger was found
// String obfusctation (beware basic)
// XorStr( s ) 
// XorStrW(s)

#include <Windows.h>
#include <iostream>
#include <string>
#include <array>
#include <cstdarg>
#include <sstream>
#define INLINE static inline
#define BEGIN_NAMESPACE( x ) namespace x {
#define END_NAMESPACE }

BEGIN_NAMESPACE(XorCompileTime)

constexpr auto time = __TIME__;
constexpr auto seed = static_cast<int>(time[7]) + static_cast<int>(time[6]) * 10 + static_cast<int>(time[4]) * 60 + static_cast<int>(time[3]) * 600 + static_cast<int>(time[1]) * 3600 + static_cast<int>(time[0]) * 36000;

// 1988, Stephen Park and Keith Miller
// "Random Number Generators: Good Ones Are Hard To Find", considered as "minimal standard"
// Park-Miller 31 bit pseudo-random number generator, implemented with G. Carta's optimisation:
// with 32-bit math and without division

template < int N >
struct RandomGenerator
{
private:
	static constexpr unsigned a = 16807; // 7^5
	static constexpr unsigned m = 2147483647; // 2^31 - 1

	static constexpr unsigned s = RandomGenerator< N - 1 >::value;
	static constexpr unsigned lo = a * (s & 0xFFFF); // Multiply lower 16 bits by 16807
	static constexpr unsigned hi = a * (s >> 16); // Multiply higher 16 bits by 16807
	static constexpr unsigned lo2 = lo + ((hi & 0x7FFF) << 16); // Combine lower 15 bits of hi with lo's upper bits
	static constexpr unsigned hi2 = hi >> 15; // Discard lower 15 bits of hi
	static constexpr unsigned lo3 = lo2 + hi;

public:
	static constexpr unsigned max = m;
	static constexpr unsigned value = lo3 > m ? lo3 - m : lo3;
};

template <>
struct RandomGenerator< 0 >
{
	static constexpr unsigned value = seed;
};

template < int N, int M >
struct RandomInt
{
	static constexpr auto value = RandomGenerator< N + 1 >::value % M;
};

template < int N >
struct RandomChar
{
	static const char value = static_cast<char>(1 + RandomInt< N, 0x7F - 1 >::value);
};

template < size_t N, int K, typename Char >
struct XorString
{
private:
	const char _key;
	std::array< Char, N + 1 > _encrypted;

	constexpr Char enc(Char c) const
	{
		return c ^ _key;
	}

	Char dec(Char c) const
	{
		return c ^ _key;
	}

public:
	template < size_t... Is >
	constexpr __forceinline XorString(const Char* str, std::index_sequence< Is... >) : _key(RandomChar< K >::value), _encrypted{ enc(str[Is])... }
	{
	}

	__forceinline decltype(auto) decrypt(void)
	{
		for (size_t i = 0; i < N; ++i) {
			_encrypted[i] = dec(_encrypted[i]);
		}
		_encrypted[N] = '\0';
		return _encrypted.data();
	}
};

//--------------------------------------------------------------------------------
//-- Note: XorStr will __NOT__ work directly with functions like printf.
//  
//         use std::cout (and similar)!
//--------------------------------------------------------------------------------


#define XorStr( s ) []{ constexpr XorCompileTime::XorString< sizeof(s)/sizeof(char) - 1, __COUNTER__, char > expr( s, std::make_index_sequence< sizeof(s)/sizeof(char) - 1>() ); return expr; }().decrypt()
#define XorStrW( s ) []{ constexpr XorCompileTime::XorString< sizeof(s)/sizeof(wchar_t) - 1, __COUNTER__, wchar_t > expr( s, std::make_index_sequence< sizeof(s)/sizeof(wchar_t) - 1>() ); return expr; }().decrypt()

END_NAMESPACE

INLINE void ZZ_strchrrepl(char* string, char torepl, char repl);
INLINE char* ZZ_ExpandNewlines(char* in);
INLINE int ZZ_CountChar(const char* string, char tocount);
INLINE int  ZZ_strichr(const char* s, char find);
INLINE void ZZ_TrimCRLF(char* string);
INLINE void ZZ_strlcat(char* dest, int size, const char* src, int cpylimit);
INLINE void ZZ_bstrcpy(char* dest, char* src);
INLINE char* ZZ_strupr(char* s1);
INLINE char* ZZ_strlwr(char* s1);
INLINE int ZZ_Compress(char* data_p);
INLINE int ZZ_strncmp(const char* s1, const char* s2, int n);
INLINE int ZZ_stricmpn(const char* s1, const char* s2, int n);
INLINE short ZZ_ShortSwap(short l);
INLINE int  ZZ_LongSwap(int l);
INLINE int ZZ_isupper(int c);
INLINE int ZZ_isprint(int c);
INLINE int ZZ_islower(int c);
INLINE int ZZ_isalpha(int c);
INLINE bool ZZ_isintegral(float f);
INLINE bool ZZ_isanumber(const char* s);
INLINE bool ZZ_strToVect(const char* string, float* vect, int dim);
INLINE bool ZZ_isVector(const char* string, int size, int dim);
INLINE bool ZZ_isInteger(const char* string, int size);
INLINE bool ZZ_isFloat(const char* string, int size);
INLINE bool ZZ_IsEqualUnitWSpace(char* cmp1, char* cmp2);
INLINE bool ZZ_isNumeric(const char* string, int size);

#define CODEGARBAGEINIT() int garbageint1 = 0xff777711; int garbageint2 = 0x87178633; int garbageint3 = 500; int garbageint4 = 880; int garbageint5 = 880; char garbagebuf1[1024]; char garbagebuf2[1024]; char garbagebuf3[1024]
#define CODEGARBAGE1( ) garbageint5 = ZZ_ShortSwap(ZZ_LongSwap(garbageint2)); ZZ_isalpha(garbageint3);ZZ_islower( garbageint5 )
#define CODEGARBAGE2( ) garbageint3 = ZZ_isupper(ZZ_isprint( garbageint4 )); ZZ_isintegral( garbageint4 )
#define CODEGARBAGE3( ) if(ZZ_isanumber((XorStr("7000 200 199 4"), garbagebuf1))){ ZZ_CountChar((XorStr("7000 200 199 4"), garbagebuf1), garbageint4); }else{ ZZ_strichr( (XorStr("7000 200 199 4"), garbagebuf1), '\n'); } ZZ_isprint( 'P' )
#define CODEGARBAGE4( ) ZZ_Compress( (char*)(XorStr("7000 200 199 4"), garbagebuf1) ); ZZ_ExpandNewlines((char*) (XorStr("7000 200 199 4"), garbagebuf1) )
#define CODEGARBAGE5( ) if(ZZ_stricmpn((XorStr("open \"PhysicalDrive\78734saf\\\""), garbagebuf2), garbagebuf1, garbageint4) == 0){ ZZ_strlwr(garbagebuf1); }else{ garbagebuf1[5] = 'T'; garbagebuf1[9] = 'q'; } ZZ_strchrrepl(garbagebuf1, '7', 'I')
#define CODEGARBAGE6( ) garbageint4 = 6; if(ZZ_isFloat((XorStr("70000.6786852"), garbagebuf2), garbageint4)){ sprintf_s(garbagebuf3, (XorStr("%d %s Check drive"), garbagebuf1), garbageint1, garbagebuf2); } garbageint5 = ZZ_CountChar(garbagebuf3, 9)
#define CODEGARBAGE( ) CODEGARBAGE1( ); CODEGARBAGE2( ); CODEGARBAGE3( ); CODEGARBAGE4( ); CODEGARBAGE5( );	CODEGARBAGE6( )

void antihwdebug(bool check) {
	CODEGARBAGEINIT();
	CODEGARBAGE();
	CONTEXT ctx = {};
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (GetThreadContext(GetCurrentThread(), &ctx))
	{
		if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
		{
			check = true;
		}
	}
	CODEGARBAGE();
}

void RemoteDebuggerCheck(bool check) {

	CODEGARBAGEINIT();
	CODEGARBAGE();

	BOOL isDebuggerPresent = false;
	if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent))
	{
		if (isDebuggerPresent)
		{
			check = true;
		}
	}
	CODEGARBAGE();
}

void TrapFlagCheck(bool check) {
	CODEGARBAGEINIT();
	CODEGARBAGE();
	bool isDebugged = true;
	__try
	{
		__asm int 3;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		// If an exception has been raised – debugger is not present
		isDebugged = false;
	}
	if (isDebugged)
	{
		check = true;
	}
}

const char* checknames[12] = {
	XorStr("OllyDbg"),
	XorStr("JSwat"),
	XorStr("Ghidra"),
	XorStr("Cheat Engine"),
	XorStr("IDA v7.2.181105"),
	XorStr("Phantom"),
	XorStr("x32dbg"),
	XorStr("x64dbg"),
	XorStr("wireshark"),
	XorStr("windbg"),
	XorStr("debugger"),
	XorStr("IDA -"),
};

bool checkwindows(std::string str) {
	for (int i = 0; i < 12; i++)
	{
		if (strstr(str.c_str(), checknames[i]) || !strcmp(str.c_str(), checknames[i])) {
			return true;
		}
	}
	return false;
}

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
	_In_      HANDLE           ProcessHandle,
	_In_      UINT             ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
	);
const UINT ProcessDebugPort = 7;

void NTDebugCheck(bool check) {

	CODEGARBAGEINIT();
	CODEGARBAGE();

	pfnNtQueryInformationProcess NtQueryInformationProcess = NULL;
	NTSTATUS status;
	DWORD isDebuggerPresent = 0;
	HMODULE hNtDll = LoadLibraryA((XorStr("ntdll.dll")));
	CODEGARBAGE();
	if (NULL != hNtDll)
	{
		NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, XorStr("NtQueryInformationProcess"));
		if (NULL != NtQueryInformationProcess)
		{
			status = NtQueryInformationProcess(
				GetCurrentProcess(),
				ProcessDebugPort,
				&isDebuggerPresent,
				sizeof(DWORD),
				NULL);
			if (status == 0x00000000 && isDebuggerPresent != 0)
			{
				check = true;
			}
		}
	}
	CODEGARBAGE();
}

void WindoWDebugCheck(bool check) {
	CODEGARBAGEINIT();
	CODEGARBAGE();
	for (HWND hwnd = GetTopWindow(NULL); hwnd != NULL; hwnd = GetNextWindow(hwnd, GW_HWNDNEXT))
	{
		int length = GetWindowTextLength(hwnd);
		if (length == 0)
			continue;

		CODEGARBAGE();
		char* title = new char[length + 1];
		GetWindowTextA(hwnd, title, length + 1);

		if (checkwindows(title))
		{
			check = true;
		}
	}
	CODEGARBAGE();
}

DWORD CalcFuncCrc(PUCHAR funcBegin, PUCHAR funcEnd)
{
	CODEGARBAGEINIT();
	CODEGARBAGE();
	DWORD crc = 0;
	for (; funcBegin < funcEnd; ++funcBegin)
	{
		crc += *funcBegin;
	}
	return crc;
}
#pragma auto_inline(off)
void DebuggeeFunction()
{
	int calc = 0;
	calc += 2;
	calc <<= 8;
	calc -= 3;
}
void DebuggeeFunctionEnd()
{
};
#pragma auto_inline(on)
DWORD g_origCrc = 0x2bd0;

void CRCDebugCheck(bool check) {

	CODEGARBAGEINIT();
	CODEGARBAGE();

	DWORD crc = CalcFuncCrc((PUCHAR)DebuggeeFunction, (PUCHAR)DebuggeeFunctionEnd);
	if (g_origCrc != crc)
	{
		check = true;
	}

	CODEGARBAGE();
}

void AhlIsDebuggerPresent(bool& check) {
	CODEGARBAGEINIT();
	CODEGARBAGE();
	NTDebugCheck(check);
	if (IsDebuggerPresent() != 0) { check = true; }
	antihwdebug(check);
	CODEGARBAGE();
	TrapFlagCheck(check);
	CODEGARBAGE();
	RemoteDebuggerCheck(check);
	CODEGARBAGE();
	CODEGARBAGE();
	CRCDebugCheck(check);
	CODEGARBAGE();
	CODEGARBAGE();
	WindoWDebugCheck(check);
	CODEGARBAGE();
	CODEGARBAGE();
}

INLINE short   ZZ_ShortSwap(short l)
{
	byte    b1, b2;

	b1 = l & 255;
	b2 = (l >> 8) & 255;

	return (b1 << 8) + b2;
}

INLINE int    ZZ_LongSwap(int l)
{
	byte    b1, b2, b3, b4;

	b1 = l & 255;
	b2 = (l >> 8) & 255;
	b3 = (l >> 16) & 255;
	b4 = (l >> 24) & 255;

	return ((int)b1 << 24) + ((int)b2 << 16) + ((int)b3 << 8) + b4;
}

INLINE int ZZ_isprint(int c)
{
	if (c >= 0x20 && c <= 0x7E)
		return (1);
	return (0);
}

INLINE int ZZ_islower(int c)
{
	if (c >= 'a' && c <= 'z')
		return (1);
	return (0);
}

INLINE int ZZ_isupper(int c)
{
	if (c >= 'A' && c <= 'Z')
		return (1);
	return (0);
}

INLINE int ZZ_isalpha(int c)
{
	if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
		return (1);
	return (0);
}

INLINE bool ZZ_isanumber(const char* s)
{
	char* p;

	if (*s == '\0')
		return false;

	strtod(s, &p);

	return *p == '\0';
}

INLINE bool ZZ_isintegral(float f)
{
	return (int)f == f;
}

INLINE bool ZZ_isprintstring(char* s) {
	char* a = s;
	while (*a) {
		if (*a < 0x20 || *a > 0x7E) return 0;
		a++;
	}
	return 1;
}

INLINE int ZZ_stricmpn(const char* s1, const char* s2, int n) {
	int		c1, c2;

	if (s1 == NULL) {
		if (s2 == NULL)
			return 0;
		else
			return -1;
	}
	else if (s2 == NULL)
		return 1;



	do {
		c1 = *s1++;
		c2 = *s2++;

		if (!n--) {
			return 0;		// strings are equal until end point
		}

		if (c1 != c2) {
			if (c1 >= 'a' && c1 <= 'z') {
				c1 -= ('a' - 'A');
			}
			if (c2 >= 'a' && c2 <= 'z') {
				c2 -= ('a' - 'A');
			}
			if (c1 != c2) {
				return c1 < c2 ? -1 : 1;
			}
		}
	} while (c1);

	return 0;		// strings are equal
}

INLINE int ZZ_strncmp(const char* s1, const char* s2, int n) {
	int		c1, c2;

	do {
		c1 = *s1++;
		c2 = *s2++;

		if (!n--) {
			return 0;		// strings are equal until end point
		}

		if (c1 != c2) {
			return c1 < c2 ? -1 : 1;
		}
	} while (c1);

	return 0;		// strings are equal
}

INLINE char* ZZ_strlwr(char* s1) {
	char* s;

	s = s1;
	while (*s) {
		*s = *(s - 26);
		s++;
	}
	return s1;
}

INLINE char* ZZ_strupr(char* s1) {
	char* s;

	s = s1;
	while (*s) {
		*s = toupper(*s);
		s++;
	}
	return s1;
}

INLINE void ZZ_bstrcpy(char* dest, char* src) {

	while (*src)
		*dest++ = *src++;

	*dest = 0;
}

INLINE void ZZ_strlcat(char* dest, int size, const char* src, int cpylimit) {

	int		l1;

	l1 = strlen(dest);
	if (l1 >= size) {

	}

	if (cpylimit >= (size - l1) || cpylimit < 1) {
		cpylimit = size - l1 - 1;
	}

	memcpy(dest + l1, src, cpylimit);
	dest[l1 + cpylimit] = 0;
}

INLINE void ZZ_TrimCRLF(char* string)
{
	char* pos;
	int len;

	pos = strchr(string, '\n');
	if (pos)
	{
		*pos = '\0';
	}
	pos = strchr(string, '\r');
	if (pos)
	{
		*pos = '\0';
	}
	len = strlen(string);
	while (len > 0 && string[len - 1] == ' ')
	{
		string[len - 1] = '\0';
		len = strlen(string);
	}
}

INLINE int  ZZ_strichr(const char* s, char find)
{
	char sc;
	int i = 0;

	if (find >= 'a' && find <= 'z')
	{
		find -= ('a' - 'A');
	}

	while (true)
	{
		if ((sc = *s++) == 0)
			return -1;

		if (sc >= 'a' && sc <= 'z')
		{
			sc -= ('a' - 'A');
		}
		if (sc == find)
			return i;

		i++;
	}

	return -1;
}

INLINE int ZZ_CountChar(const char* string, char tocount)
{
	int count;

	for (count = 0; *string; string++)
	{
		if (*string == tocount)
			count++;
	}

	return count;
}

INLINE char* ZZ_ExpandNewlines(char* in) {
	char	string[1024];
	unsigned int		l;
	string[0] = '\0';

	l = 0;
	while (*in && l < sizeof(string) - 3) {
		if (*in == '\n') {
			string[l++] = '\\';
			string[l++] = 'n';
		}
		else {
			string[l++] = *in;
		}
		in++;
	}
	string[l] = 0;

	return in;
}

INLINE void ZZ_strchrrepl(char* string, char torepl, char repl) {
	for (; *string != 0x00; string++) {
		if (*string == torepl) {
			*string = repl;
		}
	}
}

INLINE bool ZZ_isNumeric(const char* string, int size) {
	const char* ptr;
	int i;

	if (size > 0) { //If we have given a length compare the whole string

		for (i = 0, ptr = string; i < size; i++, ptr++) {
			if (i == 0 && *ptr == '-') continue;
			if (*ptr < '0' || *ptr > '9') return false;
		}

	}
	else { //Search until the 1st space otherwise or null otherwise

		for (i = 0, ptr = string; *ptr != ' '; i++, ptr++) {
			if (i == 0 && *ptr == '-') continue;
			if (!*ptr && i > 0 && ptr[-1] != '-') return true;
			if (*ptr < '0' || *ptr > '9') return false;
		}
	}

	return true;
}

INLINE bool ZZ_IsEqualUnitWSpace(char* cmp1, char* cmp2)
{

	while (1)
	{
		if (!(*cmp1) || !(*cmp2))
			break;

		if (*cmp1 == ' ' || *cmp2 == ' ')
			break;

		if (*cmp1 != *cmp2)
			return false;

		cmp1++;
		cmp2++;
	}

	if (*cmp1 && *cmp1 != ' ')
	{
		return false;
	}
	if (*cmp2 && *cmp2 != ' ')
	{
		return false;
	}

	return 1;
}

INLINE bool ZZ_isFloat(const char* string, int size)
{
	const char* ptr;
	int i;
	bool dot = false;
	bool sign = false;
	bool whitespaceended = false;

	if (size == 0) //If we have given a length compare the whole string
		size = 0x10000;

	for (i = 0, ptr = string; i < size && *ptr != '\0' && *ptr != '\n'; i++, ptr++) {

		if (*ptr == ' ')
		{
			if (whitespaceended == false)
				continue;
			else
				return true;
		}
		whitespaceended = true;

		if (*ptr == '-' && sign == 0)
		{
			sign = true;
			continue;
		}
		if (*ptr == '.' && dot == 0)
		{
			dot = true;
			continue;
		}
		if (*ptr < '0' || *ptr > '9') return false;
	}
	return true;
}

INLINE bool ZZ_isInteger(const char* string, int size)
{
	const char* ptr;
	int i;
	bool sign = false;
	bool whitespaceended = false;

	if (size == 0) //If we have given a length compare the whole string
		size = 0x10000;

	for (i = 0, ptr = string; i < size && *ptr != '\0' && *ptr != '\n' && *ptr != '\r'; i++, ptr++) {

		if (*ptr == ' ')
		{
			if (whitespaceended == false)
				continue;
			else
				return true;
		}
		whitespaceended = true;

		if (*ptr == '-' && sign == 0)
		{
			sign = true;
			continue;
		}
		if (*ptr < '0' || *ptr > '9') return false;
	}
	return true;
}

INLINE bool ZZ_isVector(const char* string, int size, int dim)
{
	const char* ptr;
	int i;

	if (size == 0) //If we have given a length compare the whole string
		size = 0x10000;

	for (i = 0, ptr = string; i < size && *ptr != '\0' && *ptr != '\n' && dim > 0; i++, ptr++) {

		if (*ptr == ' ')
		{
			continue;
		}
		dim = dim - 1;

		if (ZZ_isFloat(ptr, size - i) == false)
			return false;

		while (*ptr != ' ' && *ptr != '\0' && *ptr != '\n' && i < size)
		{
			ptr++; i++;
		}
	}
	if (dim != 0)
		return false;

	return true;
}

INLINE bool ZZ_strToVect(const char* string, float* vect, int dim)
{
	const char* ptr;
	int i;

	for (ptr = string, i = 0; *ptr != '\0' && *ptr != '\n' && i < dim; ptr++) {

		if (*ptr == ' ')
		{
			continue;
		}

		vect[i] = atof(ptr);

		i++;

		while (*ptr != ' ' && *ptr != '\0' && *ptr != '\n')
		{
			ptr++;
		}
	}
	if (i != dim)
		return false;

	return true;
}

INLINE int ZZ_Compress(char* data_p) {
	char* datai, * datao;
	int c, size;
	bool ws = false;

	size = 0;
	datai = datao = data_p;
	if (datai) {
		while ((c = *datai) != 0) {
			if (c == 13 || c == 10) {
				*datao = c;
				datao++;
				ws = false;
				datai++;
				size++;
				// skip double slash comments
			}
			else if (c == '/' && datai[1] == '/') {
				while (*datai && *datai != '\n') {
					datai++;
				}
				ws = false;
				// skip /* */ comments
			}
			else if (c == '/' && datai[1] == '*') {
				while (*datai && (*datai != '*' || datai[1] != '/'))
				{
					datai++;
				}
				if (*datai) {
					datai += 2;
				}
				ws = false;
			}
			else {
				if (ws) {
					*datao = ' ';
					datao++;
				}
				*datao = c;
				datao++;
				datai++;
				ws = false;
				size++;
			}
		}
	}
	*datao = 0;
	return size;
}



///HWID PART
//GENERAL
void GetHostInfo(std::string& result); // gets Host Info in Plaintext
void GetGUID(std::string& result);// gets hashed Globally Unique Identifier of the current System. 
///
///
/// 
/// 
/// DISK
/// Serial
/// 
/// CPU
/// GHZ
/// Cores
/// 
/// GRAPHICSCARD
/// not yet
/// 
/// RAM
/// Amount (Physical)
/// 
/// MOTHERBOARD
/// not yet
/// 
/// 
/// 

#include <powrprof.h>
#pragma comment(lib, "Powrprof.lib")
#include <fstream>
#include <algorithm>
#include <cassert>
#include <iterator>
#include <vector>



#ifndef BUFFER_SIZE_FOR_INPUT_ITERATOR
#define BUFFER_SIZE_FOR_INPUT_ITERATOR \
    1048576  //=1024*1024: default is 1MB memory
#endif

typedef unsigned long word_t;
typedef unsigned char byte_t;

static const size_t k_digest_size = 32;

namespace detail {
	inline byte_t mask_8bit(byte_t x) { return x & 0xff; }

	inline word_t mask_32bit(word_t x) { return x & 0xffffffff; }

	const word_t add_constant[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
		0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
		0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
		0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
		0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
		0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
		0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

	const word_t initial_message_digest[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372,
											  0xa54ff53a, 0x510e527f, 0x9b05688c,
											  0x1f83d9ab, 0x5be0cd19 };

	inline word_t ch(word_t x, word_t y, word_t z) { return (x & y) ^ ((~x) & z); }

	inline word_t maj(word_t x, word_t y, word_t z) {
		return (x & y) ^ (x & z) ^ (y & z);
	}

	inline word_t rotr(word_t x, std::size_t n) {
		assert(n < 32);
		return mask_32bit((x >> n) | (x << (32 - n)));
	}

	inline word_t bsig0(word_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }

	inline word_t bsig1(word_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }

	inline word_t shr(word_t x, std::size_t n) {
		assert(n < 32);
		return x >> n;
	}

	inline word_t ssig0(word_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3); }

	inline word_t ssig1(word_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10); }

	template <typename RaIter1, typename RaIter2>
	void hash256_block(RaIter1 message_digest, RaIter2 first, RaIter2 last) {
		assert(first + 64 == last);
		static_cast<void>(last);  // for avoiding unused-variable warning
		word_t w[64];
		std::fill(w, w + 64, word_t(0));
		for (std::size_t i = 0; i < 16; ++i) {
			w[i] = (static_cast<word_t>(mask_8bit(*(first + i * 4))) << 24) |
				(static_cast<word_t>(mask_8bit(*(first + i * 4 + 1))) << 16) |
				(static_cast<word_t>(mask_8bit(*(first + i * 4 + 2))) << 8) |
				(static_cast<word_t>(mask_8bit(*(first + i * 4 + 3))));
		}
		for (std::size_t i = 16; i < 64; ++i) {
			w[i] = mask_32bit(ssig1(w[i - 2]) + w[i - 7] + ssig0(w[i - 15]) +
				w[i - 16]);
		}

		word_t a = *message_digest;
		word_t b = *(message_digest + 1);
		word_t c = *(message_digest + 2);
		word_t d = *(message_digest + 3);
		word_t e = *(message_digest + 4);
		word_t f = *(message_digest + 5);
		word_t g = *(message_digest + 6);
		word_t h = *(message_digest + 7);

		for (std::size_t i = 0; i < 64; ++i) {
			word_t temp1 = h + bsig1(e) + ch(e, f, g) + add_constant[i] + w[i];
			word_t temp2 = bsig0(a) + maj(a, b, c);
			h = g;
			g = f;
			f = e;
			e = mask_32bit(d + temp1);
			d = c;
			c = b;
			b = a;
			a = mask_32bit(temp1 + temp2);
		}
		*message_digest += a;
		*(message_digest + 1) += b;
		*(message_digest + 2) += c;
		*(message_digest + 3) += d;
		*(message_digest + 4) += e;
		*(message_digest + 5) += f;
		*(message_digest + 6) += g;
		*(message_digest + 7) += h;
		for (std::size_t i = 0; i < 8; ++i) {
			*(message_digest + i) = mask_32bit(*(message_digest + i));
		}
	}

}  // namespace detail

template <typename InIter>
void output_hex(InIter first, InIter last, std::ostream& os) {
	os.setf(std::ios::hex, std::ios::basefield);
	while (first != last) {
		os.width(2);
		os.fill('0');
		os << static_cast<unsigned int>(*first);
		++first;
	}
	os.setf(std::ios::dec, std::ios::basefield);
}

template <typename InIter>
void bytes_to_hex_string(InIter first, InIter last, std::string& hex_str) {
	std::ostringstream oss;
	output_hex(first, last, oss);
	hex_str.assign(oss.str());
}

template <typename InContainer>
void bytes_to_hex_string(const InContainer& bytes, std::string& hex_str) {
	bytes_to_hex_string(bytes.begin(), bytes.end(), hex_str);
}

template <typename InIter>
std::string bytes_to_hex_string(InIter first, InIter last) {
	std::string hex_str;
	bytes_to_hex_string(first, last, hex_str);
	return hex_str;
}

template <typename InContainer>
std::string bytes_to_hex_string(const InContainer& bytes) {
	std::string hex_str;
	bytes_to_hex_string(bytes, hex_str);
	return hex_str;
}

class hash256_one_by_one {
public:
	hash256_one_by_one() { init(); }

	void init() {
		buffer_.clear();
		std::fill(data_length_digits_, data_length_digits_ + 4, word_t(0));
		std::copy(detail::initial_message_digest,
			detail::initial_message_digest + 8, h_);
	}

	template <typename RaIter>
	void process(RaIter first, RaIter last) {
		add_to_data_length(static_cast<word_t>(std::distance(first, last)));
		std::copy(first, last, std::back_inserter(buffer_));
		std::size_t i = 0;
		for (; i + 64 <= buffer_.size(); i += 64) {
			detail::hash256_block(h_, buffer_.begin() + i,
				buffer_.begin() + i + 64);
		}
		buffer_.erase(buffer_.begin(), buffer_.begin() + i);
	}

	void finish() {
		byte_t temp[64];
		std::fill(temp, temp + 64, byte_t(0));
		std::size_t remains = buffer_.size();
		std::copy(buffer_.begin(), buffer_.end(), temp);
		temp[remains] = 0x80;

		if (remains > 55) {
			std::fill(temp + remains + 1, temp + 64, byte_t(0));
			detail::hash256_block(h_, temp, temp + 64);
			std::fill(temp, temp + 64 - 4, byte_t(0));
		}
		else {
			std::fill(temp + remains + 1, temp + 64 - 4, byte_t(0));
		}

		write_data_bit_length(&(temp[56]));
		detail::hash256_block(h_, temp, temp + 64);
	}

	template <typename OutIter>
	void get_hash_bytes(OutIter first, OutIter last) const {
		for (const word_t* iter = h_; iter != h_ + 8; ++iter) {
			for (std::size_t i = 0; i < 4 && first != last; ++i) {
				*(first++) = detail::mask_8bit(
					static_cast<byte_t>((*iter >> (24 - 8 * i))));
			}
		}
	}

private:
	void add_to_data_length(word_t n) {
		word_t carry = 0;
		data_length_digits_[0] += n;
		for (std::size_t i = 0; i < 4; ++i) {
			data_length_digits_[i] += carry;
			if (data_length_digits_[i] >= 65536u) {
				carry = data_length_digits_[i] >> 16;
				data_length_digits_[i] &= 65535u;
			}
			else {
				break;
			}
		}
	}
	void write_data_bit_length(byte_t* begin) {
		word_t data_bit_length_digits[4];
		std::copy(data_length_digits_, data_length_digits_ + 4,
			data_bit_length_digits);

		// convert byte length to bit length (multiply 8 or shift 3 times left)
		word_t carry = 0;
		for (std::size_t i = 0; i < 4; ++i) {
			word_t before_val = data_bit_length_digits[i];
			data_bit_length_digits[i] <<= 3;
			data_bit_length_digits[i] |= carry;
			data_bit_length_digits[i] &= 65535u;
			carry = (before_val >> (16 - 3)) & 65535u;
		}

		// write data_bit_length
		for (int i = 3; i >= 0; --i) {
			(*begin++) = static_cast<byte_t>(data_bit_length_digits[i] >> 8);
			(*begin++) = static_cast<byte_t>(data_bit_length_digits[i]);
		}
	}
	std::vector<byte_t> buffer_;
	word_t data_length_digits_[4];  // as 64bit integer (16bit x 4 integer)
	word_t h_[8];
};

inline void get_hash_hex_string(const hash256_one_by_one& hasher,
	std::string& hex_str) {
	byte_t hash[k_digest_size];
	hasher.get_hash_bytes(hash, hash + k_digest_size);
	return bytes_to_hex_string(hash, hash + k_digest_size, hex_str);
}

inline std::string get_hash_hex_string(const hash256_one_by_one& hasher) {
	std::string hex_str;
	get_hash_hex_string(hasher, hex_str);
	return hex_str;
}

namespace impl {
	template <typename RaIter, typename OutIter>
	void hash256_impl(RaIter first, RaIter last, OutIter first2, OutIter last2, int,
		std::random_access_iterator_tag) {
		hash256_one_by_one hasher;
		// hasher.init();
		hasher.process(first, last);
		hasher.finish();
		hasher.get_hash_bytes(first2, last2);
	}

	template <typename InputIter, typename OutIter>
	void hash256_impl(InputIter first, InputIter last, OutIter first2,
		OutIter last2, int buffer_size, std::input_iterator_tag) {
		std::vector<byte_t> buffer(buffer_size);
		hash256_one_by_one hasher;
		// hasher.init();
		while (first != last) {
			int size = buffer_size;
			for (int i = 0; i != buffer_size; ++i, ++first) {
				if (first == last) {
					size = i;
					break;
				}
				buffer[i] = *first;
			}
			hasher.process(buffer.begin(), buffer.begin() + size);
		}
		hasher.finish();
		hasher.get_hash_bytes(first2, last2);
	}
}

template <typename InIter, typename OutIter>
void hash256(InIter first, InIter last, OutIter first2, OutIter last2,
	int buffer_size = BUFFER_SIZE_FOR_INPUT_ITERATOR) {
	impl::hash256_impl(
		first, last, first2, last2, buffer_size,
		typename std::iterator_traits<InIter>::iterator_category());
}

template <typename InIter, typename OutContainer>
void hash256(InIter first, InIter last, OutContainer& dst) {
	hash256(first, last, dst.begin(), dst.end());
}

template <typename InContainer, typename OutIter>
void hash256(const InContainer& src, OutIter first, OutIter last) {
	hash256(src.begin(), src.end(), first, last);
}

template <typename InContainer, typename OutContainer>
void hash256(const InContainer& src, OutContainer& dst) {
	hash256(src.begin(), src.end(), dst.begin(), dst.end());
}

template <typename InIter>
void hash256_hex_string(InIter first, InIter last, std::string& hex_str) {
	byte_t hashed[k_digest_size];
	hash256(first, last, hashed, hashed + k_digest_size);
	std::ostringstream oss;
	output_hex(hashed, hashed + k_digest_size, oss);
	hex_str.assign(oss.str());
}

template <typename InIter>
std::string hash256_hex_string(InIter first, InIter last) {
	std::string hex_str;
	hash256_hex_string(first, last, hex_str);
	return hex_str;
}

inline void hash256_hex_string(const std::string& src, std::string& hex_str) {
	hash256_hex_string(src.begin(), src.end(), hex_str);
}

template <typename InContainer>
void hash256_hex_string(const InContainer& src, std::string& hex_str) {
	hash256_hex_string(src.begin(), src.end(), hex_str);
}

template <typename InContainer>
std::string hash256_hex_string(const InContainer& src) {
	return hash256_hex_string(src.begin(), src.end());
}
template<typename OutIter>void hash256(std::ifstream& f, OutIter first, OutIter last) {
	hash256(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>(), first, last);

}

char PC_Name[MAX_COMPUTERNAME_LENGTH + 1];
char Username_[16 + 1];
char CPU_clock[16];
std::string Ram_;

typedef struct _PROCESSOR_POWER_INFORMATION {
	ULONG  Number;
	ULONG  MaxMhz;
	ULONG  CurrentMhz;
	ULONG  MhzLimit;
	ULONG  MaxIdleState;
	ULONG  CurrentIdleState;
} PROCESSOR_POWER_INFORMATION, * PPROCESSOR_POWER_INFORMATION;

std::string intoStr(int in) {
	std::stringstream ss;
	ss << in;
	return ss.str();
}

void make_info()
{
	DWORD size;
	size = MAX_COMPUTERNAME_LENGTH + 1;
	GetComputerNameA(PC_Name, &size);
	size = 16 + 1;
	GetUserNameA(Username_, &size);
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);

	size = sysInfo.dwNumberOfProcessors * sizeof(PROCESSOR_POWER_INFORMATION);
	LPBYTE buf = new BYTE[size];
	CallNtPowerInformation(ProcessorInformation, NULL, 0, buf, size);
	PPROCESSOR_POWER_INFORMATION cpuinfo = (PPROCESSOR_POWER_INFORMATION)buf;
	std::string full_cpu_ratio = intoStr(cpuinfo->MaxMhz) + " GHz " + intoStr(sysInfo.dwNumberOfProcessors) + " Cores";
	full_cpu_ratio.erase(3, 1);
	full_cpu_ratio.insert(1, ".");
	memcpy(CPU_clock, full_cpu_ratio.c_str(), sizeof(full_cpu_ratio));
	
	MEMORYSTATUSEX statex;
	statex.dwLength = sizeof(statex);
	GlobalMemoryStatusEx(&statex);
	Ram_ += " Ram: " + intoStr(((statex.ullTotalPhys / 1024) / 1024)/ 1024); // round up  is needed I think 

}

void GetGUID(std::string& result)
{
	CODEGARBAGEINIT();
	CODEGARBAGE();
	make_info();
	DWORD disk_serialINT;
	GetVolumeInformationA(NULL, NULL, NULL, &disk_serialINT, NULL, NULL, NULL, NULL);
	std::string HDDserial = std::to_string(disk_serialINT);
	std::string ComputerName = PC_Name, Username = Username_, CPU = CPU_clock, Ram = Ram_;
	result = ComputerName;	result += Username;	result += HDDserial;
	result += CPU;	result += Ram;
	CODEGARBAGE();
	std::vector<unsigned char> hash(k_digest_size);
	hash256(result.begin(), result.end(), hash.begin(), hash.end());
	std::string hex_str = bytes_to_hex_string(hash.begin(), hash.end());
	result = (hex_str);
}

std::string GetHwInfo()
{
	CODEGARBAGEINIT();
	CODEGARBAGE();
	make_info();
	CODEGARBAGE();
	DWORD disk_serialINT;
	LPSTR disknametest = NULL;
	CHAR lpVolumeNameBuffer[MAX_PATH + 1];
	BOOL retVal;

	retVal = GetVolumeInformationA("C:\\", lpVolumeNameBuffer, sizeof(lpVolumeNameBuffer), &disk_serialINT, NULL, NULL, NULL, NULL);

	if (retVal == 0)
	{
		std::cout << XorStr("GetVolumeInformation failed with error ") << GetLastError() << std::endl;
	}
	std::string HDDserial = std::to_string(disk_serialINT);
	std::string ComputerName = PC_Name, Username = Username_, CPU = CPU_clock;
	std::string result = ComputerName;
	CODEGARBAGE();
	result += " ";
	result += Username;
	result += " ";
	result += HDDserial;
	result += " ";
	result += CPU;
	result += " ";
	result += Ram_;
	return (result);
}


void GetHostInfo(std::string& result) {
	CODEGARBAGEINIT();
	CODEGARBAGE();
	result = GetHwInfo();
	CODEGARBAGE();
}
