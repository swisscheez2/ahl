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
//         To work with them you need a wrapper function that takes a const char*
//         as parameter and passes it to printf and alike.
//
//         The Microsoft Compiler/Linker is not working correctly with variadic 
//         templates!
//  
//         Use the functions below or use std::cout (and similar)!
//--------------------------------------------------------------------------------

static auto w_printf = [](const char* fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vprintf_s(fmt, args);
	va_end(args);
};

static auto w_printf_s = [](const char* fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vprintf_s(fmt, args);
	va_end(args);
};


static auto w_sprintf_s = [](char* buf, size_t buf_size, const char* fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vsprintf_s(buf, buf_size, fmt, args);
	va_end(args);
};

static auto w_sprintf_s_ret = [](char* buf, size_t buf_size, const char* fmt, ...) {
	int ret;
	va_list args;
	va_start(args, fmt);
	ret = vsprintf_s(buf, buf_size, fmt, args);
	va_end(args);
	return ret;
};

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

	pfnNtQueryInformationProcess NtQueryInformationProcess = NULL;
	NTSTATUS status;
	DWORD isDebuggerPresent = 0;
	HMODULE hNtDll = LoadLibraryA((XorStr("ntdll.dll")));

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

	DWORD crc = CalcFuncCrc((PUCHAR)DebuggeeFunction, (PUCHAR)DebuggeeFunctionEnd);
	if (g_origCrc != crc)
	{
		check = true;
	} 

}

__declspec(noinline) void AhlIsDebuggerPresent(bool &check) {
	CODEGARBAGEINIT();
	CODEGARBAGE();
	NTDebugCheck(check);
	if (IsDebuggerPresent() != 0)
	{
		check = true;
	}
	CODEGARBAGE();
	TrapFlagCheck(check);
	CODEGARBAGE();
	RemoteDebuggerCheck(check);
	CODEGARBAGE();
	CODEGARBAGE();
	CRCDebugCheck(check);
	CODEGARBAGE();
	antihwdebug(check);
	CODEGARBAGE();
	WindoWDebugCheck(check);
	CODEGARBAGE();
	CODEGARBAGE();
	antihwdebug(check);
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