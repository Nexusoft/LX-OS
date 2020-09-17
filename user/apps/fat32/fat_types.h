#ifndef __FAT_TYPES_H__
#define __FAT_TYPES_H__

#define PDEBUG_CODE_TRACE

#ifdef PDEBUG_CODE_TRACE

#define pwhr() printf("%s() :==> %d\n", __FUNCTION__,__LINE__)
#define pmsg(fmt, ...) printf( fmt, ## __VA_ARGS__)
#else
#define pwhr()
#define pmsg(fmt, ...)
#endif

//-------------------------------------------------------------
// System specific types
//-------------------------------------------------------------
#ifndef BYTE
	typedef unsigned char BYTE;
#endif

#ifndef UINT16
	typedef unsigned short UINT16;
#endif

#ifndef UINT32
	typedef unsigned long UINT32;
#endif

#ifndef TRUE
	#define TRUE 1
#endif

#ifndef FALSE
	#define FALSE 0
#endif

#ifndef NULL
	#define NULL 0
#endif

//-------------------------------------------------------------
// Structure Packing Compile Options
//-------------------------------------------------------------
#define STRUCT_PACK	
#define STRUCT_PACK_BEGIN	
#define STRUCT_PACK_END		

#endif
