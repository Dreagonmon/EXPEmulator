_FOPEN		= (-1)	        #/* from sys/file.h, kernel use only */
_FREAD		= 0x0001	        #/* read enabled */
_FWRITE		= 0x0002	        #/* write enabled */
_FAPPEND	= 0x0008	        #/* append (writes guaranteed at the end) */
_FMARK		= 0x0010	        #/* internal; mark during gc() */
_FDEFER		= 0x0020	        #/* internal; defer for next gc pass */
_FASYNC		= 0x0040	        #/* signal pgrp when data ready */
_FSHLOCK	= 0x0080	        #/* BSD flock() shared lock present */
_FEXLOCK	= 0x0100	        #/* BSD flock() exclusive lock present */
_FCREAT		= 0x0200	        #/* open with file create */
_FTRUNC		= 0x0400	        #/* open with truncation */
_FEXCL		= 0x0800	        #/* error on open if file exists */
_FNBIO		= 0x1000	        #/* non blocking I/O (sys5 style) */
_FSYNC		= 0x2000	        #/* do all writes synchronously */
_FNONBLOCK	= 0x4000	        #/* non blocking I/O (POSIX style) */
_FNDELAY	= _FNONBLOCK	    #  /* non blocking I/O (4.2 style) */
_FNOCTTY	= 0x8000	        #/* don't assign a ctty on this open */

O_RDONLY	=   0		        #/* +1 == FREAD */
O_WRONLY	=   1		        #/* +1 == FWRITE */
O_RDWR		=   2		        #/* +1 == FREAD|FWRITE */
O_APPEND	=   _FAPPEND
O_CREAT		=   _FCREAT
O_TRUNC		=   _FTRUNC
O_EXCL		=   _FEXCL
O_SYNC		=   _FSYNC

O_NONBLOCK = _FNONBLOCK
O_NOCTTY   = _FNOCTTY

LL_SWI_BASE = 0xEE00
LLAPI_SWI_BASE = 0xD700

LLAPI_APP_DELAY_MS              =   (LLAPI_SWI_BASE + 1)
LLAPI_APP_STDOUT_PUTC           =   (LLAPI_SWI_BASE + 2)
LLAPI_APP_GET_RAM_SIZE          =   (LLAPI_SWI_BASE + 3)
LLAPI_APP_GET_TICK_MS           =   (LLAPI_SWI_BASE + 4)
LLAPI_APP_GET_TICK_US           =   (LLAPI_SWI_BASE + 5)
LLAPI_APP_DISP_PUT_P            =   (LLAPI_SWI_BASE + 6)
LLAPI_APP_DISP_PUT_HLINE        =   (LLAPI_SWI_BASE + 7)
LLAPI_APP_DISP_GET_P            =   (LLAPI_SWI_BASE + 8)
LLAPI_APP_QUERY_KEY             =   (LLAPI_SWI_BASE + 9)
LLAPI_APP_RTC_GET_S             =   (LLAPI_SWI_BASE + 10)
LLAPI_APP_RTC_SET_S             =   (LLAPI_SWI_BASE + 11) 
LLAPI_APP_IS_KEY_DOWN           =   (LLAPI_SWI_BASE + 13)
LLAPI_APP_DISP_PUT_KSTRING      =   (LLAPI_SWI_BASE + 14)
LLAPI_APP_DISP_CLEAN            =   (LLAPI_SWI_BASE + 15)
LLAPI_APP_DISP_PUT_HLINE_LEN    =   (LLAPI_SWI_BASE + 16)

LLAPI_MMAP          =   (LLAPI_SWI_BASE + 20)
LLAPI_MUNMAP        =   (LLAPI_SWI_BASE + 21)

LLAPI_THREAD_CREATE               =   (LLAPI_SWI_BASE + 160)
LLAPI_APP_EXIT                    =   (LLAPI_SWI_BASE + 161)
LLAPI_SET_PERF_LEVEL              =   (LLAPI_SWI_BASE + 170)

LL_SWI_ICACHE_INV       =       (LL_SWI_BASE + 117)
LL_SWI_DCACHE_CLEAN     =       (LL_SWI_BASE + 118)
LL_SWI_FS_SIZE          =      (LL_SWI_BASE + 119)
LL_SWI_FS_REMOVE        =      (LL_SWI_BASE + 120)
LL_SWI_FS_RENAME        =      (LL_SWI_BASE + 121)
LL_SWI_FS_STAT          =      (LL_SWI_BASE + 122)
LL_SWI_FS_OPEN          =      (LL_SWI_BASE + 123)
LL_SWI_FS_CLOSE         =      (LL_SWI_BASE + 124)
LL_SWI_FS_SYNC          =      (LL_SWI_BASE + 125)
LL_SWI_FS_READ          =      (LL_SWI_BASE + 126)
LL_SWI_FS_WRITE         =      (LL_SWI_BASE + 127)
LL_SWI_FS_SEEK          =      (LL_SWI_BASE + 128)
LL_SWI_FS_REWIND        =      (LL_SWI_BASE + 129)
LL_SWI_FS_TRUNCATE      =      (LL_SWI_BASE + 130)
LL_SWI_FS_TELL          =      (LL_SWI_BASE + 131)

LL_SWI_FS_DIR_MKDIR             =  (LL_SWI_BASE + 132)
LL_SWI_FS_DIR_OPEN              =  (LL_SWI_BASE + 133)
LL_SWI_FS_DIR_CLOSE             =  (LL_SWI_BASE + 134)
LL_SWI_FS_DIR_SEEK              =  (LL_SWI_BASE + 135)
LL_SWI_FS_DIR_TELL              =  (LL_SWI_BASE + 136)
LL_SWI_FS_DIR_REWIND            =  (LL_SWI_BASE + 137)
LL_SWI_FS_DIR_READ              =  (LL_SWI_BASE + 138)
LL_SWI_FS_DIR_GET_CUR_TYPE      =          (LL_SWI_BASE + 139)
LL_SWI_FS_DIR_GET_CUR_NAME      =          (LL_SWI_BASE + 140)
LL_SWI_FS_DIR_GET_CUR_SIZE      =          (LL_SWI_BASE + 141)
LL_SWI_FS_GET_FOBJ_SZ           =       (LL_SWI_BASE + 142)
LL_SWI_FS_GET_DIROBJ_SZ         =       (LL_SWI_BASE + 143)


