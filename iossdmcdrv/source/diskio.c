/*-----------------------------------------------------------------------*/
/* Low level disk I/O module SKELETON for FatFs     (C)ChaN, 2019        */
/*-----------------------------------------------------------------------*/
/* If a working storage control module is available, it should be        */
/* attached to the FatFs via a glue function rather than modifying it.   */
/* This is an example of glue functions to attach various exsisting      */
/* storage control modules to the FatFs module with a defined API.       */
/*-----------------------------------------------------------------------*/

#include "ff.h"			/* Obtains integer types */
#include "diskio.h"		/* Declarations of disk functions */

BYTE SdmcFfsStatus(void);
DSTATUS SdmcFfsInit(void);
DRESULT SdmcFfsRead(void* buff, DWORD sector, DWORD count, void* mdl);
DRESULT SdmcFfsWrite(const void* buff, DWORD sector, DWORD count, void* mdl);
DRESULT SdmcFfsCopy(void* dest, void* src, DWORD count, DWORD toMdl);
DRESULT SdmcFfsIoctl(BYTE cmd, void* buff);

/*-----------------------------------------------------------------------*/
/* Get Drive Status                                                      */
/*-----------------------------------------------------------------------*/

DSTATUS disk_status (
	BYTE pdrv		/* Physical drive nmuber to identify the drive */
)
{
	return SdmcFfsStatus();
}



/*-----------------------------------------------------------------------*/
/* Inidialize a Drive                                                    */
/*-----------------------------------------------------------------------*/

DSTATUS disk_initialize (
	BYTE pdrv				/* Physical drive nmuber to identify the drive */
)
{
	return SdmcFfsInit();
}



/*-----------------------------------------------------------------------*/
/* Read Sector(s)                                                        */
/*-----------------------------------------------------------------------*/

DRESULT disk_read (
	BYTE pdrv,		/* Physical drive nmuber to identify the drive */
	BYTE *buff,		/* Data buffer to store read data */
	LBA_t sector,	/* Start sector in LBA */
	UINT count,		/* Number of sectors to read */
	void* mdl /* NT Memory descritor list describing physical area of buffer */
)
{
	return SdmcFfsRead(buff, sector, count, mdl);
}



/*-----------------------------------------------------------------------*/
/* Write Sector(s)                                                       */
/*-----------------------------------------------------------------------*/

#if FF_FS_READONLY == 0

DRESULT disk_write (
	BYTE pdrv,			/* Physical drive nmuber to identify the drive */
	const BYTE *buff,	/* Data to be written */
	LBA_t sector,		/* Start sector in LBA */
	UINT count,			/* Number of sectors to write */
	void* mdl /* NT Memory descritor list describing physical area of buffer */
)
{
	return SdmcFfsWrite(buff, sector, count, mdl);
}

#endif

DRESULT plat_copy(
	void* dest, // Destination buffer or MDL
	void* source, // Source buffer or MDL
	UINT count, // Number of bytes to copy
	UINT toMdl // Destination is MDL, otherwise source is MDL
)
{
	return SdmcFfsCopy(dest, source, count, toMdl);
}


/*-----------------------------------------------------------------------*/
/* Miscellaneous Functions                                               */
/*-----------------------------------------------------------------------*/

DRESULT disk_ioctl (
	BYTE pdrv,		/* Physical drive nmuber (0..) */
	BYTE cmd,		/* Control code */
	void *buff		/* Buffer to send/receive control data */
)
{
	return SdmcFfsIoctl(cmd, buff);
}

