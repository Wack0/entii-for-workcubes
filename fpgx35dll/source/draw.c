#include "driver.h"
#include "runtime.h"
#include "texdraw.h"


static BOOL CopyBitsSwap32(
SURFOBJ  *psoDest,
SURFOBJ  *psoSrc,
CLIPOBJ  *pco,
XLATEOBJ *pxlo,
RECTL    *prclDest,
POINTL   *pptlSrc)
{
/*
	Copy 32bpp bitmap data endian swapped
*/
	
	LONG lDeltaSrc = psoSrc->lDelta;
	LONG lDeltaDst = psoDest->lDelta;
	
	if (pco != NULL &&  pco->iDComplexity != DC_TRIVIAL) {
		return FALSE;
	}
	
	if (prclDest->top >= prclDest->bottom) return TRUE;
	if (prclDest->left >= prclDest->right) return TRUE;
	
	
	LONG xDst = prclDest->left;
	LONG yDst = prclDest->top;
	LONG xSrc = pptlSrc->x + xDst - prclDest->left;
	LONG ySrc = pptlSrc->y + yDst - prclDest->top;
	
	LONG cx = prclDest->right - xDst;
	LONG cy = prclDest->bottom - yDst;
	
	LONG xSrcStart = xSrc;
	LONG xSrcEnd = xSrcStart + cx;
	LONG xDstStart = xDst;
	LONG yDstStart = prclDest->top;
	PBYTE pjSrc = ((PBYTE) psoSrc->pvScan0) + (ySrc * psoSrc->lDelta);
	PBYTE pjDst = ((PBYTE) psoDest->pvScan0) + (yDst * psoDest->lDelta);
	
	PULONG pulSrc = (PULONG) (pjSrc + (4 * xSrcStart));
	PULONG pulDst = (PULONG) (pjDst + (4 * xDstStart));
	PULONG pstartSrc = (PULONG) psoSrc->pvBits;
	PULONG pendSrc = (PULONG) ((PUCHAR) pstartSrc + psoSrc->cjBits);
	PULONG pstartDst = (PULONG) psoDest->pvBits;
	PULONG pendDst = (PULONG) ((PUCHAR) pstartDst + psoDest->cjBits);
	ULONG copyX = cx;
	ULONG copyY = cy;
	
	ULONG srcHeight = psoSrc->sizlBitmap.cy;
	ULONG srcWidth = psoSrc->sizlBitmap.cx;
	PBYTE pSrcFbStart = ((PBYTE) psoSrc->pvScan0);
	if (psoSrc->lDelta < 0) pSrcFbStart += (srcHeight * psoSrc->lDelta);
	PBYTE pDestFbStart = ((PBYTE) psoDest->pvScan0);
	ULONG destHeight = psoDest->sizlBitmap.cy;
	ULONG destWidth = psoDest->sizlBitmap.cx;
	if (psoDest->lDelta < 0) pDestFbStart += (destHeight * psoDest->lDelta);
	
	ULONG heightOffset = 0, widthOffset = 0;
	if (destHeight == 240) {
		heightOffset = (480 / 2) - (240 / 2);
		widthOffset = (640 / 2) - (320 / 2);
	}
	if ((heightOffset & 1) != 0) heightOffset--;
	if ((widthOffset & 1) != 0) widthOffset--;
	
	ULONG cyIdx = 0;
	while (1) {
		PULONG pulSrcTemp = pulSrc;
		PULONG pulDstTemp = pulDst;
		// Bounds check the pointers, we could be in here when drawing off the screen
		if (pulSrc >= pstartSrc && pulDst >= pstartDst) {
			ULONG TexOffsetY = CalculateTexYOffset32(yDstStart + cyIdx + heightOffset, 640);
			ULONG TexOffset = 0;
			
			ULONG cxTemp = cx;
			ULONG cxIdx = 0;
			BOOLEAN validAccess;
			// Read normally from source, write swapped to dest.
			while (cxTemp--) {
				validAccess = pulSrcTemp >= pstartSrc && pulDstTemp >= pstartDst &&
					pulSrcTemp < pendSrc && pulDstTemp < pendDst &&
					(xDst + cxIdx) < destWidth &&
					(yDst + cyIdx) < destHeight;
				if (validAccess) {
					ULONG sourceVal = LoadToRegister32(*pulSrcTemp);
					pulSrcTemp++;
					//EfbWrite32(pulDstTemp, sourceVal);
					//pulDstTemp++;
					TexOffset = CalculateTexOffsetWithYOffset32(xDst + cxIdx + widthOffset, TexOffsetY);
					if (((TexOffset & 3) == 0) && ((xDst + cxIdx) & 3) < 3 && (cxTemp > 1)) {
						// Will be writing the next pixel too, we can optimise this to two writes from four reads and four writes.
						ULONG sourceVal2 = LoadToRegister32(*pulSrcTemp);
						pulSrcTemp++;
						TexWriteRgb2Aligned(pDestFbStart, TexOffset, sourceVal, sourceVal2);
						cxIdx++;
						cxTemp--;
					} else {
						TexWriteRgb(pDestFbStart, TexOffset, sourceVal);
					}
				} else {
					pulSrcTemp++;
				}
				cxIdx++;
			}
		}
		
		cy--;
		cyIdx++;
		if (cy == 0) break;
		pulSrc = (PULONG) (((PBYTE)pulSrc) + lDeltaSrc);
		pulDst = (PULONG) (((PBYTE)pulDst) + lDeltaDst);
	}
	
	return TRUE;
}

static ULONG Rol32(ULONG Value, ULONG Count) {
	const ULONG mask = (8 * sizeof(Value) - 1);
	Count &= mask;
	return (Value << Count) | (Value >> ( (-Count) & mask));
}

static BOOL CopyBitsSwap16(
SURFOBJ  *psoDest,
SURFOBJ  *psoSrc,
CLIPOBJ  *pco,
XLATEOBJ *pxlo,
RECTL    *prclDest,
POINTL   *pptlSrc)
{
/*
	Copy 16bpp bitmap data endian swapped
*/
	
	LONG lDeltaSrc = psoSrc->lDelta;
	LONG lDeltaDst = psoDest->lDelta;
	
	if (pco != NULL &&  pco->iDComplexity != DC_TRIVIAL) {
		return FALSE;
	}
	
	if (prclDest->top >= prclDest->bottom) return TRUE;
	if (prclDest->left >= prclDest->right) return TRUE;
	
	
	LONG xDst = prclDest->left;
	LONG yDst = prclDest->top;
	LONG xSrc = pptlSrc->x + xDst - prclDest->left;
	LONG ySrc = pptlSrc->y + yDst - prclDest->top;
	
	LONG cx = prclDest->right - xDst;
	LONG cy = prclDest->bottom - yDst;
	
	LONG xSrcStart = xSrc;
	LONG xSrcEnd = xSrcStart + cx;
	LONG xDstStart = xDst;
	LONG yDstStart = prclDest->top;
	PBYTE pjSrc = ((PBYTE) psoSrc->pvScan0) + (ySrc * psoSrc->lDelta);
	PBYTE pjDst = ((PBYTE) psoDest->pvScan0) + (yDst * psoDest->lDelta);
	
	PUSHORT pusSrc = (PUSHORT) (pjSrc + (2 * xSrcStart));
	PUSHORT pusDst = (PUSHORT) (pjDst + (2 * xDstStart));
	PUSHORT pstartSrc = (PUSHORT) psoSrc->pvBits;
	PUSHORT pendSrc = (PUSHORT) ((PUCHAR) pstartSrc + psoSrc->cjBits);
	PUSHORT pstartDst = (PUSHORT) psoDest->pvBits;
	PUSHORT pendDst = (PUSHORT) ((PUCHAR) pstartDst + psoDest->cjBits);
	ULONG copyX = cx;
	ULONG copyY = cy;
	
	ULONG srcHeight = psoSrc->sizlBitmap.cy;
	ULONG srcWidth = psoSrc->sizlBitmap.cx;
	PBYTE pSrcFbStart = ((PBYTE) psoSrc->pvScan0);
	if (psoSrc->lDelta < 0) pSrcFbStart += (srcHeight * psoSrc->lDelta);
	PBYTE pDestFbStart = ((PBYTE) psoDest->pvScan0);
	ULONG destHeight = psoDest->sizlBitmap.cy;
	ULONG destWidth = psoDest->sizlBitmap.cx;
	if (psoDest->lDelta < 0) pDestFbStart += (destHeight * psoDest->lDelta);
	
	ULONG heightOffset = 0, widthOffset = 0;
	if (destHeight == 240) {
		heightOffset = (480 / 2) - (240 / 2);
		widthOffset = (640 / 2) - (320 / 2);
	}
	if ((heightOffset & 1) != 0) heightOffset--;
	if ((widthOffset & 1) != 0) widthOffset--;
	
	ULONG cyIdx = 0;
	while (1) {
		PUSHORT pusSrcTemp = pusSrc;
		PUSHORT pusDstTemp = pusDst;
		// Bounds check the pointers, we could be in here when drawing off the screen
		if (pusSrc >= pstartSrc && pusDst >= pstartDst) {
			ULONG TexOffsetY = CalculateTexYOffset16(yDstStart + cyIdx + heightOffset, 640);
			ULONG TexOffset = 0;
			
			ULONG cxTemp = cx;
			ULONG cxIdx = 0;
			BOOLEAN validAccess;
			// Read normally from source, write swapped to dest.
			while (cxTemp--) {
				validAccess = pusSrcTemp >= pstartSrc && pusDstTemp >= pstartDst &&
					pusSrcTemp < pendSrc && pusDstTemp < pendDst &&
					(xDst + cxIdx) < destWidth &&
					(yDst + cyIdx) < destHeight;
				if (validAccess) {
					//EfbWrite32(pulDstTemp, sourceVal);
					//pulDstTemp++;
					TexOffset = CalculateTexOffsetWithYOffset16(xDst + cxIdx + widthOffset, TexOffsetY);
					if (((TexOffset & 3) == 0) && ((xDst + cxIdx) & 3) < 3 && (cxTemp > 1)) {
						// Will be writing the next pixel too, optimise to a single write from one read and one write
						ULONG sourceVal2 = LoadToRegister32(*(PULONG)pusSrcTemp);
						pusSrcTemp += 2;
						NativeWriteBase32(pDestFbStart, TexOffset, Rol32(sourceVal2, 16));
						//TexWriteRgb5652Aligned(pDestFbStart, TexOffset, sourceVal, sourceVal2);
						cxIdx++;
						cxTemp--;
					} else {
						USHORT sourceVal = (USHORT)LoadToRegister32(*pusSrcTemp);
						pusSrcTemp++;
						TexWriteRgb565(pDestFbStart, TexOffset, sourceVal);
					}
				} else {
					pusSrcTemp++;
				}
				cxIdx++;
			}
		}
		
		cy--;
		cyIdx++;
		if (cy == 0) break;
		pusSrc = (PUSHORT) (((PBYTE)pusSrc) + lDeltaSrc);
		pusDst = (PUSHORT) (((PBYTE)pusDst) + lDeltaDst);
	}
	
	return TRUE;
}

static BOOL CopyBitsSwap8(
SURFOBJ  *psoDest,
SURFOBJ  *psoSrc,
CLIPOBJ  *pco,
XLATEOBJ *pxlo,
RECTL    *prclDest,
POINTL   *pptlSrc)
{
/*
	Copy 8bpp colour-table indexed bitmap data endian swapped
*/
	
	LONG lDeltaSrc = psoSrc->lDelta;
	LONG lDeltaDst = psoDest->lDelta;
	
	if (pco != NULL &&  pco->iDComplexity != DC_TRIVIAL) {
		return FALSE;
	}
	
	if (prclDest->top >= prclDest->bottom) return TRUE;
	if (prclDest->left >= prclDest->right) return TRUE;
	
	
	LONG xDst = prclDest->left;
	LONG yDst = prclDest->top;
	LONG xSrc = pptlSrc->x + xDst - prclDest->left;
	LONG ySrc = pptlSrc->y + yDst - prclDest->top;
	
	LONG cx = prclDest->right - xDst;
	LONG cy = prclDest->bottom - yDst;
	
	LONG xSrcStart = xSrc;
	LONG xSrcEnd = xSrcStart + cx;
	LONG xDstStart = xDst;
	LONG yDstStart = prclDest->top;
	PBYTE pjSrc = ((PBYTE) psoSrc->pvScan0) + (ySrc * lDeltaSrc);
	PBYTE pjDst = ((PBYTE) psoDest->pvScan0) + (yDst * lDeltaDst);
	
	PUCHAR pucSrc = (PUCHAR) (pjSrc + (xSrcStart));
	PUCHAR pucDst = (PUCHAR) (pjDst + (xDstStart));
	PUCHAR pstartSrc = (PUCHAR) psoSrc->pvBits;
	PUCHAR pendSrc = (PUCHAR) ((PUCHAR) pstartSrc + psoSrc->cjBits);
	PUCHAR pstartDst = (PUCHAR) psoDest->pvBits;
	PUCHAR pendDst = (PUCHAR) ((PUCHAR) pstartDst + psoDest->cjBits);
	ULONG copyX = cx;
	ULONG copyY = cy;
	
	ULONG srcHeight = psoSrc->sizlBitmap.cy;
	ULONG srcWidth = psoSrc->sizlBitmap.cx;
	PBYTE pSrcFbStart = ((PBYTE) psoSrc->pvScan0);
	if (lDeltaSrc < 0) pSrcFbStart += (srcHeight * lDeltaSrc);
	PBYTE pDestFbStart = ((PBYTE) psoDest->pvScan0);
	ULONG destHeight = psoDest->sizlBitmap.cy;
	ULONG destWidth = psoDest->sizlBitmap.cx;
	if (lDeltaDst < 0) pDestFbStart += (destHeight * lDeltaDst);
	
	ULONG heightOffset = 0, widthOffset = 0;
	if (destHeight == 240) {
		heightOffset = (480 / 2) - (240 / 2);
		widthOffset = (640 / 2) - (320 / 2);
	}
	if ((heightOffset & 3) != 0) heightOffset -= (4 - (heightOffset & 3));
	if ((widthOffset & 3) != 0) widthOffset -= (4 - (widthOffset & 3));
	
	ULONG cyIdx = 0;
	while (1) {
		PUCHAR pucSrcTemp = pucSrc;
		PUCHAR pucDstTemp = pucDst;
		// Bounds check the pointers, we could be in here when drawing off the screen
		if (pucSrc >= pstartSrc && pucDst >= pstartDst) {
			ULONG TexOffsetY = CalculateTexYOffset8(yDstStart + cyIdx + heightOffset, 640);
			ULONG TexOffset = 0;
			
			ULONG cxTemp = cx;
			ULONG cxIdx = 0;
			BOOLEAN validAccess;
			// Read normally from source, write swapped to dest.
			while (cxTemp--) {
				validAccess = pucSrcTemp >= pstartSrc && pucDstTemp >= pstartDst &&
					pucSrcTemp < pendSrc && pucDstTemp < pendDst &&
					(xDst + cxIdx) < destWidth &&
					(yDst + cyIdx) < destHeight;
				if (validAccess) {
					//EfbWrite32(pulDstTemp, sourceVal);
					//pulDstTemp++;
					TexOffset = CalculateTexOffsetWithYOffset8(xDst + cxIdx + widthOffset, TexOffsetY);
					if (((TexOffset & 3) == 0) && ((xDst + cxIdx) & 7) < 5 && (cxTemp > 3)) {
						// Writing aligned at least four pixels.
						// Optimise to a single write
						ULONG sourceVal32 = __builtin_bswap32(*(PULONG)pucSrcTemp);
						pucSrcTemp += 4;
						/*
						sourceVal2 = (UCHAR)LoadToRegister32(*pucSrcTemp);
						pucSrcTemp++;
						sourceVal3 = (UCHAR)LoadToRegister32(*pucSrcTemp);
						pucSrcTemp++;
						UCHAR sourceVal4 = (UCHAR)LoadToRegister32(*pucSrcTemp);
						pucSrcTemp++;
						TexWriteCi84Aligned(pDestFbStart, TexOffset, sourceVal, sourceVal2, sourceVal3, sourceVal4);
						*/
						NativeWriteBase32(pDestFbStart, TexOffset, sourceVal32);
						cxIdx += 3;
						cxTemp -= 3;
					} else
					{
						
						UCHAR sourceVal = (UCHAR)LoadToRegister32(*pucSrcTemp);
						USHORT sourceVal2 = 0x100, sourceVal3 = 0x100;
						pucSrcTemp++;
						// Read up to two more pixels where possible. (optimise to one read and one write where unaligned)
						ULONG TexOffsetByte = TexOffset & 3;
						if (((TexOffsetByte + 1) < 4) && (((xDst + cxIdx) & 3) < 3) && (cxTemp > 1)) {
							sourceVal2 = (UCHAR)LoadToRegister32(*pucSrcTemp);
							pucSrcTemp++;
							if (((TexOffsetByte + 2) < 4) && (((xDst + cxIdx) & 3) < 2) && (cxTemp > 2)) {
								sourceVal3 = (UCHAR)LoadToRegister32(*pucSrcTemp);
								pucSrcTemp++;
								cxIdx++;
								cxTemp--;
							}
							cxIdx++;
							cxTemp--;
						}
						TexWriteCi8(pDestFbStart, TexOffset, sourceVal, sourceVal2, sourceVal3);
					}
				} else {
					pucSrcTemp++;
				}
				cxIdx++;
			}
		}
		
		cy--;
		cyIdx++;
		if (cy == 0) break;
		pucSrc = (PUCHAR) (((PBYTE)pucSrc) + lDeltaSrc);
		pucDst = (PUCHAR) (((PBYTE)pucDst) + lDeltaDst);
	}
	
	return TRUE;
}

BOOL CopyBitsSwap(
SURFOBJ  *psoDest,
SURFOBJ  *psoSrc,
CLIPOBJ  *pco,
XLATEOBJ *pxlo,
RECTL    *prclDest,
POINTL   *pptlSrc)
{
	RECTL rcl;
	POINTL point = {0};
	
	if (pco == NULL || pco->iDComplexity == DC_TRIVIAL) {
		rcl.left = max(0, prclDest->left);
		rcl.top = max(0, prclDest->top);
		rcl.right = min(psoDest->sizlBitmap.cx, prclDest->right);
		rcl.bottom = min(psoDest->sizlBitmap.cy, prclDest->bottom);
	} else {
		rcl.left = max(pco->rclBounds.left, prclDest->left);
		rcl.top = max(pco->rclBounds.top, prclDest->top);
		rcl.right = min(pco->rclBounds.right, prclDest->right);
		rcl.bottom = min(pco->rclBounds.bottom, prclDest->bottom);
	}
	
	if (rcl.top >= rcl.bottom) return TRUE;
	if (rcl.left >= rcl.right) return TRUE;
	
	if (pptlSrc == NULL) {
		pptlSrc = &point;
		point.x = rcl.left;
		point.y = rcl.top;
	}
	
	switch (psoSrc->iBitmapFormat) {
		default:
			return FALSE;
		case BMF_8BPP:
			return CopyBitsSwap8(psoDest, psoSrc, NULL, NULL, &rcl, pptlSrc);
		case BMF_16BPP:
			return CopyBitsSwap16(psoDest, psoSrc, NULL, NULL, &rcl, pptlSrc);
		case BMF_32BPP:
			return CopyBitsSwap32(psoDest, psoSrc, NULL, NULL, &rcl, pptlSrc);
	}
}

enum {
	STYPE_OURSURFACE = STYPE_DEVICE
};

BOOL DrvCopyBits(
SURFOBJ  *psoDest,
SURFOBJ  *psoSrc,
CLIPOBJ  *pco,
XLATEOBJ *pxlo,
RECTL    *prclDest,
POINTL   *pptlSrc)
{

/*
	DrvCopyBits translates between device-managed raster surfaces and
	GDI standard-format bitmaps. This function is required for a device driver
	that has device-managed bitmaps or raster surfaces.
	The implementation in the driver must translate driver surfaces to and from
	any standard-format bitmap.
	
	Standard-format bitmaps are single-plane, packed-pixel format. Each scan line is
	aligned on a four-byte boundary. These bitmaps have
	1, 4, 8, 16, 24, 32, or 64 bits per pixel.
	
	This function should ideally be able to deal with RLE and device-dependent
	bitmaps. (See the Windows NT SDK.) The device-dependent format is optional;
	only a few specialized drivers need to support it. These bitmaps may be sent
	to this function as a result of the following GDI functions:
	SetDIBits, SetDIBitsToDevice, GetDIBits, SetBitmapBits, and GetBitmapBits.
*/

	// If both surfaces are not device managed, just call original func:
	if (psoDest->iType != STYPE_OURSURFACE && psoSrc->iType != STYPE_OURSURFACE) {
		return EngCopyBits(psoDest, psoSrc, pco, pxlo, prclDest, pptlSrc);
	}
	
	// Get the pdev. At least one of dest or src must be devbitmap.
	PPDEV ppDev = NULL;
	if (psoDest->iType == STYPE_OURSURFACE) ppDev = (PPDEV)psoDest->dhpdev;
	else if (psoSrc->iType == STYPE_OURSURFACE) ppDev = (PPDEV)psoSrc->dhpdev;
	else {
		// Should never get here.
		return FALSE;
	}
	
	// Both surfaces are device mapped
	if (psoDest->iType == STYPE_OURSURFACE && psoSrc->iType == STYPE_OURSURFACE) {
		// Proxy through the double buffer.
		psoDest = ppDev->psurfDouble;
		psoSrc = ppDev->psurfDouble;
		if (!EngCopyBits(psoDest, psoSrc, pco, pxlo, prclDest, pptlSrc)) {
			return FALSE;
		}
		psoDest = ppDev->psurfBigFb;
		return CopyBitsSwap(psoDest, psoSrc, pco, NULL, prclDest, NULL);
	}
	
	// Copying to framebuffer
	if (psoDest->iType == STYPE_OURSURFACE) {
		// Source is always going to be a 32bpp bitmap
		// Proxy through the double buffer.
		psoDest = ppDev->psurfDouble;
		if (!EngCopyBits(psoDest, psoSrc, pco, pxlo, prclDest, pptlSrc)) {
			return FALSE;
		}
		psoSrc = psoDest;
		psoDest = ppDev->psurfBigFb;
		return CopyBitsSwap(psoDest, psoSrc, pco, NULL, prclDest, NULL);
	}
	
	// Copying from framebuffer
	if (psoSrc->iType == STYPE_OURSURFACE) {
		// Dest is always going to be a 32bpp bitmap
		// Proxy through the double buffer.
		psoSrc = ppDev->psurfDouble;
		return EngCopyBits(psoDest, psoSrc, pco, pxlo, prclDest, pptlSrc);
	}
	
	// Should never get here.
	return FALSE;
}

BOOL DrvStrokePath(
SURFOBJ*   pso,
PATHOBJ*   ppo,
CLIPOBJ*   pco,
XFORMOBJ*  pxo,
BRUSHOBJ*  pbo,
POINTL*    pptlBrush,
LINEATTRS* pla,
MIX        mix)
{
	/*
		DrvStrokePath strokes a path when called by GDI.
		If the driver has hooked the function,
		and if the appropriate GCAPs are set,
		GDI calls DrvStrokePath when GDI draws a line or curve
		with any set of attributes.
	*/
	
	if (pso->iType != STYPE_OURSURFACE) {
		// Not device managed, call original function
		return EngStrokePath(pso, ppo, pco, pxo, pbo, pptlBrush, pla, mix);
	}
	
	PPDEV ppdev = (PPDEV)pso->dhpdev;
	
	// Get the path bounds, convert it into a rect
	RECTFX PathBounds;
	RECTL destRect;
	PATHOBJ_vGetBounds(ppo, &PathBounds);
	destRect.left = (PathBounds.xLeft >> 4);
	destRect.top = (PathBounds.yTop >> 4);
	destRect.right = (PathBounds.xRight >> 4) + 2;
	destRect.bottom = (PathBounds.yBottom >> 4) + 2;
	
	// Call via the double buffer
	if (!EngStrokePath(ppdev->psurfDouble, ppo, pco, pxo, pbo, pptlBrush, pla, mix)) {
		return FALSE;
	}
	
	// Copy back to the framebuffer
	return CopyBitsSwap(ppdev->psurfBigFb, ppdev->psurfDouble, pco, NULL, &destRect, NULL);
}

BOOL DrvTextOut(
SURFOBJ*  pso,
STROBJ*   pstro,
FONTOBJ*  pfo,
CLIPOBJ*  pco,
RECTL*    prclExtra,
RECTL*    prclOpaque,
BRUSHOBJ* pboFore,
BRUSHOBJ* pboOpaque,
POINTL*   pptlOrg,
MIX       mix)
{
	/*
		DrvTextOut is the entry point from GDI that calls for the driver to
		render a set of glyphs at specified positions.
	*/
	
	if (pso->iType != STYPE_OURSURFACE) {
		// Not device managed, call original function
		return EngTextOut(pso, pstro, pfo, pco, prclExtra, prclOpaque, pboFore, pboOpaque, pptlOrg, mix);
	}
	
	// Copy to the double buffer
	RECTL* prclDest = (prclOpaque != NULL) ? prclOpaque : &pstro->rclBkGround;
	PPDEV ppdev = (PPDEV)pso->dhpdev;
	
	RECTL rclDest;
	memcpy(&rclDest, prclDest, sizeof(rclDest));
	
	// Call via the double buffer
	if (!EngTextOut(ppdev->psurfDouble, pstro, pfo, pco, prclExtra, prclOpaque, pboFore, pboOpaque, pptlOrg, mix)) {
		return FALSE;
	}
	
	// Copy back to the framebuffer
	return CopyBitsSwap(ppdev->psurfBigFb, ppdev->psurfDouble, pco, NULL, &rclDest, NULL);
}

BOOL DrvBitBlt(
SURFOBJ  *psoDest,	
SURFOBJ  *psoSrc,	
SURFOBJ  *psoMask,	
CLIPOBJ  *pco,	
XLATEOBJ  *pxlo,	
RECTL  *prclDest,	
POINTL  *pptlSrc,	
POINTL  *pptlMask,	
BRUSHOBJ  *pbo,	
POINTL  *pptlBrush,	
ROP4  rop4	
) {
	/*
		DrvBitBlt provides general bit-block transfer capabilities between device-managed surfaces,
		between GDI-managed standard-format bitmaps, or between a device-managed surface and a GDI-managed standard-format bitmap.
	*/
	
	// If both surfaces are not device managed, just call original func:
	if (psoDest->iType != STYPE_OURSURFACE && (psoSrc == NULL || psoSrc->iType != STYPE_OURSURFACE)) {
		return EngBitBlt(psoDest, psoSrc, psoMask, pco, pxlo, prclDest, pptlSrc, pptlMask, pbo, pptlBrush, rop4);
	}
	
	// Get the pdev. At least one of dest or src must be devbitmap.
	PPDEV ppDev = NULL;
	if (psoDest->iType == STYPE_OURSURFACE) ppDev = (PPDEV)psoDest->dhpdev;
	else if (psoSrc != NULL && psoSrc->iType == STYPE_OURSURFACE) ppDev = (PPDEV)psoSrc->dhpdev;
	else {
		// Should never get here.
		return FALSE;
	}
	
	// Both surfaces are device mapped
	if (psoDest->iType == STYPE_OURSURFACE && (psoSrc == NULL || psoSrc->iType == STYPE_OURSURFACE)) {
		// Proxy through the double buffer.
		psoDest = ppDev->psurfDouble;
		if (psoSrc != NULL) psoSrc = ppDev->psurfDouble;
		if (!EngBitBlt(psoDest, psoSrc, psoMask, pco, pxlo, prclDest, pptlSrc, pptlMask, pbo, pptlBrush, rop4)) {
			return FALSE;
		}
		psoDest = ppDev->psurfBigFb;
		psoSrc = ppDev->psurfDouble;
		return CopyBitsSwap(psoDest, psoSrc, pco, NULL, prclDest, NULL);
	}
	
	// Drawing to framebuffer
	if (psoDest->iType == STYPE_OURSURFACE) {
		// Source is always going to be a 32bpp bitmap
		// Proxy through the double buffer.
		psoDest = ppDev->psurfDouble;
		if (!EngBitBlt(psoDest, psoSrc, psoMask, pco, pxlo, prclDest, pptlSrc, pptlMask, pbo, pptlBrush, rop4)) {
			return FALSE;
		}
		psoSrc = psoDest;
		psoDest = ppDev->psurfBigFb;
		return CopyBitsSwap(psoDest, psoSrc, pco, NULL, prclDest, NULL);
	}
	
	// Drawing from framebuffer
	if (psoSrc != NULL && psoSrc->iType == STYPE_OURSURFACE) {
		// Dest is always going to be a 32bpp bitmap
		// Proxy through the double buffer.
		psoSrc = ppDev->psurfDouble;
		return EngBitBlt(psoDest, psoSrc, psoMask, pco, pxlo, prclDest, pptlSrc, pptlMask, pbo, pptlBrush, rop4);
	}
	
	// Should never get here.
	return FALSE;
}

BOOL DrvStretchBlt(
SURFOBJ  *psoDest,	
SURFOBJ  *psoSrc,	
SURFOBJ  *psoMask,	
CLIPOBJ  *pco,	
XLATEOBJ  *pxlo,	
COLORADJUSTMENT  *pca,	
POINTL  *pptlHTOrg,	
RECTL  *prclDest,	
RECTL  *prclSrc,	
POINTL  *pptlMask,	
ULONG  iMode	
) {
	/*
		DrvStretchBlt provides stretching bit-block transfer capabilities between any combination of device-managed and GDI-managed surfaces.
		This function enables the device driver to write to GDI bitmaps, especially when the driver can do halftoning.
		This function allows the same halftoning algorithm to be applied to GDI bitmaps and device surfaces.
	*/
	
	// If both surfaces are not device managed, just call original func:
	if (psoDest->iType != STYPE_OURSURFACE && (psoSrc == NULL || psoSrc->iType != STYPE_OURSURFACE)) {
		return EngStretchBlt(psoDest, psoSrc, psoMask, pco, pxlo, pca, pptlHTOrg, prclDest, prclSrc, pptlMask, iMode);
	}
	
	// Get the pdev. At least one of dest or src must be devbitmap.
	PPDEV ppDev = NULL;
	if (psoDest->iType == STYPE_OURSURFACE) ppDev = (PPDEV)psoDest->dhpdev;
	else if (psoSrc != NULL && psoSrc->iType == STYPE_OURSURFACE) ppDev = (PPDEV)psoSrc->dhpdev;
	else {
		// Should never get here.
		return FALSE;
	}
	
	// Both surfaces are device mapped
	if (psoDest->iType == STYPE_OURSURFACE && (psoSrc == NULL || psoSrc->iType != STYPE_OURSURFACE)) {
		// Proxy through the double buffer.
		psoDest = ppDev->psurfDouble;
		if (psoSrc != NULL) psoSrc = ppDev->psurfDouble;
		if (!EngStretchBlt(psoDest, psoSrc, psoMask, pco, pxlo, pca, pptlHTOrg, prclDest, prclSrc, pptlMask, iMode)) {
			return FALSE;
		}
		psoDest = ppDev->psurfBigFb;
		psoSrc = ppDev->psurfDouble;
		return CopyBitsSwap(psoDest, psoSrc, pco, NULL, prclDest, NULL);
	}
	
	// Drawing to framebuffer
	if (psoDest->iType == STYPE_OURSURFACE) {
		// Source is always going to be a 32bpp bitmap
		// Proxy through the double buffer.
		psoDest = ppDev->psurfDouble;
		if (!EngStretchBlt(psoDest, psoSrc, psoMask, pco, pxlo, pca, pptlHTOrg, prclDest, prclSrc, pptlMask, iMode)) {
			return FALSE;
		}
		psoSrc = psoDest;
		psoDest = ppDev->psurfBigFb;
		return CopyBitsSwap(psoDest, psoSrc, pco, NULL, prclDest, NULL);
	}
	
	// Drawing from framebuffer
	if (psoSrc != NULL && psoSrc->iType == STYPE_OURSURFACE) {
		// Dest is always going to be a 32bpp bitmap
		// Proxy through the double buffer.
		psoSrc = ppDev->psurfDouble;
		return EngStretchBlt(psoDest, psoSrc, psoMask, pco, pxlo, pca, pptlHTOrg, prclDest, prclSrc, pptlMask, iMode);
	}
	
	// Should never get here.
	return FALSE;
}

BOOL DrvPaint(
SURFOBJ  *pso,	
CLIPOBJ  *pco,	
BRUSHOBJ  *pbo,	
POINTL  *pptlBrushOrg,	
MIX  mix	
) {
	/*
		DrvPaint paints a specified region. This function is required if any drawing is to be done on a device-managed surface.
	*/
	
	if (pso->iType != STYPE_OURSURFACE) {
		return EngPaint(pso, pco, pbo, pptlBrushOrg, mix);
	}
	
	PPDEV ppdev = (PPDEV)pso->dhpdev;
	
	// Call via the double buffer
	if (!EngPaint(ppdev->psurfDouble, pco, pbo, pptlBrushOrg, mix)) {
		return FALSE;
	}
	
	// Copy back to the framebuffer
	return CopyBitsSwap(ppdev->psurfBigFb, ppdev->psurfDouble, pco, NULL, &pco->rclBounds, NULL);
}

BOOL DrvFillPath(
SURFOBJ  *pso,	
PATHOBJ  *ppo,	
CLIPOBJ  *pco,	
BRUSHOBJ  *pbo,	
POINTL  *pptlBrushOrg,	
MIX  mix,	
FLONG  flOptions	
) {
	/*
		DrvFillPath is an optional entry point to handle the filling of closed paths.
	*/
	
	if (pso->iType != STYPE_OURSURFACE) {
		return EngFillPath(pso, ppo, pco, pbo, pptlBrushOrg, mix, flOptions);
	}
	
	PPDEV ppdev = (PPDEV)pso->dhpdev;
	
	// Call via the double buffer
	if (!EngFillPath(ppdev->psurfDouble, ppo, pco, pbo, pptlBrushOrg, mix, flOptions)) {
		return FALSE;
	}
	
	// Get the path bounds, convert it into a rect
	RECTFX PathBounds;
	RECTL destRect;
	PATHOBJ_vGetBounds(ppo, &PathBounds);
	destRect.left = (PathBounds.xLeft >> 4);
	destRect.top = (PathBounds.yTop >> 4);
	destRect.right = (PathBounds.xRight >> 4) + 2;
	destRect.bottom = (PathBounds.yBottom >> 4) + 2;
	EngDeletePath(ppo);
	
	// Copy back to the framebuffer
	return CopyBitsSwap(ppdev->psurfBigFb, ppdev->psurfDouble, pco, NULL, &destRect, NULL);
}

BOOL DrvStrokeAndFillPath(
SURFOBJ  *pso,	
PATHOBJ  *ppo,	
CLIPOBJ  *pco,	
XFORMOBJ  *pxo,	
BRUSHOBJ  *pboStroke,	
LINEATTRS  *plineattrs,	
BRUSHOBJ  *pboFill,	
POINTL  *pptlBrushOrg,	
MIX  mixFill,	
FLONG  flOptions	
) {
	/*
		DrvStrokeAndFillPath fills and strokes a path concurrently.
	*/
	
	if (pso->iType != STYPE_OURSURFACE) {
		// Not device managed, call original function
		return EngStrokeAndFillPath(pso, ppo, pco, pxo, pboStroke, plineattrs, pboFill, pptlBrushOrg, mixFill, flOptions);
	}
	
	PPDEV ppdev = (PPDEV)pso->dhpdev;
	
	// Get the path bounds, convert it into a rect
	RECTFX PathBounds;
	RECTL destRect;
	PATHOBJ_vGetBounds(ppo, &PathBounds);
	destRect.left = (PathBounds.xLeft >> 4);
	destRect.top = (PathBounds.yTop >> 4);
	destRect.right = (PathBounds.xRight >> 4) + 2;
	destRect.bottom = (PathBounds.yBottom >> 4) + 2;
	
	// Call via the double buffer
	if (!EngStrokeAndFillPath(ppdev->psurfDouble, ppo, pco, pxo, pboStroke, plineattrs, pboFill, pptlBrushOrg, mixFill, flOptions)) {
		return FALSE;
	}
	
	// Copy back to the framebuffer
	return CopyBitsSwap(ppdev->psurfBigFb, ppdev->psurfDouble, pco, NULL, &destRect, NULL);
}