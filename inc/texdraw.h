#pragma once

static ULONG CalculateTexOffset32(ULONG x, ULONG y, ULONG width) {
	return (((y >> 2) << 4) * width) +
		((x >> 2) << 6) +
		(((y % 4 << 2) + x % 4) << 1);
}

static ULONG CalculateTexYOffset32(ULONG y, ULONG width) {
	return (((y >> 2) << 4) * width) +
		(((y & 3) << 2) << 1);
}

static ULONG CalculateTexOffsetWithYOffset32(ULONG x, ULONG yOffset) {
	return yOffset +
		((x >> 2) << 6) +
		((x & 3) << 1);
}

static ULONG CalculateTexOffset16(ULONG x, ULONG y, ULONG width) {
	return (((y >> 2) << 3) * width) +
		((x >> 2) << 5) +
		(((y % 4 << 2) + x % 4) << 1);
}

static ULONG CalculateTexYOffset16(ULONG y, ULONG width) {
	return (((y >> 2) << 3) * width) +
		(((y & 3) << 2) << 1);
}

static ULONG CalculateTexOffsetWithYOffset16(ULONG x, ULONG yOffset) {
	return yOffset +
		((x >> 2) << 5) +
		((x & 3) << 1);
}

static ULONG CalculateTexYOffset8(ULONG y, ULONG width) {
	return ((y & ~3) * width) +
		((y & 3) << 3);
}

static ULONG CalculateTexOffsetWithYOffset8(ULONG x, ULONG yOffset) {
	return yOffset +
		((x & ~7) << 2) +
		(x & 7);
}

static ULONG TexReadRgb(PUCHAR pTex, ULONG offset) {
	ULONG r = NativeReadBase8(pTex, offset + 1);
	ULONG gb = NativeReadBase16(pTex, offset + 32);
	return (r << 16) | gb;
}

static void TexWriteRgb(PUCHAR pTex, ULONG offset, ULONG rgb) {
	if ((offset & 3) != 0) {
		// offset must be at +2
		ULONG offset32 = offset & ~3;
		ULONG value = NativeReadBase32(pTex, offset32);
		value &= 0xFFFF0000;
		value |= 0xFF00 | (rgb >> 16);
		ULONG value2 = NativeReadBase32(pTex, offset32 + 0x20);
		value2 &= 0xFFFF0000;
		value2 |= (rgb & 0xFFFF);
		NativeWriteBase32(pTex, offset32, value);
		NativeWriteBase32(pTex, offset32 + 0x20, value2);
	} else {
		ULONG value = NativeReadBase32(pTex, offset);
		value &= 0x0000FFFF;
		value |= (0xFF000000 | (rgb & 0xFF0000));
		ULONG value2 = NativeReadBase32(pTex, offset + 0x20);
		value2 &= 0x0000FFFF;
		value2 |= (rgb & 0xFFFF) << 16;
		NativeWriteBase32(pTex, offset, value);
		NativeWriteBase32(pTex, offset + 0x20, value2);
	}
}

static void TexWriteRgb565(PUCHAR pTex, ULONG offset, USHORT rgb565) {
	if ((offset & 3) != 0) {
		// offset must be at +2
		ULONG offset32 = offset & ~3;
		ULONG value = NativeReadBase32(pTex, offset32);
		value &= 0xFFFF0000;
		value |= rgb565;
		NativeWriteBase32(pTex, offset32, value);
	} else {
		ULONG value = NativeReadBase32(pTex, offset);
		value &= 0x0000FFFF;
		value |= (ULONG)rgb565 << 16;
		NativeWriteBase32(pTex, offset, value);
	}
}

static void TexWriteCi8(PUCHAR pTex, ULONG offset, UCHAR ci8, USHORT ci8_2, USHORT ci8_3) {
	ULONG offset32 = offset & ~3;
	ULONG offsetPx = (offset & 3);
	ULONG offsetMask = 0xFF << ((3 - offsetPx) << 3);
	ULONG valueOr = (ULONG)ci8 << ((3 - offsetPx) << 3);
	if ((ci8_2 & ~0xFF) == 0) {
		offsetMask |= 0xFF << ((3 - (offsetPx + 1)) << 3);
		valueOr |= (ULONG)ci8_2 << ((3 - (offsetPx + 1)) << 3);
	}
	if ((ci8_3 & ~0xFF) == 0) {
		offsetMask |= 0xFF << ((3 - (offsetPx + 2)) << 3);
		valueOr |= (ULONG)ci8_3 << ((3 - (offsetPx + 2)) << 3);
	}
	ULONG value = NativeReadBase32(pTex, offset32);
	value &= ~offsetMask;
	value |= valueOr;
	
	NativeWriteBase32(pTex, offset32, value);
}

static void TexWriteRgb2Aligned(PUCHAR pTex, ULONG offset, ULONG rgb0, ULONG rgb1) {
	ULONG value = 0xFF00FF00 | (rgb1 >> 16) | (rgb0 & 0xFF0000);
	ULONG value2 = ((rgb0 & 0xFFFF) << 16) | (rgb1 & 0xFFFF);
	NativeWriteBase32(pTex, offset, value);
	NativeWriteBase32(pTex, offset + 0x20, value2);
}

static void TexWriteRgb5652Aligned(PUCHAR pTex, ULONG offset, USHORT rgb0, USHORT rgb1) {
	ULONG value = ((ULONG)rgb0 << 16) | (ULONG)rgb1;
	NativeWriteBase32(pTex, offset, value);
}

static void TexWriteCi84Aligned(PUCHAR pTex, ULONG offset, UCHAR ci8, UCHAR ci8_2, UCHAR ci8_3, UCHAR ci8_4) {
	ULONG value = ((ULONG)ci8 << 24) | ((ULONG)ci8_2 << 16) | ((ULONG)ci8_3 << 8) | (ULONG)ci8_4;
	NativeWriteBase32(pTex, offset, value);
}
