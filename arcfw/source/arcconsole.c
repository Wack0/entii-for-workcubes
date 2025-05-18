// Forked from the libogc console.c,
// changes made to imitate what an existing ARC firmware implementation does.

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include "arc.h"
#include "arcconsole.h"
#include "runtime.h"

#define FONT_XSIZE		8
#define FONT_YSIZE		16
#define FONT_XFACTOR	1
#define FONT_YFACTOR	1
#define FONT_XGAP			0
#define FONT_YGAP			0
#define TAB_SIZE			4

typedef struct _console_data_s {
	void* destbuffer;
	unsigned char* font;
	int con_xres, con_yres, con_stride;
	int target_x, target_y, tgt_stride;
	int cursor_row, cursor_col;
	int saved_row, saved_col;
	int con_rows, con_cols;

	int foreground, background;
	unsigned int real_foreground, real_background;
	bool high_intensity, underscore, reverse;
} console_data_s;

//color table
static const unsigned int color_table_yuv[] =
{
  0x10801080,		// 30 normal black
  0x316D31B8,		// 31 normal red
  0x515B5151,		// 32 normal green
  0x71487189,		// 33 normal yellow
  0x1DB81D77,		// 34 normal blue
  0x3DA53DAF,		// 35 normal magenta
  0x5D935D48,		// 36 normal cyan
  0xB580B580,		// 37 normal white
  0x7E807E80,		// 30 bright black
  0x515A51F0,		// 31 bright red
  0x91369122,		// 32 bright green
  0xD210D292,		// 33 bright yellow
  0x29F0296E,		// 34 bright blue
  0x6ACA6ADE,		// 35 bright magenta
  0xAAA6AA10,		// 36 bright cyan
  0xEB80EB80,		// 37 bright white
};

static const unsigned int color_table_rgb[] =
{
  0x00000000,		// 30 normal black
  0x00aa0000,		// 31 normal red
  0x0000aa00,		// 32 normal green
  0x00aaaa00,		// 33 normal yellow
  0x000000aa,		// 34 normal blue
  0x00aa00aa,		// 35 normal magenta
  0x0000aaaa,		// 36 normal cyan
  0x00aaaaaa,		// 37 normal white
  0x00555555,		// 30 bright black
  0x00ff5555,		// 31 bright red
  0x0055ff55,		// 32 bright green
  0x00ffff55,		// 33 bright yellow
  0x005555ff,		// 34 bright blue
  0x00ff55ff,		// 35 bright magenta
  0x0055ffff,		// 36 bright cyan
  0x00ffffff,		// 37 bright white
};

static struct _console_data_s stdcon;
static struct _console_data_s* curr_con = NULL;
ULONG g_framebuffer_phys = 0;

static bool s_is_rgb = false;

#define color_table (s_is_rgb ? color_table_rgb : color_table_yuv)

extern u8 console_font_8x16[];


static void __console_drawc(int c)
{
	console_data_s* con;
	int ay;
	unsigned int* ptr;
	unsigned char* pbits;
	unsigned char bits;
	unsigned int color;
	unsigned int fgcolor, bgcolor;
	unsigned int nextline;

	if (!curr_con) return;
	con = curr_con;

	if (s_is_rgb) ptr = (unsigned int*)(con->destbuffer + (con->con_stride * con->cursor_row * FONT_YSIZE) + ((con->cursor_col * FONT_XSIZE) * 4));
	else {
		ptr = (unsigned int*)(
			con->destbuffer +
			(con->con_stride * con->cursor_row * FONT_YSIZE) +
			((con->cursor_col * FONT_XSIZE / 2) * 4) +
			(con->target_y * con->con_stride) + (con->target_x * 2)
			);
	}
	pbits = &con->font[c * FONT_YSIZE];
	nextline = con->con_stride;
	fgcolor = con->real_foreground;
	bgcolor = con->real_background;

	for (ay = 0; ay < FONT_YSIZE; ay++)
	{
		/* hard coded loop unrolling ! */
		/* this depends on FONT_XSIZE = 8*/
#if FONT_XSIZE == 8
		bits = *pbits++;
		unsigned int* ptrOld = ptr;
		color = 0;

#define PLOT_FLAG(x) do {\
	if (s_is_rgb) {\
		if (bits & (x)) color = fgcolor;\
		else color = bgcolor;\
		*ptr = color;\
		/* NativeWrite32(ptr, color); */\
		ptr++;\
		break;\
	}\
	unsigned int mask = 0xFFFF00FF;\
	if ((x) & 0x55) mask = 0x0000FF00;\
	if (bits & (x)) color |= fgcolor & mask;\
	else color |= bgcolor & mask;\
} while (0)

#define WRITE_FB() do {\
	if (s_is_rgb) break;\
	NativeWrite32(ptr, color);\
	ptr++;\
	color = 0;\
} while (0)

		/* bits 1 & 2 */
		PLOT_FLAG(0x80);
		PLOT_FLAG(0x40);
		WRITE_FB();

		/* bits 3 & 4 */
		PLOT_FLAG(0x20);
		PLOT_FLAG(0x10);
		WRITE_FB();

		/* bits 5 & 6 */
		PLOT_FLAG(0x08);
		PLOT_FLAG(0x04);
		WRITE_FB();

		/* bits 7 & 8 */
		PLOT_FLAG(0x02);
		PLOT_FLAG(0x01);
		WRITE_FB();

		/* next line */
		ptr = (unsigned int*)((ULONG)ptrOld + nextline);
#else
#endif
	}
}
static void __console_clear_line(int line, int from, int to) {
	console_data_s* con;
	unsigned int c;
	unsigned int* p;
	unsigned int x_pixels;
	unsigned int px_per_col = FONT_XSIZE;
	unsigned int line_height = FONT_YSIZE;
	unsigned int line_width;

	if (!(con = curr_con)) return;
	// For some reason there are xres/2 pixels per screen width
	x_pixels = con->con_xres;

	line_width = (to - from) * px_per_col;
	p = (unsigned int*)con->destbuffer;

	// Move pointer to the current line and column offset
	p += line * (FONT_YSIZE * x_pixels) + from * px_per_col;

	// Clears 1 line of pixels at a time, line_height times
	while (line_height--) {
		c = line_width;
		while (c--) {
			NativeWrite32(p, con->real_background);
			p++;
		}
		p -= line_width;
		p += x_pixels;
	}
}
static void __console_clear(void)
{
	console_data_s* con;
	unsigned int c;
	unsigned int* p;

	if (!(con = curr_con)) return;

	c = (con->con_xres * con->con_yres);
	p = (unsigned int*)con->destbuffer;

	while (c--) {
		NativeWrite32(p, con->real_background);
		p++;
	}

	con->cursor_row = 0;
	con->cursor_col = 0;
	con->saved_row = 0;
	con->saved_col = 0;
}
static void __console_clear_from_cursor(void) {
	console_data_s* con;
	int cur_row;

	if (!(con = curr_con)) return;
	cur_row = con->cursor_row;

	__console_clear_line(cur_row, con->cursor_col, con->con_cols);

	while (cur_row++ < con->con_rows)
		__console_clear_line(cur_row, 0, con->con_cols);

}
static void __console_clear_to_cursor(void) {
	console_data_s* con;
	int cur_row;

	if (!(con = curr_con)) return;
	cur_row = con->cursor_row;

	__console_clear_line(cur_row, 0, con->cursor_col);

	while (cur_row--)
		__console_clear_line(cur_row, 0, con->con_cols);
}

void ArcConsoleUseRgb(void) {
	s_is_rgb = true;
}

void ArcConsoleInit(void* framebuffer, int xstart, int ystart, int xres, int yres, int stride)
{
	console_data_s* con = &stdcon;

	g_framebuffer_phys = (ULONG)MEM_K1_TO_PHYSICAL(framebuffer);
	con->destbuffer = framebuffer;
	con->con_xres = xres;
	con->con_yres = yres;
	con->con_cols = (xres - xstart) / FONT_XSIZE;
	con->con_rows = (yres - ystart) / FONT_YSIZE;
	con->con_stride = con->tgt_stride = stride;
	con->target_x = xstart;
	con->target_y = ystart;
	con->cursor_row = 0;
	con->cursor_col = 0;
	con->saved_row = 0;
	con->saved_col = 0;

	con->font = console_font_8x16;

	con->foreground = 7;
	con->background = 0;
	con->real_foreground = color_table[7];
	con->real_background = color_table[0];
	con->high_intensity = false;
	con->underscore = false;
	con->reverse = false;

	curr_con = con;
	
	__console_clear();
}

static int __console_parse_escsequence(const BYTE* pchr)
{
	BYTE chr;
	console_data_s* con;
	int i;
	int parameters[3];
	int para;

	if (!curr_con) return -1;
	con = curr_con;

	/* set default value */
	para = 0;
	parameters[0] = 0;
	parameters[1] = 0;
	parameters[2] = 0;

	/* scan parameters */
	i = 0;
	chr = *pchr;
	while ((para < 3) && (chr >= '0') && (chr <= '9'))
	{
		while ((chr >= '0') && (chr <= '9'))
		{
			/* parse parameter */
			parameters[para] *= 10;
			parameters[para] += chr - '0';
			pchr++;
			i++;
			chr = *pchr;
		}
		para++;

		if (*pchr == ';')
		{
			/* skip parameter delimiter */
			pchr++;
			i++;
		}
		chr = *pchr;
	}

	/* get final character */
	chr = *pchr++;
	i++;
	switch (chr)
	{
		/////////////////////////////////////////
		// Cursor directional movement
		/////////////////////////////////////////
	case 'A':
	{
		curr_con->cursor_row -= parameters[0];
		if (curr_con->cursor_row < 0) curr_con->cursor_row = 0;
		break;
	}
	case 'B':
	{
		curr_con->cursor_row += parameters[0];
		if (curr_con->cursor_row >= curr_con->con_rows) curr_con->cursor_row = curr_con->con_rows - 1;
		break;
	}
	case 'C':
	{
		curr_con->cursor_col += parameters[0];
		if (curr_con->cursor_col >= curr_con->con_cols) curr_con->cursor_col = curr_con->con_cols - 1;
		break;
	}
	case 'D':
	{
		curr_con->cursor_col -= parameters[0];
		if (curr_con->cursor_col < 0) curr_con->cursor_col = 0;
		break;
	}
	/////////////////////////////////////////
	// Cursor position movement
	/////////////////////////////////////////
	case 'H':
	case 'f':
	{
		if (parameters[0] != 0) parameters[0]--;
		if (parameters[1] != 0) parameters[1]--;
		curr_con->cursor_col = parameters[1];
		curr_con->cursor_row = parameters[0];
		if (curr_con->cursor_row >= curr_con->con_rows) curr_con->cursor_row = curr_con->con_rows - 1;
		if (curr_con->cursor_col >= curr_con->con_cols) curr_con->cursor_col = curr_con->con_cols - 1;
		break;
	}
	/////////////////////////////////////////
	// Screen clear
	/////////////////////////////////////////
	case 'J':
	{
		if (parameters[0] == 0)
			__console_clear_from_cursor();
		else if (parameters[0] == 1)
			__console_clear_to_cursor();
		else
			__console_clear();

		break;
	}
	/////////////////////////////////////////
	// Line clear
	/////////////////////////////////////////
	case 'K':
	{
		if (parameters[0] == 0)
			__console_clear_line(curr_con->cursor_row, curr_con->cursor_col, curr_con->con_cols);
		else if (parameters[0] == 1)
			__console_clear_line(curr_con->cursor_row, 0, curr_con->cursor_col);
		else
			__console_clear_line(curr_con->cursor_row, 0, curr_con->con_cols);

		break;
	}
	/////////////////////////////////////////
	// Save cursor position
	/////////////////////////////////////////
	case 's':
	{
		con->saved_col = con->cursor_col;
		con->saved_row = con->cursor_row;
		break;
	}
	/////////////////////////////////////////
	// Load cursor position
	/////////////////////////////////////////
	case 'u':
		con->cursor_col = con->saved_col;
		con->cursor_row = con->saved_row;
		break;
		/////////////////////////////////////////
		// SGR Select Graphic Rendition
		/////////////////////////////////////////
	case 'm':
	{
		// handle 0 disable attributes
		if (parameters[0] == 0) {
			con->high_intensity = con->underscore = con->reverse = false;
		}
		// handle 1 enable high intensity
		else if (parameters[0] == 1) {
			con->high_intensity = true;
		}
		// handle 4 enable underscore
		else if (parameters[0] == 4) {
			con->underscore = true;
		}
		// handle 7 enable reverse
		else if (parameters[0] == 7) {
			con->reverse = true;
		}
		// handle 30-37 for foreground color changes
		else if ((parameters[0] >= 30) && (parameters[0] <= 37))
		{
			parameters[0] -= 30;

			if (parameters[1] == 1)
			{
				// Intensity: Bold makes color bright
				con->high_intensity = true;
			}
			con->foreground = parameters[0];
		}
		// handle 40-47 for background color changes
		else if ((parameters[0] >= 40) && (parameters[0] <= 47))
		{
			parameters[0] -= 40;

			con->background = parameters[0];
		}

		// recompute real foreground/background
		con->real_foreground = con->foreground;
		con->real_background = con->background;
		if (con->high_intensity) con->real_foreground += 8;
		if (con->reverse) {
			con->real_background = con->real_foreground;
			con->real_foreground = con->background;
		}
		con->real_background = color_table[con->real_background];
		con->real_foreground = color_table[con->real_foreground];
		break;
	}
	}

	return(i);
}

int ArcConsoleWrite(const BYTE* ptr, size_t len)
{
	size_t i = 0;
	const BYTE* tmp = ptr;
	console_data_s* con;
	BYTE chr;

	if (!curr_con) return -1;
	con = curr_con;
	if (!tmp || len <= 0) return -1;

	i = 0;
	while (*tmp != '\0' && i < len)
	{
		chr = *tmp++;
		i++;
		if (chr == 0x9b || ((chr == 0x1b) && (*tmp == '[')))
		{
			/* escape sequence found */
			int k;

			if (chr != 0x9b) {
				tmp++;
				i++;
			}
			k = __console_parse_escsequence(tmp);
			tmp += k;
			i += k;
		}
		else
		{
			switch (chr)
			{
			case '\n':
			case 0xb: // VT
			case '\f': // FF
				con->cursor_row++;
				break;
			case '\r':
				con->cursor_col = 0;
				break;
			case '\b':
				con->cursor_col--;
				if (con->cursor_col < 0)
				{
					con->cursor_col = 0;
				}
				break;
			case '\t':
				if (con->cursor_col % TAB_SIZE) con->cursor_col += (con->cursor_col % TAB_SIZE);
				else con->cursor_col += TAB_SIZE;
				break;
			default:
				__console_drawc(chr);
				con->cursor_col++;

				if (con->cursor_col >= con->con_cols)
				{
					con->cursor_col = con->con_cols - 1; // do not wrap around, says jazz arc fw impl
				}
			}
		}

		if (con->cursor_row >= con->con_rows)
		{
			/* if bottom border reached scroll */
#if 1
			ULONG srcPtr = (ULONG)con->destbuffer + con->con_stride * (FONT_YSIZE * FONT_YFACTOR + FONT_YGAP);
			for (ULONG destPtr = (ULONG)con->destbuffer; destPtr < (ULONG)con->destbuffer + con->con_stride * con->con_yres - FONT_YSIZE; srcPtr += 4, destPtr += 4) {
				NativeWrite32((PVOID)destPtr, NativeRead32((PVOID)srcPtr));
			}
#else
			memcpy(con->destbuffer,
				con->destbuffer + con->con_stride * (FONT_YSIZE * FONT_YFACTOR + FONT_YGAP),
				con->con_stride * con->con_yres - FONT_YSIZE);
#endif

			unsigned int cnt = (con->con_stride * (FONT_YSIZE * FONT_YFACTOR + FONT_YGAP)) / 4;
			unsigned int* ptr = (unsigned int*)(con->destbuffer + con->con_stride * (con->con_yres - FONT_YSIZE));
			while (cnt--) {
				NativeWrite32(ptr, con->real_background);
				ptr++;
			}
			con->cursor_row--;
		}
	}

	return i;
}

void ArcConsoleGetStatus(PARC_DISPLAY_STATUS Status) {
	if (curr_con == NULL) return;
	Status->CursorXPosition = curr_con->cursor_col;
	Status->CursorYPosition = curr_con->cursor_row;
	Status->CursorMaxXPosition = curr_con->con_cols;
	Status->CursorMaxYPosition = curr_con->con_rows;
	Status->ForegroundColor = curr_con->foreground;
	Status->BackgroundColor = curr_con->background;
	Status->HighIntensity = curr_con->high_intensity;
	Status->Underscored = curr_con->underscore;
	Status->ReverseVideo = curr_con->reverse;
}
