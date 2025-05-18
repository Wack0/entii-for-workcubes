/*
 *   OpenBIOS native timer driver
 *
 *   (C) 2004 Stefan Reinauer
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "types.h"
#include "timer.h"

static unsigned long timer_freq = 0;
static unsigned long timer_freq_usecs = 0;

#define ticks_to_microsecs(ticks)	((((uint64_t)(ticks)*8)/(uint64_t)((timer_freq/1000)/125)))
#define microsecs_to_ticks(usec)	(((uint64_t)(usec)*((timer_freq/1000)/125))/8)

void setup_timers(ULONG DecrementerFreq)
{
	timer_freq = DecrementerFreq;
	timer_freq_usecs = DecrementerFreq / 1000000;
}

void udelay(unsigned int usecs)
{
	_wait_ticks(timer_freq_usecs * usecs);
}

unsigned long long currticks(void) {
	unsigned long long _get_ticks(void);
	return _get_ticks();
}

unsigned long long currusecs(void) {
	//return ticks_to_microsecs(currticks());
	if (timer_freq_usecs == 40) return currticks() / 40;
	if (timer_freq_usecs == 60) return currticks() / 60;
	return currticks() / (unsigned long long)timer_freq_usecs;
}

unsigned long currmsecs(void) {
	return (unsigned long)(currusecs() / 1000);
}

void ndelay(unsigned int nsecs)
{
	udelay((nsecs + 999) / 1000);
}

void mdelay(unsigned int msecs)
{
	udelay(msecs * 1000);
}

