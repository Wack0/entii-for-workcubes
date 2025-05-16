
void ArcConsoleUseRgb(void);

void ArcConsoleInit(void* framebuffer, int xstart, int ystart, int xres, int yres, int stride);

int ArcConsoleWrite(const BYTE* ptr, size_t len);

void ArcConsoleGetStatus(PARC_DISPLAY_STATUS Status);