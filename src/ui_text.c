#include "os.h"
#include "os_io_seproxyhal.h"

#include "algo_ui.h"

#define MAX_CHARS_PER_LINE 8

char text[128];
static int lineBufferPos;

// 2 extra bytes for ".." on continuation
// 1 extra byte for the null termination
char lineBuffer[MAX_CHARS_PER_LINE+2+1];

void
ui_text_putn(const char *msg, size_t maxlen)
{
  for (unsigned int i = 0; i < sizeof(text) && i < maxlen; i++) {
    text[i] = msg[i];

    if (msg[i] == '\0') {
      break;
    }
  }

  text[sizeof(text)-1] = '\0';
  lineBufferPos = 0;

  PRINTF("ui_text_putn: text %s\n", &text[0]);
}

void
ui_text_put(const char *msg)
{
  ui_text_putn(msg, SIZE_MAX);

  /* Caller should invoke ui_text_more() after ui_text_put(). */
}
