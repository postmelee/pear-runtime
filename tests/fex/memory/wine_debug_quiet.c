/* Original Pear standalone diagnostic-channel adapter. MIT-licensed.
 * Supplies Wine debug formatting symbols only for a standalone source-owner
 * fixture; it never substitutes for a platform, protection or EC operation. */
#include "wine/debug.h"
unsigned char __wine_dbg_get_channel_flags(struct __wine_debug_channel *channel)
{ (void)channel; return 0; }
const char *__wine_dbg_strdup(const char *text) { return text; }
int __wine_dbg_output(const char *text) { (void)text; return 0; }
int __wine_dbg_header(enum __wine_debug_class cls, struct __wine_debug_channel *channel, const char *function)
{ (void)cls; (void)channel; (void)function; return 0; }
