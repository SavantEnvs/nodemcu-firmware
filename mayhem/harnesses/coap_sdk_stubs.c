/*
 * The two ESP8266-SDK-bound symbols app/coap/coap.c references, for the host build:
 *  - endpoints[]: the real table (app/coap/endpoints.c) needs the SDK headers (os_type.h,
 *    user_interface.h) and the firmware's live Lua state; here it holds only the terminator, so
 *    coap_handle_req answers every request with its no-match (4.04) path.
 *  - os_random(): the SDK RNG, used only by coap_setup() (message-id seed), which no target calls.
 */
#include <stddef.h>
#include "coap.h"

const coap_endpoint_t endpoints[] = {
  {(coap_method_t)0, NULL, NULL, NULL, NULL}
};

unsigned long os_random(void) { return 0; }
