/*
 * CoAP server request handling (app/coap/coap_server.c coap_server_respond -> coap.c coap_parse,
 * coap_handle_req, coap_make_response, coap_build), called exactly as the firmware's coap module
 * calls it on every received UDP datagram (app/modules/coap.c coap_received): datagrams longer than
 * MAX_MESSAGE_SIZE are dropped before parsing, the response goes into a MAX_MESSAGE_SIZE+1 buffer.
 *
 * The endpoint table is SDK-bound (endpoints.c needs the ESP8266 SDK headers and the live Lua
 * state), so coap_sdk_stubs.c supplies an empty table: every request takes coap_handle_req's
 * no-matching-endpoint path (4.04 response built from the request's token).
 * After that the parsed packet's options are looked up and the packet re-serialised.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "coap.h"

size_t coap_server_respond(char *req, unsigned short reqlen, char *rsp, unsigned short rsplen);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > MAX_MESSAGE_SIZE)
    return -1; /* coap_received drops these before parsing */
  char *req = malloc(size ? size : 1); /* exact-size copy so ASan sees over-reads */
  if (!req)
    return 0;
  memcpy(req, data, size);

  uint8_t rsp[MAX_MESSAGE_SIZE + 1];
  memset(rsp, 0, sizeof rsp);
  coap_server_respond(req, (unsigned short)size, (char *)rsp, sizeof rsp);

  coap_packet_t pkt;
  memset(&pkt, 0, sizeof pkt);
  if (coap_parse(&pkt, (const uint8_t *)req, size) == 0) {
    uint8_t count = 0;
    const coap_option_t *opt = coap_findOptions(&pkt, COAP_OPTION_URI_PATH, &count);
    char str[MAX_SEGMENTS_SIZE + 1];
    for (uint8_t i = 0; opt && i < count; i++)
      coap_buffer_to_string(str, sizeof str, &opt[i].buf);
    coap_findOptions(&pkt, COAP_OPTION_CONTENT_FORMAT, &count);
    size_t rlen = sizeof rsp;
    coap_build(rsp, &rlen, &pkt);
  }
  free(req);
  return 0;
}
