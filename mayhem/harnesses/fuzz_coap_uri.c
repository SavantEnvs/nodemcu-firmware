/*
 * CoAP URI parser (app/coap/uri.c) as the coap module's client request path uses it
 * (app/modules/coap.c coap_request): coap_new_uri(url) -> coap_new_pdu -> coap_make_request (which
 * splits the URI path and query into options with coap_split_path/coap_split_query) -> coap_build.
 *
 * Input: <url> NUL <payload>; with no NUL the whole input is the URL, so seeds are plain URLs.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "coap.h"
#include "uri.h"
#include "pdu.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const uint8_t *nul = memchr(data, 0, size);
  size_t ulen = nul ? (size_t)(nul - data) : size;
  size_t plen = nul ? size - ulen - 1 : 0;

  unsigned char *url = malloc(ulen ? ulen : 1);
  uint8_t *payload = malloc(plen ? plen : 1);
  if (!url || !payload) {
    free(url);
    free(payload);
    return 0;
  }
  memcpy(url, data, ulen);
  if (plen)
    memcpy(payload, nul + 1, plen);

  coap_uri_t *uri = coap_new_uri(url, ulen);
  if (uri != NULL) {
    coap_pdu_t *pdu = coap_new_pdu();
    if (pdu) {
      coap_make_request(&pdu->scratch, pdu->pkt, COAP_TYPE_CON, COAP_METHOD_GET, uri,
                        plen ? payload : NULL, plen);
      coap_build(pdu->msg.p, &pdu->msg.len, pdu->pkt);
      coap_delete_pdu(pdu);
    }
    free(uri);
  }
  free(url);
  free(payload);
  return 0;
}
