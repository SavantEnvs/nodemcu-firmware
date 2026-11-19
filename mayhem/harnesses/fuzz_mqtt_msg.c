/*
 * MQTT message decoding (app/mqtt/mqtt_msg.c) the way the firmware's mqtt module handles one received
 * TCP segment (app/modules/mqtt.c mqtt_socket_received):
 *  - a segment whose first message is a CONNACK is handled as in the MQTT_CONNECT_SENT state
 *    (type check + return code, rest of the segment ignored);
 *  - otherwise the MQTT_DATA loop (READPACKET ... RX_MESSAGE_PROCESSED) runs: total length (varint),
 *    type/qos, packet id; the "message too long" branch (> max_message_length, default
 *    DEFAULT_MAX_MESSAGE_LENGTH = 1024), including the qos>0 && msg_id==0 short-buffer case and the
 *    overflow delivery of the whole remaining buffer; the partial-message exit; per-type handling
 *    (PUBLISH delivers topic/payload over message_length bytes, and the PUBACK / PUBREC / PUBREL /
 *    PUBCOMP / PINGRESP replies are built with the mqtt_msg_* encoders into a MQTT_BUF_SIZE
 *    buffer); then the input advances by message_length to the next message in the segment.
 * mqtt.c's segment length is uint16_t, so inputs are limited to 65535 bytes. Buffering of a partial
 * message across segments is not modelled: one input is one segment.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "mqtt_msg.h"

#define MQTT_BUF_SIZE 1460              /* app/modules/mqtt.c */
#define DEFAULT_MAX_MESSAGE_LENGTH 1024 /* app/modules/mqtt.c */

static volatile uint32_t sink;

/* deliver_publish(): topic and data are taken from `length` bytes at `message`. The hash loops stand in
 * for mqtt.c's lua_pushlstring(L, topic, topic_length) / lua_pushlstring(L, data, data_length): they read
 * exactly the bytes mqtt.c copies, so an over-read reported here is that mqtt.c over-read (e.g. a
 * wrapped negative message_length passed on as a ~65 k uint16_t length). */
static void deliver_publish(uint8_t *message, uint16_t length) {
  uint16_t tlen = length, dlen = length;
  const char *topic = mqtt_get_publish_topic(message, &tlen);
  const char *pdata = mqtt_get_publish_data(message, &dlen);
  uint32_t h = 0;
  if (topic && tlen > 0) {
    for (uint16_t i = 0; i < tlen; i++) h = h * 31 + (uint8_t)topic[i];
    if (pdata && dlen > 0)
      for (uint16_t i = 0; i < dlen; i++) h = h * 31 + (uint8_t)pdata[i];
  }
  sink ^= h;
}

/* the reply mqtt.c queues; it reads the reply's qos back with mqtt_get_qos(temp_msg->data) */
static void reply(mqtt_message_t *m) {
  if (m)
    sink ^= mqtt_get_qos(m->data) ^ m->length;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0 || size > 0xffff)
    return -1; /* mqtt.c is never called with an empty segment; lengths are uint16_t */
  uint8_t *buf = malloc(size);
  if (!buf)
    return 0;
  memcpy(buf, data, size);

  uint8_t *in_buffer = buf;
  uint16_t in_buffer_length = (uint16_t)size;

  if (mqtt_get_type(in_buffer) == MQTT_MSG_TYPE_CONNACK) {
    /* MQTT_CONNECT_SENT: the return code is read with no length check */
    sink ^= mqtt_get_connect_ret_code(in_buffer);
    free(buf);
    return 0;
  }

  while (in_buffer_length > 0) { /* READPACKET, state MQTT_DATA */
    uint8_t temp_buffer[MQTT_BUF_SIZE];
    mqtt_message_buffer_t msgb;
    mqtt_msg_init(&msgb, temp_buffer, MQTT_BUF_SIZE);

    int32_t message_length = mqtt_get_total_length(in_buffer, in_buffer_length);
    uint8_t msg_type = mqtt_get_type(in_buffer);
    uint8_t msg_qos = mqtt_get_qos(in_buffer);
    uint16_t msg_id = mqtt_get_id(in_buffer, in_buffer_length);
    sink ^= mqtt_get_dup(in_buffer) ^ mqtt_get_retain(in_buffer);

    if (message_length > DEFAULT_MAX_MESSAGE_LENGTH) {
      if (msg_qos > 0 && msg_id == 0) {
        message_length = -1; /* short-buffer mode: falls through to partial handling */
      } else {
        if (msg_type == MQTT_MSG_TYPE_PUBLISH) {
          deliver_publish(in_buffer, in_buffer_length); /* overflow callback */
          if (msg_qos == 1)
            reply(mqtt_msg_puback(&msgb, msg_id));
          else if (msg_qos == 2)
            reply(mqtt_msg_pubrec(&msgb, msg_id));
        }
        if (message_length > in_buffer_length)
          break; /* skip into the next segment */
        goto processed;
      }
    }

    if (message_length == -1 || message_length > in_buffer_length)
      break; /* partial message: buffered until the next segment */

    switch (msg_type) {
    case MQTT_MSG_TYPE_PUBLISH:
      if (msg_qos == 1)
        reply(mqtt_msg_puback(&msgb, msg_id));
      else if (msg_qos == 2)
        reply(mqtt_msg_pubrec(&msgb, msg_id));
      deliver_publish(in_buffer, (uint16_t)message_length);
      break;
    case MQTT_MSG_TYPE_PUBREC:
      reply(mqtt_msg_pubrel(&msgb, msg_id));
      break;
    case MQTT_MSG_TYPE_PUBREL:
      reply(mqtt_msg_pubcomp(&msgb, msg_id));
      break;
    case MQTT_MSG_TYPE_PINGREQ:
      reply(mqtt_msg_pingresp(&msgb));
      break;
    default: /* SUBACK, UNSUBACK, PUBACK, PUBCOMP, PINGRESP: id compared with the pending queue */
      sink ^= msg_id;
      break;
    }

  processed: /* RX_MESSAGE_PROCESSED */
    /* mqtt.c: in_buffer_length -= message_length; in_buffer += message_length. The device compiler
     * wraps the uint16_t result modulo 2^16; computed unsigned here so a wrapped (negative)
     * message_length does not trip UBSan in harness arithmetic. The pointer step is kept as-is. */
    in_buffer_length = (uint16_t)(in_buffer_length - (uint32_t)message_length);
    in_buffer += message_length;
  }
  free(buf);
  return 0;
}
