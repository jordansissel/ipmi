#include "ipmi_packet.h"
#include "mongoose.h"

static size_t mbuf_append8(struct mbuf *buf, uint8_t v) {
    return mbuf_append(buf, (const void *)&v, sizeof(v));
}

/*
static size_t mbuf_append16(struct mbuf *buf, uint16_t v) {
    v = ntohs(v); // RMCP+IPMI are network-byte order
    return mbuf_append(buf, (const void *) &v, sizeof(v));
}
*/

static size_t mbuf_append32(struct mbuf *buf, uint32_t v) {
    v = ntohl(v); // RMCP+IPMI are network-byte order
    return mbuf_append(buf, (const void *)&v, sizeof(v));
}

void parsePacket(struct mbuf buf) {
    const char *p = buf.buf;

    printf("Parsing\n");
    insist(p[0] == 0x06, "Version must be 0x06. Got 0x%02x", p[0]);
    insist(p[1] == 0x00, "reserved field must be 0x00, got 0x%02x", p[1]);

    printf("Seq: %u\n", (uint8_t) p[2]);
    insist(p[3] == 0x07, "Message class must be Normal IPMI (0x07), got 0x%02x", p[3]);
}

struct mbuf getChannelAuthenticationCapabilities(IPMI::AuthenticationCapability authCap) {
    struct mbuf buf;
    mbuf_init(&buf, 4 + 10 + 7 + 2);
    insist(buf.buf != NULL, "Buffer allocation failed");

    mbuf_append8(&buf, 0x06); /* version */
    mbuf_append8(&buf, 0x00); /* reserved */
    // No sequence number for this RMCP payload, so set to 0xff
    mbuf_append8(&buf, 0xFF); /* seq num 0xff means not used */
    mbuf_append8(&buf, 0x07); /* Message Class: Normal (0 @ bit 7) | IPMI (0x7) */

    mbuf_append8(&buf, 0);  /* Authentication Type NONE. Follows spec for Get Channel Authentication Capabilities Command */
    mbuf_append32(&buf, 0); /* sequence number unused in this request */
    mbuf_append32(&buf, 0); /* session id unused in this request */
    // skip writing auth code because there is no authentication code when auth type is NONE.

    mbuf_append8(&buf, 9); /* payload length: 7 (header) + 2 (command args) */
    uint8_t checksum = 0;
    mbuf_append8(&buf, 0x20); /* BMC's  responder address (i2c terminology) */
    checksum += buf.buf[buf.len - 1];

    // combo field: NetFN + LUN. Lower 2 bits are the LUN. Upper 6 is the NetFN */
    mbuf_append8(&buf, 0x06 << 2); /* `App` - Application Request Network Function */
    checksum += buf.buf[buf.len - 1];

    checksum = -checksum;
    mbuf_append8(&buf, checksum);
    /* Spec: "When the checksum and the bytes are added together, modulo 256, the result should be 0" */
    insist((uint8_t)(buf.buf[14] + buf.buf[15] + buf.buf[16]) == 0, "IPMB requester-checksum failed: %d + %d + %d != 0 (%d)", buf.buf[14], buf.buf[15], buf.buf[16], (buf.buf[14] + buf.buf[15] + buf.buf[16]));

    checksum = 0;
    mbuf_append8(&buf, 0x81); /* Requester address. 0x81 == "software id for the remote console" */
    checksum += buf.buf[buf.len - 1];

    // combo field: Sequence + LUN. Lower 2 bits are the LUN. Upper 6 is the sequence number */
    mbuf_append8(&buf, 0x01 << 2); /* Requester sequence + LUN */
    checksum += buf.buf[buf.len - 1];

    mbuf_append8(&buf, 0x38); /* Get Channel Authentication Capabilities command */
    checksum += buf.buf[buf.len - 1];

    mbuf_append8(&buf, 0x0e); /* Use current channel */
    checksum += buf.buf[buf.len - 1];

    mbuf_append8(&buf, (uint8_t)authCap); /* Request Administrator privileges */
    checksum += buf.buf[buf.len - 1];

    checksum = -checksum;
    mbuf_append8(&buf, checksum);
    insist((uint8_t)((buf.buf[17] + buf.buf[18] + buf.buf[19] + buf.buf[20] + buf.buf[21]) + buf.buf[22]) == 0, "IPMB requester-command checksum failed.");

    return buf;
}