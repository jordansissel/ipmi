#include "insist.h"
#include "ipmi.h"
#include <stdint.h>
#include <string>

#include "ipmi_packet.h"
#include "mongoose.h"

struct rmcp getChannelAuthenticationCapabilities(IPMI::AuthenticationCapability authCap) {
    struct rmcp r;
    r.version = 0x06;
    r.reserved = 0;
    r.sequence = 0xff;
    r.message_type = 0x07;
    r.message_class = 0;

    r.session.authentication_type = 0; /* Authentication Type NONE. Follows spec for Get Channel Authentication Capabilities Command */
    r.session.sequence_number = 0;/* sequence number unused in this request */
    r.session.session_id = 0;/* session id unused in this request */
    // skip writing auth code because there is no authentication code when auth type is NONE.

    r.session.length = 9; /* payload length: 7 (header) + 2 (command args) */
    r.session.message.target = 0x20; /* BMC's  responder address (i2c terminology) */
    r.session.message.netFn = 0x06; /* Application Request */
    r.session.message.targetLun = 0;
    r.session.message.checksum1 = -(0x20 + (0x06<<2));

    r.session.message.source = 0x81;
    r.session.message.sequence = 0x01;
    r.session.message.sourceLun = 0x00;
    r.session.message.command = 0x38;
    r.session.message.parameters.getChannelAuthenticationCapabilities.Request.channel = 0x0e; /* Use current channel */
    r.session.message.parameters.getChannelAuthenticationCapabilities.Request.privileges = (uint8_t)authCap; /* Request Administrator privileges */
    r.session.message.parameters.getChannelAuthenticationCapabilities.Request.checksum = -( 
        + r.session.message.source
        + (r.session.message.sequence << 2 | r.session.message.sourceLun)
        + r.session.message.command
        + r.session.message.parameters.getChannelAuthenticationCapabilities.Request.channel 
        + r.session.message.parameters.getChannelAuthenticationCapabilities.Request.privileges
    );

    return r;
}

