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
    r.message.target = 0x20; /* BMC's  responder address (i2c terminology) */
    r.message.netFn = 0x06; /* Application Request */
    r.message.targetLun = 0;
    r.message.checksum1 = -(0x20 + (0x06<<2));

    r.message.source = 0x81;
    r.message.sequence = 0x01;
    r.message.sourceLun = 0x00;
    r.message.command = 0x38;
    r.message.parameters.getChannelAuthenticationCapabilities.request.channel = 0x0e; /* Use current channel */
    r.message.parameters.getChannelAuthenticationCapabilities.request.privileges = (uint8_t)authCap; /* Request Administrator privileges */
    r.message.parameters.getChannelAuthenticationCapabilities.request.checksum = -( 
        + r.message.source
        + (r.message.sequence << 2 | r.message.sourceLun)
        + r.message.command
        + r.message.parameters.getChannelAuthenticationCapabilities.request.channel 
        + r.message.parameters.getChannelAuthenticationCapabilities.request.privileges
    );

    return r;
}

/* Only MD5 supported right now, so no argument given. */
struct rmcp getSessionChallenge() {
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

    r.session.length = 24; /* payload length: 7 (header) + 17 (command args) */
    r.message.target = 0x20; /* BMC's  responder address (i2c terminology) */
    r.message.netFn = 0x06; /* Application Request */
    r.message.targetLun = 0;
    r.message.checksum1 = -(0x20 + (0x06<<2));

    r.message.source = 0x81;
    r.message.sequence = 0x01;
    r.message.sourceLun = 0x00;
    r.message.command = 0x39; /* Get Session Challenge == 0x39 */

    /* XXX: Make auth type a parameter */
    r.message.parameters.getSessionChallenge.request.auth_type = 0x02; /* md5 */

    /* XXX: Make username a parameter */
    memset(r.message.parameters.getSessionChallenge.request.username, 0, 16);
    memcpy(r.message.parameters.getSessionChallenge.request.username, "root", 4);

    r.message.parameters.getSessionChallenge.request.checksum = -( 
        + r.message.source
        + (r.message.sequence << 2 | r.message.sourceLun)
        + r.message.command
        + r.message.parameters.getSessionChallenge.request.auth_type 
        // XXX: When username is configurable, this needs to change
        + 'r' + 'o' + 'o' + 't'
    );

    return r;
}
struct rmcp_with_auth getActivateSession(uint8_t challenge[16]) {
    struct rmcp_with_auth r;
    r.version = 0x06;
    r.reserved = 0;
    r.sequence = 0xff;
    r.message_type = 0x07;
    r.message_class = 0;

    r.session.authentication_type = 0; /* Authentication Type NONE. Follows spec for Get Channel Authentication Capabilities Command */
    r.session.sequence_number = 0;/* sequence number unused in this request */
    r.session.session_id = 0;/* session id unused in this request */

    r.session.length = 19; /* payload length: 7 (header) + 11 (command args) */
    r.message.target = 0x20; /* BMC's  responder address (i2c terminology) */
    r.message.netFn = 0x06; /* Application Request */
    r.message.targetLun = 0;
    r.message.checksum1 = -(0x20 + (0x06<<2));

    r.message.source = 0x81;
    r.message.sequence = 0x01;
    r.message.sourceLun = 0x00;
    r.message.command = 0x3A; /* Activate Session == 0x3A */

    /* XXX: Make auth type a parameter */
    r.message.parameters.activateSession.request.auth_type = 0x02; /* MD5 */
    r.message.parameters.activateSession.request.privilege = 0x04; /* Administrator */
    memcpy(&r.message.parameters.activateSession.request.challenge, challenge, 16);
    
    /* XXX: Randomize this initial sequence number */
    r.message.parameters.activateSession.request.sequence = 0x01; /* Initial sequence number */

    /* XXX: Make username a parameter */
    memset(r.message.parameters.getSessionChallenge.request.username, 0, 16);
    memcpy(r.message.parameters.getSessionChallenge.request.username, "root", 4);

    r.message.parameters.getSessionChallenge.request.checksum = -( 
        + r.message.source
        + (r.message.sequence << 2 | r.message.sourceLun)
        + r.message.command
        + r.message.parameters.getSessionChallenge.request.auth_type 
        // XXX: When username is configurable, this needs to change
        + 'r' + 'o' + 'o' + 't'
    );

    return r;
}

