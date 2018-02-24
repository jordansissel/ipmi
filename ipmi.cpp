#include "ipmi.h"
#include "insist.h"
#include "openssl/md5.h"
#include <stdint.h>
#include <string>

#include "ipmi_packet.h"
#include "mongoose.h"

struct rmcp
getChannelAuthenticationCapabilities(IPMI::AuthenticationCapability authCap) {
  struct rmcp r;
  r.version = 0x06;
  r.reserved = 0;
  r.sequence = 0xff;
  r.message_type = 0x07;
  r.message_class = 0;

  r.session.authentication_type = 0; /* Authentication Type NONE. Follows spec
                                        for Get Channel Authentication
                                        Capabilities Command */
  r.session.sequence_number = 0; /* sequence number unused in this request */
  r.session.session_id = 0;      /* session id unused in this request */
  // skip writing auth code because there is no authentication code when auth
  // type is NONE.

  r.session.length = 9;    /* payload length: 7 (header) + 2 (command args) */
  r.message.target = 0x20; /* BMC's  responder address (i2c terminology) */
  r.message.netFn = 0x06;  /* Application Request */
  r.message.targetLun = 0;
  r.message.checksum1 = -(0x20 + (0x06 << 2));

  r.message.source = 0x81;
  r.message.sequence = 0x01;
  r.message.sourceLun = 0x00;
  r.message.command = 0x38;
  r.message.parameters.getChannelAuthenticationCapabilities.request.channel =
      0x0e; /* Use current channel */
  r.message.parameters.getChannelAuthenticationCapabilities.request.privileges =
      (uint8_t)authCap; /* Request Administrator privileges */
  r.message.parameters.getChannelAuthenticationCapabilities.request.checksum =
      -(+r.message.source + (r.message.sequence << 2 | r.message.sourceLun) +
        r.message.command +
        r.message.parameters.getChannelAuthenticationCapabilities.request
            .channel +
        r.message.parameters.getChannelAuthenticationCapabilities.request
            .privileges);

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

  r.session.authentication_type = 0; /* Authentication Type NONE. Follows spec
                                        for Get Channel Authentication
                                        Capabilities Command */
  r.session.sequence_number = 0; /* sequence number unused in this request */
  r.session.session_id = 0;      /* session id unused in this request */
  // skip writing auth code because there is no authentication code when auth
  // type is NONE.

  r.session.length = 24;   /* payload length: 7 (header) + 17 (command args) */
  r.message.target = 0x20; /* BMC's  responder address (i2c terminology) */
  r.message.netFn = 0x06;  /* Application Request */
  r.message.targetLun = 0;
  r.message.checksum1 = -(0x20 + (0x06 << 2));

  r.message.source = 0x81;
  r.message.sequence = 0x01;
  r.message.sourceLun = 0x00;
  r.message.command = 0x39; /* Get Session Challenge == 0x39 */

  /* XXX: Make auth type a parameter */
  r.message.parameters.getSessionChallenge.request.auth_type = 0x02; /* md5 */

  /* XXX: Make username a parameter */
  memset(r.message.parameters.getSessionChallenge.request.username, 0, 16);
  memcpy(r.message.parameters.getSessionChallenge.request.username, "root", 4);

  r.message.parameters.getSessionChallenge.request.checksum =
      -(+r.message.source + (r.message.sequence << 2 | r.message.sourceLun) +
        r.message.command +
        r.message.parameters.getSessionChallenge.request.auth_type
        // XXX: When username is configurable, this needs to change
        + 'r' + 'o' + 'o' + 't');

  return r;
}

struct rmcp_with_auth getActivateSession(const uint8_t password[16],
                                         const uint8_t challenge[16],
                                         const uint32_t session_id) {
  struct rmcp_with_auth r;
  r.version = 0x06;
  r.reserved = 0;
  r.sequence = 0xff;
  r.message_type = 0x07;
  r.message_class = 0;

  r.session.authentication_type = 0x02; /* MD5 */
  r.session.sequence_number = 0; /* sequence number unused in this request */
  r.session.session_id = session_id;

  r.session.length = 29;   /* payload length: 7 (header) + 11 (command args) */
  r.message.target = 0x20; /* BMC's  responder address (i2c terminology) */
  r.message.netFn = 0x06;  /* Application Request */
  r.message.targetLun = 0;
  r.message.checksum1 = -(0x20 + (0x06 << 2));

  r.message.source = 0x81;
  r.message.sequence = 0x01;
  r.message.sourceLun = 0x00;
  r.message.command = 0x3A; /* Activate Session == 0x3A */

  /* XXX: Make auth type a parameter */
  auto request = &r.message.parameters.activateSession.request;
  request->auth_type = 0x02; /* MD5 */
  request->privilege = 0x04; /* Administrator */
  memcpy(&request->challenge, challenge, 16);

  /* XXX: Randomize this initial sequence number */
  request->sequence = 0x00; /* Initial sequence number */

  /* Compute the checksum */
  request->checksum =
      r.message.source + (r.message.sequence << 2 | r.message.sourceLun) +
      r.message.command + request->auth_type + request->privilege;

  for (uint8_t i = 0; i < 16; i++) {
    request->checksum += request->challenge[i];
  }

  request->checksum +=
      (request->sequence & 0xff) + ((request->sequence >> 8) & 0xff) +
      ((request->sequence >> 16) & 0xff) + ((request->sequence >> 24) & 0xff);

  MD5_CTX c;
  MD5_Init(&c);
  MD5_Update(&c, password, 16);
  auto session_id_nb = htonl(session_id); /* network byte order */
  printf("Session id: ");
  mg_hexdumpf(stdout, &session_id, 4);
  MD5_Update(&c, &session_id, sizeof(session_id));
  printf("message: ");
  mg_hexdumpf(stdout, &r.message, 6);
  MD5_Update(&c, &r.message, 6 /* first 6 bytes of the header */);

  printf("request: ");
  mg_hexdumpf(stdout, request, sizeof(*request));
  MD5_Update(&c, request, sizeof(*request));
  MD5_Update(&c, &request->sequence, 4);
  MD5_Update(&c, password, 16);
  MD5_Final(r.session.auth_code, &c);

  printf("auth_code: ");
  mg_hexdumpf(stdout, r.session.auth_code, 16);

  request->checksum = -request->checksum;
  /* End checksum compute */

  return r;
}
