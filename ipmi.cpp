/*
    Copyright Jordan Sissel, 2018
    This file is part of jordansissel/ipmi.

    jordansissel/ipmi is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    jordansissel/ipmi is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with jordansissel/ipmi.  If not, see <http://www.gnu.org/licenses/>.
  */
#include "ipmi.h"
#include "insist.h"
#include "mongoose.h"
#include <stdint.h>

namespace IPMI {
void RMCP::write(struct mbuf &out) const {
  mbuf_append(&out, &version, 1);
  mbuf_append(&out, &reserved, 1);
  mbuf_append(&out, &sequence, 1);
  mbuf_append(&out, &message_class, 1);
}

void RMCP::read(struct mbuf &in) {
  insist(in.len >= 4,
         "Need at least 4 bytes for RMCP header, but have %zd bytes.", in.len);

  version = in.buf[0];
  reserved = in.buf[1];
  sequence = in.buf[2];
  message_class = in.buf[3];
  mbuf_remove(&in, 4);
}

void Session::write(struct mbuf &out) const {
  uint32_t networkbytes;
  mbuf_append(&out, &auth_type, 1);

  // networkbytes = htonl(sequence);
  networkbytes = sequence;
  printf("Writing(%08x) -> %08x\n", sequence, networkbytes);
  mbuf_append(&out, &networkbytes, 4);

  // networkbytes = htonl(id);
  networkbytes = id;
  mbuf_append(&out, &networkbytes, 4);

  if (auth_type == 0x02) { /* md5 */
    mbuf_append(&out, auth_code, 16);
  }

  mbuf_append(&out, &length, 1);
}

void Session::read(struct mbuf &in) {
  insist(in.len >= 10,
         "Need at least 10 bytes for Session header, but have %zd bytes",
         in.len);
  auth_type = in.buf[0];

  memcpy(&sequence, in.buf + 1, 4);
  // sequence = ntohl(sequence);
  memcpy(&id, in.buf + 5, 4);
  // id = ntohl(id);

  if (auth_type > 0) {
    insist(in.len >= 26,
           "Need at least 26 bytes for Session header when auth_type>0, but "
           "have %zd bytes",
           in.len);
    memcpy(&auth_code, in.buf + 9, 16);
    length = in.buf[9 + 16];
    mbuf_remove(&in, 26);
  } else {
    memset(&auth_code, 0, 16);
    length = in.buf[9];
    mbuf_remove(&in, 10);
  }

  printf("[%s] length %zd\n", auth_type > 0 ? "auth" : "none", length);
}

void IPMB::write(struct mbuf &out) const {
  mbuf_append(&out, &target, 1);
  uint8_t scratch = (netFn << 2) | targetLun;
  mbuf_append(&out, &scratch, 1);

  // Compute checksum
  uint8_t checksum = -(target + scratch);
  mbuf_append(&out, &checksum, 1);

  mbuf_append(&out, &source, 1);
  scratch = (sequence << 2) | sourceLun;
  mbuf_append(&out, &scratch, 1);
  mbuf_append(&out, &command, 1);
}

void IPMB::read(struct mbuf &in) {
  insist(in.len >= 7,
         "Need at least 7 bytes for IPMB header, but have %zd bytes", in.len);

  target = in.buf[0];
  netFn = in.buf[1] >> 2;
  targetLun = in.buf[1] & 3;
  checksum = in.buf[2];

  source = in.buf[3];
  sequence = in.buf[4] >> 2;
  sourceLun = in.buf[4] & 3;
  command = in.buf[5];
  mbuf_remove(&in, 6);
}

namespace GetChannelAuthenticationCapabilities {

void Request::write(struct mbuf &out) const {
  mbuf_append(&out, &channel, 1);
  mbuf_append(&out, &privileges, 1);
}

void Request::read(struct mbuf &in) {
  insist(in.len >= 2,
         "Need at least 2 bytes for GetChannelAuthenticationCapabities Request "
         "header, but have %zd bytes",
         in.len);

  channel = in.buf[0];
  privileges = in.buf[1];

  mbuf_remove(&in, 2);
}

void Response::write(struct mbuf &out) const {
  insist(false, "Not implemented.");
}

void Response::read(struct mbuf &in) {
  insist(in.len >= 9,
         "Need at least 9 bytes for GetChannelAuthenticationCapabities Request "
         "header, but have %zd bytes",
         in.len);

  completion_code = in.buf[0];
  channel = in.buf[1];
  auth_type1 = in.buf[2];
  auth_type2 = in.buf[3];
  reserved = in.buf[4];
  oem1 = in.buf[5];
  oem2 = in.buf[6];
  oem3 = in.buf[7];
  oem_aux = in.buf[8];

  insist(completion_code == 0, "GetChannelAuthenticationRequest failed");
  insist(hasMD5(), "MD5 is not supported by the remote IPMI "
                   "device, but is required by this "
                   "implementation.");
  mbuf_remove(&in, 9);
}

}; // namespace GetChannelAuthenticationCapabilities

namespace GetSessionChallenge {
void Request::write(struct mbuf &out) const {
  mbuf_append(&out, &auth_type, 1);
  mbuf_append(&out, &user, 16);
}

void Request::read(struct mbuf &in) {
  insist(in.len >= 17,
         "Need at least 17 bytes for SessionChallenge request, but have %zd "
         "bytes.",
         in.len);

  auth_type = in.buf[0];
  memcpy(user, in.buf + 1, 16);
  mbuf_remove(&in, 17);
}

void Response::write(struct mbuf &out) const {
  uint32_t scratch;

  // scratch = htonl(session_id);
  scratch = session_id;
  mbuf_append(&out, &scratch, 4);
  mbuf_append(&out, challenge, 16);
}

void Response::read(struct mbuf &in) {
  insist(in.len >= 21,
         "Need at least 21 bytes for SessionChallenge response, but have %zd "
         "bytes.",
         in.len);

  uint8_t completion_code = in.buf[0];
  insist(completion_code == 0, "GetChannelAuthenticationRequest failed");

  memcpy(&session_id, in.buf + 1, 4);
  // session_id = ntohl(session_id);

  memcpy(&challenge, in.buf + 5, 16);
  printf("Challenge: ");
  mg_hexdumpf(stdout, challenge, 16);

  mbuf_remove(&in, 21);
}
} // namespace GetSessionChallenge

namespace ActivateSession {
void Request::read(struct mbuf &in) {}

void Request::write(struct mbuf &out) const {
  // uint32_t scratch = htonl(sequence);
  uint32_t scratch = sequence;
  mbuf_append(&out, &auth_type, 1);
  mbuf_append(&out, &privilege, 1);
  mbuf_append(&out, &challenge, 16);
  mbuf_append(&out, &scratch, 4);
}

void Response::read(struct mbuf &in) {
  uint8_t completion_code = in.buf[0];
  insist(completion_code == 0, "ActivateSession request failed");

  auth_type = in.buf[1];

  memcpy(&session, in.buf + 2, 4);
  // session = ntohl(session);

  memcpy(&sequence, in.buf + 6, 4);
  // sequence = ntohl(sequence);
  mg_hexdumpf(stdout, in.buf + 6, 4);

  privilege = in.buf[10];
  mbuf_remove(&in, 11);
}

void Response::write(struct mbuf &out) const {}

} // namespace ActivateSession

namespace SetSessionPrivilege {
void Request::read(struct mbuf &in) {}
void Request::write(struct mbuf &out) const {
  mbuf_append(&out, &privilege, 1);
}
void Response::read(struct mbuf &in) {
  insist(
      in.len >= 2,
      "Need at least 2 bytes for SetSessionPrivilege response, but have %zd.",
      in.len);
  uint8_t completion_code = in.buf[0];
  insist(completion_code == 0, "SetSessionPrivilege request failed");

  privilege = in.buf[1];
  mbuf_remove(&in, 2);
}
void Response::write(struct mbuf &out) const {}
} // namespace SetSessionPrivilege

namespace ChassisControl {
void Request::read(struct mbuf &in) {}
void Request::write(struct mbuf &out) const { mbuf_append(&out, &command, 1); }
void Response::read(struct mbuf &in) {
  insist(in.len >= 1,
         "Need at least 1 bytes for ChassisControl response, but have %zd.",
         in.len);
  uint8_t completion_code = in.buf[0];
  insist(completion_code == 0, "ChassisControl request failed");
  mbuf_remove(&in, 1);
}
void Response::write(struct mbuf &out) const {}
} // namespace ChassisControl

void getChannelAuthenticationCapabilities(struct mbuf &buf) {
  RMCP rmcp = {};
  IPMB ipmb = {0x06, 0x01, 0x38};
  GetChannelAuthenticationCapabilities::Request request = {};
  Session session = {0x00, 0x00000000, 0x00000000, request.length()};

  rmcp.write(buf);
  session.write(buf);
  ipmb.write(buf);
  request.write(buf);

  // compute trailing checksum
  uint8_t checksum = 0;
  for (size_t i = 17; i < buf.len; i++) {
    checksum += buf.buf[i];
  }
  checksum = -checksum;
  mbuf_append(&buf, &checksum, 1);
}

void decode(struct mbuf &buf, RMCP &rmcp, IPMB &ipmb, Session &session,
            GetChannelAuthenticationCapabilities::Response &response) {

  // Sum of all bytes 17..end should equal 0 (checksum is negative of sum)
  uint8_t value = 0;
  for (size_t i = 17; i < buf.len; i++) {
    value += (uint8_t)buf.buf[i];
  }
  insist(value == 0, "Checksum failed on receiving packet");

  rmcp.read(buf);
  session.read(buf);

  ipmb.read(buf);
  printf("Command: %02x\n", ipmb.command);
  response.read(buf);

  mbuf_remove(&buf, 1); // remove last byte (the checksum)
}

void getSessionChallenge(struct mbuf &buf) {
  RMCP rmcp = {};
  IPMB ipmb = {0x06, 0x01, 0x39 /* SessionChallenge */};
  GetSessionChallenge::Request request = {};
  Session session = {0x00, 0x00000000, 0x00000000, request.length()};

  rmcp.write(buf);
  session.write(buf);
  ipmb.write(buf);
  request.write(buf);

  // compute trailing checksum
  uint8_t checksum = 0;
  for (size_t i = 17; i < buf.len; i++) {
    checksum += buf.buf[i];
  }
  checksum = -checksum;
  mbuf_append(&buf, &checksum, 1);
}

void decode(struct mbuf &buf, RMCP &rmcp, IPMB &ipmb, Session &session,
            GetSessionChallenge::Response &response) {
  // Sum of all bytes 17..end should equal 0 (checksum is negative of sum)
  uint8_t value = 0;
  for (size_t i = 17; i < buf.len; i++) {
    value += (uint8_t)buf.buf[i];
  }
  insist(value == 0, "Checksum failed on receiving packet");

  rmcp.read(buf);
  session.read(buf);

  ipmb.read(buf);
  printf("Command: %02x\n", ipmb.command);
  response.read(buf);

  mbuf_remove(&buf, 1); // remove last byte (the checksum)
}

void activateSession(struct mbuf &buf, uint8_t password[16], uint32_t sequence,
                     uint32_t session_id, uint8_t challenge[16]) {
  RMCP rmcp = {};
  IPMB ipmb = {0x06, 0x01, 0x3A /* Activate Session */};
  const ActivateSession::Request request(sequence, challenge);
  Session session = {0x02, 0x00000000, session_id, request.length()};

  // void cs_md5_init(cs_md5_ctx *c);
  // void cs_md5_update(cs_md5_ctx *c, const unsigned char *data, size_t len);
  // void cs_md5_final(unsigned char *md, cs_md5_ctx *c);

  rmcp.write(buf);
  session.write(buf);
  size_t offset = buf.len;
  ipmb.write(buf);
  request.write(buf);

  // compute trailing checksum
  uint8_t checksum = 0;
  for (size_t i = 17 + 16; i < buf.len; i++) {
    checksum += buf.buf[i];
  }
  checksum = -checksum;
  mbuf_append(&buf, &checksum, 1);

  // Compute auth code: MD5(password + sequence + data + password)
  printf("Session: %08x\n", session_id);
  // printf("Sequence: %08x\n", sequence);
  cs_md5_ctx md5;
  cs_md5_init(&md5);
  cs_md5_update(&md5, password, 16);
  // printf("md5'ing password: "), mg_hexdumpf(stdout, password, 16);

  // uint32_t scratch = htonl(session_id);
  uint32_t scratch = session_id;
  cs_md5_update(&md5, (const unsigned char *)&scratch, 4);
  // printf("md5'ing session: "), mg_hexdumpf(stdout, &scratch, 4);

  // printf("md5'ing data: "),
  // mg_hexdumpf(stdout, buf.buf + offset, buf.len - offset);
  cs_md5_update(&md5, (const unsigned char *)(buf.buf + offset),
                buf.len - offset);
  scratch = 0; // Sequence number is 0 until after this message
  cs_md5_update(&md5, (const unsigned char *)&scratch, 4);
  // printf("md5'ing sequence: "), mg_hexdumpf(stdout, &scratch, 4);

  cs_md5_update(&md5, password, 16);
  // printf("md5'ing password: "), mg_hexdumpf(stdout, password, 16);

  uint8_t authcode[16];
  cs_md5_final(authcode, &md5);
  // printf("Auth code: ");
  mg_hexdumpf(stdout, authcode, 16);
  memcpy(buf.buf + offset - (16 + 1), authcode, 16);
}

void decode(struct mbuf &buf, const uint8_t password[16], RMCP &rmcp,
            IPMB &ipmb, Session &session, ActivateSession::Response &response) {
  rmcp.read(buf);
  session.read(buf);

  // Sum of all bytes 17..end should equal 0 (checksum is negative of sum)
  uint8_t value = 0;
  for (size_t i = 0; i < buf.len; i++) {
    value += (uint8_t)buf.buf[i];
  }
  insist(value == 0, "Checksum failed on receiving packet");

  ipmb.read(buf);
  printf("Command: %02x\n", ipmb.command);
  response.read(buf);

  mbuf_remove(&buf, 1); // remove last byte (the checksum)
  insist(
      buf.len == 0,
      "Buffer length should be empty if decoding is correct, but has %zd bytes",
      buf.len);
}

void setSessionPrivilege(struct mbuf &buf, uint32_t session_id,
                         uint32_t sequence, uint8_t password[16],
                         IPMI::AuthenticationCapability privilege) {
  RMCP rmcp = {};
  IPMB ipmb = {0x06, 0x01, 0x3B /* Set Session Privilege*/};
  const SetSessionPrivilege::Request request((uint8_t)privilege);
  Session session = {0x02, sequence, session_id, request.length()};

  rmcp.write(buf);
  session.write(buf);
  size_t offset = buf.len;
  ipmb.write(buf);
  request.write(buf);

  // compute trailing checksum
  uint8_t checksum = 0;
  for (size_t i = 17 + 16; i < buf.len; i++) {
    checksum += buf.buf[i];
  }
  checksum = -checksum;
  mbuf_append(&buf, &checksum, 1);

  // Compute auth code: MD5(password + sequence + data + password)
  printf("Session: %08x\n", session_id);
  printf("Sequence: %08x\n", sequence);
  cs_md5_ctx md5;
  cs_md5_init(&md5);
  cs_md5_update(&md5, password, 16);
  printf("md5'ing password: "), mg_hexdumpf(stdout, password, 16);

  // uint32_t scratch = htonl(session_id);
  uint32_t scratch = session_id;
  cs_md5_update(&md5, (const unsigned char *)&scratch, 4);
  // printf("md5'ing session: "), mg_hexdumpf(stdout, &scratch, 4);

  // printf("md5'ing data: "),
  // mg_hexdumpf(stdout, buf.buf + offset, buf.len - offset);
  cs_md5_update(&md5, (const unsigned char *)(buf.buf + offset),
                buf.len - offset);
  // scratch = htonl(sequence);
  scratch = sequence;
  cs_md5_update(&md5, (const unsigned char *)&scratch, 4);
  // printf("md5'ing sequence: "), mg_hexdumpf(stdout, &scratch, 4);

  cs_md5_update(&md5, password, 16);
  // printf("md5'ing password: "), mg_hexdumpf(stdout, password, 16);

  uint8_t authcode[16];
  cs_md5_final(authcode, &md5);
  // printf("Auth code: ");
  mg_hexdumpf(stdout, authcode, 16);
  memcpy(buf.buf + offset - (16 + 1), authcode, 16);
}

void decode(struct mbuf &buf, const uint8_t password[16], RMCP &rmcp,
            IPMB &ipmb, Session &session,
            SetSessionPrivilege::Response &response) {
  rmcp.read(buf);
  session.read(buf);

  // Verify checksum
  uint8_t value = 0;
  for (size_t i = 0; i < buf.len; i++) {
    value += (uint8_t)buf.buf[i];
  }
  insist(value == 0, "Checksum failed on receiving packet");

  ipmb.read(buf);
  printf("Command: %02x\n", ipmb.command);
  response.read(buf);

  mbuf_remove(&buf, 1); // remove last byte (the checksum)
  insist(
      buf.len == 0,
      "Buffer length should be empty if decoding is correct, but has %zd bytes",
      buf.len);
}

void chassisControl(struct mbuf &buf, uint32_t session_id, uint32_t sequence,
                    uint8_t password[16], ChassisControlCommand command) {
  RMCP rmcp = {};
  IPMB ipmb = {0x00 /* Chassis Request */, 0x01, 0x02 /* Chassis Control */};
  const ChassisControl::Request request(command);
  Session session = {0x02, sequence, session_id, request.length()};

  rmcp.write(buf);
  session.write(buf);
  size_t offset = buf.len;
  ipmb.write(buf);
  request.write(buf);

  // compute trailing checksum
  uint8_t checksum = 0;
  for (size_t i = 17 + 16; i < buf.len; i++) {
    checksum += buf.buf[i];
  }
  checksum = -checksum;
  mbuf_append(&buf, &checksum, 1);

  // Compute auth code: MD5(password + sequence + data + password)
  printf("Session: %08x\n", session_id);
  printf("Sequence: %08x\n", sequence);
  cs_md5_ctx md5;
  cs_md5_init(&md5);
  cs_md5_update(&md5, password, 16);
  printf("md5'ing password: "), mg_hexdumpf(stdout, password, 16);

  // uint32_t scratch = htonl(session_id);
  uint32_t scratch = session_id;
  cs_md5_update(&md5, (const unsigned char *)&scratch, 4);
  // printf("md5'ing session: "), mg_hexdumpf(stdout, &scratch, 4);

  // printf("md5'ing data: "),
  // mg_hexdumpf(stdout, buf.buf + offset, buf.len - offset);
  cs_md5_update(&md5, (const unsigned char *)(buf.buf + offset),
                buf.len - offset);
  // scratch = htonl(sequence);
  scratch = sequence;
  cs_md5_update(&md5, (const unsigned char *)&scratch, 4);
  // printf("md5'ing sequence: "), mg_hexdumpf(stdout, &scratch, 4);

  cs_md5_update(&md5, password, 16);
  // printf("md5'ing password: "), mg_hexdumpf(stdout, password, 16);

  uint8_t authcode[16];
  cs_md5_final(authcode, &md5);
  // printf("Auth code: ");
  mg_hexdumpf(stdout, authcode, 16);
  memcpy(buf.buf + offset - (16 + 1), authcode, 16);
}
} // namespace IPMI