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

Status RMCP::read(struct mbuf &in) {
  insist_return(in.len >= 4, Status::Failure,
                "Need at least 4 bytes for RMCP header, but have %zd bytes.",
                in.len);

  version = in.buf[0];
  reserved = in.buf[1];
  sequence = in.buf[2];
  message_class = in.buf[3];
  mbuf_remove(&in, 4);

  return Status::Success;
}

void Session::write(struct mbuf &out) const {
  mbuf_append(&out, &auth_type, 1);
  mbuf_append(&out, &sequence, 4);
  mbuf_append(&out, &id, 4);

  // Per spec, the authcode is only sent if auth_type != 0.
  if (auth_type != 0x00) {
    mbuf_append(&out, auth_code, 16);
  }

  mbuf_append(&out, &length, 1);
}

Status Session::read(struct mbuf &in) {
  insist_return(in.len >= 10, Status::Failure,
                "Need at least 10 bytes for Session header, but have %zd bytes",
                in.len);
  auth_type = in.buf[0];

  memcpy(&sequence, in.buf + 1, 4);
  memcpy(&id, in.buf + 5, 4);

  if (auth_type > 0) {
    insist_return(
        in.len >= 26, Status::Failure,
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

  // printf("[%s] length %zd\n", auth_type > 0 ? "auth" : "none", length);
  return Status::Success;
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

Status IPMB::read(struct mbuf &in) {
  insist_return(in.len >= 7, Status::Failure,
                "Need at least 7 bytes for IPMB header, but have %zd bytes",
                in.len);

  target = in.buf[0];
  netFn = in.buf[1] >> 2;
  targetLun = in.buf[1] & 3;
  checksum = in.buf[2];

  source = in.buf[3];
  sequence = in.buf[4] >> 2;
  sourceLun = in.buf[4] & 3;
  command = in.buf[5];
  mbuf_remove(&in, 6);
  return Status::Success;
}

namespace GetChannelAuthenticationCapabilities {

void Request::write(struct mbuf &out) const {
  mbuf_append(&out, &channel, 1);
  mbuf_append(&out, &privileges, 1);
}

Status Request::read(struct mbuf &in) {
  insist_return(
      in.len >= 2, Status::Failure,
      "Need at least 2 bytes for GetChannelAuthenticationCapabities Request "
      "header, but have %zd bytes",
      in.len);

  channel = in.buf[0];
  privileges = in.buf[1];

  mbuf_remove(&in, 2);
  return Status::Success;
}

void Response::write(struct mbuf &out) const {
  insist(false, "Not implemented.");
}

Status Response::read(struct mbuf &in) {
  insist_return(
      in.len >= 9, Status::Failure,
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

  insist_return(completion_code == 0, Status::Failure,
                "GetChannelAuthenticationRequest failed");
  insist_return(hasMD5(), Status::Failure,
                "MD5 is not supported by the remote IPMI "
                "device, but is required by this "
                "implementation.");
  mbuf_remove(&in, 9);
  return Status::Success;
}

}; // namespace GetChannelAuthenticationCapabilities

namespace GetSessionChallenge {
void Request::write(struct mbuf &out) const {
  mbuf_append(&out, &auth_type, 1);
  mbuf_append(&out, &user, 16);
}

Status Request::read(struct mbuf &in) {
  insist_return(
      in.len >= 17, Status::Failure,
      "Need at least 17 bytes for SessionChallenge request, but have %zd "
      "bytes.",
      in.len);

  auth_type = in.buf[0];
  memcpy(user, in.buf + 1, 16);
  mbuf_remove(&in, 17);
  return Status::Success;
}

void Response::write(struct mbuf &out) const {
  mbuf_append(&out, &session_id, 4);
  mbuf_append(&out, challenge, 16);
}

Status Response::read(struct mbuf &in) {
  insist_return(
      in.len >= 21, Status::Failure,
      "Need at least 21 bytes for SessionChallenge response, but have %zd "
      "bytes.",
      in.len);

  uint8_t completion_code = in.buf[0];
  insist_return(completion_code == 0, Status::Failure,
                "GetChannelAuthenticationRequest failed");

  memcpy(&session_id, in.buf + 1, 4);

  memcpy(&challenge, in.buf + 5, 16);
  printf("Challenge: ");
  mg_hexdumpf(stdout, challenge, 16);

  mbuf_remove(&in, 21);
  return Status::Success;
}
} // namespace GetSessionChallenge

namespace ActivateSession {
Status Request::read(struct mbuf &in) { insist(false, "Not implemented"); }

void Request::write(struct mbuf &out) const {
  mbuf_append(&out, &auth_type, 1);
  mbuf_append(&out, &privilege, 1);
  mbuf_append(&out, &challenge, 16);
  mbuf_append(&out, &sequence, 4);
}

Status Response::read(struct mbuf &in) {
  uint8_t completion_code = in.buf[0];
  insist_return(completion_code == 0, Status::Failure,
                "ActivateSession request failed");

  auth_type = in.buf[1];

  memcpy(&session, in.buf + 2, 4);

  memcpy(&sequence, in.buf + 6, 4);
  // mg_hexdumpf(stdout, in.buf + 6, 4);

  privilege = in.buf[10];
  mbuf_remove(&in, 11);
  return Status::Success;
}

void Response::write(struct mbuf &out) const {}

} // namespace ActivateSession

namespace SetSessionPrivilege {
Status Request::read(struct mbuf &in) { insist(false, "Not implemented"); }
void Request::write(struct mbuf &out) const {
  mbuf_append(&out, &privilege, 1);
}
Status Response::read(struct mbuf &in) {
  insist_return(
      in.len >= 2, Status::Failure,
      "Need at least 2 bytes for SetSessionPrivilege response, but have %zd.",
      in.len);
  uint8_t completion_code = in.buf[0];
  insist_return(completion_code == 0, Status::Failure,
                "SetSessionPrivilege request failed");

  privilege = in.buf[1];
  mbuf_remove(&in, 2);
  return Status::Success;
}
void Response::write(struct mbuf &out) const {}
} // namespace SetSessionPrivilege

namespace ChassisControl {
Status Request::read(struct mbuf &in) { insist(false, "Not implemented"); }
void Request::write(struct mbuf &out) const { mbuf_append(&out, &command, 1); }
Status Response::read(struct mbuf &in) {
  insist_return(
      in.len >= 1, Status::Failure,
      "Need at least 1 bytes for ChassisControl response, but have %zd.",
      in.len);
  uint8_t completion_code = in.buf[0];
  insist_return(completion_code == 0, Status::Failure,
                "ChassisControl request failed");
  mbuf_remove(&in, 1);
  return Status::Success;
}
void Response::write(struct mbuf &out) const {}
} // namespace ChassisControl

void getChannelAuthenticationCapabilities(struct mbuf &buf) {
  RMCP rmcp = {};
  IPMB ipmb = {NetworkFunction::AppRequest, 0x01, 0x38};
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

Status decode(struct mbuf &buf, RMCP &rmcp, IPMB &ipmb, Session &session,
              GetChannelAuthenticationCapabilities::Response &response) {

  // Sum of all bytes 17..end should equal 0 (checksum is negative of sum)
  uint8_t value = 0;
  for (size_t i = 17; i < buf.len; i++) {
    value += (uint8_t)buf.buf[i];
  }
  insist_return(value == 0, Status::Failure,
                "Checksum failed on receiving packet");

  rmcp.read(buf);
  session.read(buf);

  ipmb.read(buf);
  printf("Command: %02x\n", ipmb.command);
  response.read(buf);

  mbuf_remove(&buf, 1); // remove last byte (the checksum)
  return Status::Success;
}

void getSessionChallenge(struct mbuf &buf) {
  RMCP rmcp = {};
  IPMB ipmb = {NetworkFunction::AppRequest, 0x01, 0x39 /* SessionChallenge */};
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

Status decode(struct mbuf &buf, RMCP &rmcp, IPMB &ipmb, Session &session,
              GetSessionChallenge::Response &response) {
  // Sum of all bytes 17..end should equal 0 (checksum is negative of sum)
  uint8_t value = 0;
  for (size_t i = 17; i < buf.len; i++) {
    value += (uint8_t)buf.buf[i];
  }
  insist_return(value == 0, Status::Failure,
                "Checksum failed on receiving packet");

  rmcp.read(buf);
  session.read(buf);

  ipmb.read(buf);
  printf("Command: %02x\n", ipmb.command);
  response.read(buf);

  mbuf_remove(&buf, 1); // remove last byte (the checksum)
  return Status::Success;
}

void activateSession(struct mbuf &buf, uint8_t password[16], uint32_t sequence,
                     uint32_t session_id, uint8_t challenge[16]) {
  RMCP rmcp = {};
  IPMB ipmb = {NetworkFunction::AppRequest, 0x01, 0x3A /* Activate Session */};
  const ActivateSession::Request request(sequence, challenge);
  Session session = {0x02, 0x00000000, session_id, request.length()};

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

  uint32_t scratch = 0; // Sequence number is 0 until after this message
  const uint8_t *msgs[] = {password, (uint8_t *)&session_id,
                           (uint8_t *)(buf.buf + offset), (uint8_t *)&scratch,
                           password};
  const size_t msg_lens[] = {16, 4, buf.len - offset, 4, 16};
  uint8_t authcode[16];
  mg_hash_md5_v(5, msgs, msg_lens, authcode);

  printf("Auth code: ");
  // mg_hexdumpf(stdout, authcode, 16);
  memcpy(buf.buf + offset - (16 + 1), authcode, 16);
}

Status decode(struct mbuf &buf, const uint8_t password[16], RMCP &rmcp,
              IPMB &ipmb, Session &session,
              ActivateSession::Response &response) {
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
  insist_return(
      buf.len == 0, Status::Failure,
      "Buffer length should be empty if decoding is correct, but has %zd bytes",
      buf.len);
  return Status::Success;
}

void setSessionPrivilege(struct mbuf &buf, uint32_t session_id,
                         uint32_t sequence, uint8_t password[16],
                         IPMI::AuthenticationCapability privilege) {
  RMCP rmcp = {};
  IPMB ipmb = {NetworkFunction::AppRequest, 0x01,
               0x3B /* Set Session Privilege*/};
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
  const uint8_t *msgs[] = {password, (uint8_t *)&session_id,
                           (uint8_t *)(buf.buf + offset), (uint8_t *)&sequence,
                           password};
  const size_t msg_lens[] = {16, 4, buf.len - offset, 4, 16};
  uint8_t authcode[16];
  mg_hash_md5_v(5, msgs, msg_lens, authcode);
  // printf("Auth code: ");
  // mg_hexdumpf(stdout, authcode, 16);
  memcpy(buf.buf + offset - (16 + 1), authcode, 16);
}

Status decode(struct mbuf &buf, const uint8_t password[16], RMCP &rmcp,
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
  // printf("Command: %02x\n", ipmb.command);
  response.read(buf);

  mbuf_remove(&buf, 1); // remove last byte (the checksum)
  insist_return(
      buf.len == 0, Status::Failure,
      "Buffer length should be empty if decoding is correct, but has %zd bytes",
      buf.len);
  return Status::Success;
}

void chassisControl(struct mbuf &buf, uint32_t session_id, uint32_t sequence,
                    uint8_t password[16], ChassisControlCommand command) {
  RMCP rmcp = {};
  IPMB ipmb = {NetworkFunction::ChassisRequest, 0x01,
               0x02 /* Chassis Control */};
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
  // printf("Session: %08x\n", session_id);
  // printf("Sequence: %08x\n", sequence);
  const uint8_t *msgs[] = {password, (uint8_t *)&session_id,
                           (uint8_t *)(buf.buf + offset), (uint8_t *)&sequence,
                           password};
  const size_t msg_lens[] = {16, 4, buf.len - offset, 4, 16};
  uint8_t authcode[16];
  mg_hash_md5_v(5, msgs, msg_lens, authcode);
  // printf("Auth code: ");
  // mg_hexdumpf(stdout, authcode, 16);
  memcpy(buf.buf + offset - (16 + 1), authcode, 16);
}
} // namespace IPMI