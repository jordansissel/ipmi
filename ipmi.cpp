#include "ipmi.h"
#include "insist.h"
#include "mongoose.h"
#include <stdint.h>

namespace IPMI {
void RMCP::write(struct mbuf &out) {
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

void Session::write(struct mbuf &out) {
  uint32_t networkbytes;
  mbuf_append(&out, &auth_type, 1);

  networkbytes = htonl(sequence);
  mbuf_append(&out, &networkbytes, 4);

  networkbytes = htonl(id);
  mbuf_append(&out, &networkbytes, 4);

  mbuf_append(&out, &length, 1);
}

void Session::read(struct mbuf &in) {
  insist(in.len >= 10,
         "Need at least 10 bytes for Session header, but have %zd bytes",
         in.len);
  auth_type = in.buf[0];
  memcpy(&sequence, in.buf + 1, 4);
  sequence = htonl(sequence);
  memcpy(&id, in.buf + 5, 4);
  id = htonl(id);

  length = in.buf[9];
  mbuf_remove(&in, 10);
}

void IPMB::write(struct mbuf &out) {
  mbuf_append(&out, &target, 1);
  uint8_t scratch = (netFn << 2) | targetLun;
  mbuf_append(&out, &scratch, 1);

  // Compute checksum
  checksum = -(target + scratch);
  mbuf_append(&out, &checksum, 1);

  mbuf_append(&out, &source, 1);
  scratch = (sequence << 2) | sourceLun;
  mbuf_append(&out, &scratch, 1);
  mbuf_append(&out, &command, 1);
}

void IPMB::read(struct mbuf &in) {
  insist(in.len >= 6,
         "Need at least 6 bytes for IPMB header, but have %zd bytes", in.len);

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
uint8_t Request::length() { return IPMB_SIZE + 2 + CHECKSUM_SIZE; }

void Request::write(struct mbuf &out) {
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

void Response::write(struct mbuf &out) { insist(false, "Not implemented."); }

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

void decodeChannelAuthenticationCapabilitiesResponse(struct mbuf &buf) {
  RMCP rmcp;
  IPMB ipmb;
  Session session;
  GetChannelAuthenticationCapabilities::Response response;

  rmcp.read(buf);
  session.read(buf);
  ipmb.read(buf);
  printf("Command: %02x\n", ipmb.command);
  response.read(buf);
}

} // namespace IPMI