#include "insist.h"
#include "ipmi.h"
#include <stdint.h>
#include <string>

#include "ipmi_packet.h"
#include "mongoose.h"

namespace IPMI {
  static char unknown_buf[50];
  static const char *stateToString(const ClientState s) {
    switch (s) {
    case ClientState::Initial:
      return "Initial";
    case ClientState::NeedChannelAuthenticationCapabilities:
      return "NeedChannelAuthenticationCapabilities";
    case ClientState::NeedSessionChallenge:
      return "NeedSessionChallenge";
    case ClientState::NeedActivateSession:
      return "NeedActivateSession";
    case ClientState::NeedSetSessionPrivilegeLevel:
      return "NeedSetSessionPrivilegeLevel";
    case ClientState::SessionReady:
      return "SessionReady";
    }

    sprintf(unknown_buf, "Unknown state: %d", (int) s);
    return unknown_buf;
  }

  void Client::send(ChassisControlCommand command) {
    printf("send() state = %s\n", stateToString(state));
    requestQueue.push_back(command);

    if (state == ClientState::Initial && connection != NULL) {
      begin();
    }
  }

  void Client::chassisControl(ChassisControlCommand command) {
    printf("State: %s\n", stateToString(state));
    send(command);
  }

  #pragma pack(1)
  struct ipmi_message {
    uint8_t target;
    uint8_t netFn : 6;
    uint8_t targetLun : 2;
    uint8_t checksum1;

    uint8_t source;
    uint8_t sequence : 6;
    uint8_t sourceLun : 2;
    uint8_t command;

    union parameters {
      struct GetChannelAuthenticationCapabilities {
        uint8_t channel;
        uint8_t privileges;
      };
    };
  };

  struct rmcp {
    uint8_t version;
    uint8_t reserved;
    uint8_t sequence;

    uint8_t message_type : 7;
    uint8_t message_class : 1;
    
    struct ipmi_session {
      uint8_t authentication_type;
      uint32_t sequence_number;
      uint32_t session_id;
      uint8_t length;
      struct ipmi_message message;
    } session;
  };
  #pragma pack()


  void Client::begin() {
    state = ClientState::NeedChannelAuthenticationCapabilities;
    printf("Begin... %s\n", stateToString(state));
    // Send the ChannelAuthenticationCapabilities packet
    struct mbuf packet = getChannelAuthenticationCapabilities(AuthenticationCapability::Administrator);

    struct rmcp *req = (struct rmcp *)packet.buf;
    printf("Version: %d\n", req->version);
    printf("Seq: %d\n", req->sequence);
    printf("Message class: %d\n", req->message_type);

    printf("Length: %d\n", req->session.length);
    printf("%02x -> %02x : %02x\n", req->session.message.source, req->session.message.target, req->session.message.command);

    mg_send(connection, packet.buf, packet.len);
    mbuf_free(&packet);
  }

  void Client::receivePacket(struct mbuf buf) {
    printf("receivePacket() state = %s\n", stateToString(state));
    switch (state) {
      case ClientState::Initial:
        begin();
        break;
      case ClientState::NeedChannelAuthenticationCapabilities:
        receive(buf);
        // If all is good, set state NeedSessionChallenge and send a GetSessionChallenge request
        break;
      case ClientState::NeedSessionChallenge:
        // If all is good, set state NeedActivateSssion and send a ActivateSssion request
        break;
      case ClientState::NeedActivateSession: 
        // If all is good, set state NeedActivateSssion and send a SetSessionPrivilegeLevel request
        break;
      case ClientState::NeedSetSessionPrivilegeLevel:
        // If all is good, set state SessionReady

        // After: Pop any command waiting in the queue and send it.
        break;
      case ClientState::SessionReady: 
        // what now?
        // After: Pop any command waiting in the queue and send it.
        break;
    }
  }

  void Client::receive(struct mbuf buf) {
    mg_hexdumpf(stdout, buf.buf, buf.len);

    insist((uint8_t)buf.buf[0] == 0x06, "Invalid RMCP version (%02x required but got %02x)", 0x06, (uint8_t) buf.buf[0]);
    insist((uint8_t)buf.buf[1] == 0x00, "byte 2 of RMCP must be 0x00, got %02x", (uint8_t) buf.buf[1]);

    if (state == ClientState::NeedChannelAuthenticationCapabilities) {
      insist((uint8_t) buf.buf[2] == 0xff, "sequence number of RMCP must be 0xff, got 0x%02x", (uint8_t) buf.buf[2]);
    }

    insist((uint8_t) buf.buf[3] == 0x07, "message class must be normal ipmi (0x07), but got 0x%02x", (uint8_t) buf.buf[3]);

    uint8_t authType = buf.buf[4];
    uint32_t sequence, session;
    memcpy(&sequence, buf.buf + 5, 4);
    sequence = ntohl(sequence);
    memcpy(&session, buf.buf + 9, 4);
    sequence = ntohl(sequence);

    uint8_t length = (uint8_t) buf.buf[13];
    uint8_t targetAddress = (uint8_t) buf.buf[14];
    uint8_t netFn = (uint8_t) buf.buf[15] >> 2; // upper 6 bits
    uint8_t targetLun = (uint8_t) buf.buf[15] & 3; // lower 2 bits

    // checksum
    insist(buf.buf[16] + buf.buf[14] + buf.buf[15] == 0, "Checksum failed on request target");

    uint8_t sourceAddress = (uint8_t) buf.buf[17];
    uint8_t reqSequence = (uint8_t) buf.buf[18] >> 2; // upper 6 bits
    uint8_t reqLun = (uint8_t) buf.buf[18] & 3; // lower 2 bits
    uint8_t command = buf.buf[19];

    printf("0x%02x -> 0x%02x command 0x%02x\n", sourceAddress, targetAddress, command);
    switch (command) {
    case 0x38:
      handleGetChannelAuthenticationCapabilities(buf);
      break;
    default:
      printf("Unknown command 0x%02x\n", command);
    }
  }

  void Client::handleGetChannelAuthenticationCapabilities(struct mbuf buf) {
    uint8_t channelNumber, authTypeSupport; 

    // Check completion code == 0
    insist(buf.buf[20] == 0, "GetChannelAuthenticationCapabilities completion code was nonzero");

    channelNumber = (uint8_t) buf.buf[21];

    uint16_t authSupport = buf.buf[22] << 8 | buf.buf[23];

    if (authSupport & (1<<10)) { printf("MD5 supported\n"); }
    if (authSupport & (1<<9)) { printf("MD2 supported\n"); }
    if (authSupport & (1<<12)) { printf("straight password supported\n"); }
  }

  void Client::setConnection(mg_connection *c) {
    state = ClientState::Initial;
    connection = c;

    if (requestQueue.size() > 0) {
      begin();
    }
  }


};

