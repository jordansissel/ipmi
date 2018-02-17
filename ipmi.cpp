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


  void Client::begin() {
    state = ClientState::NeedChannelAuthenticationCapabilities;
    printf("Begin... %s\n", stateToString(state));
    // Send the ChannelAuthenticationCapabilities packet
    struct rmcp packet = getChannelAuthenticationCapabilities(AuthenticationCapability::Administrator);
    mg_hexdumpf(stdout, &packet, 23);
    mg_send(connection, (const void *)&packet, 23 /* compute this */);
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

    struct rmcp *r = (struct rmcp *) buf.buf;

    switch (r->session.message.command) {
      case 0x38; /* GetChannelAuthenticationCapabilities */
        break;
      default:
        printf("Unknown command: %02x\n", r->session.message.command);
    }
    printf("0x%02x -> 0x%02x command 0x%02x\n", r->session.message.source, r->session.message.target, r->session.message.command);
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

