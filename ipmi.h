#pragma once

#include "insist.h"
#include <stdint.h>
#include <list>
#include <string>
#include "mongoose.h"
#include "ipmi_packet.h"

namespace IPMI {
  enum class AuthenticationCapability {
    Reserved = 0,
    Callback = 1,
    User = 2,
    Operator = 3,
    Administrator = 4,
    OEM = 5
  };

  enum class ChassisControlCommand {
    PowerDown = 0,
    PowerUp = 1,
    PowerCycle = 2,
    HardReset = 3,
    PulseDiagnosticInterrupt = 5,
    SoftShutdown = 5
  };

};

struct rmcp getChannelAuthenticationCapabilities(IPMI::AuthenticationCapability authCap);
struct rmcp getSessionChallenge();

#if 0
namespace IPMI {
  static void getChannelAuthenticationCapabilities(AuthenticationCapability authCap, uint8_t **packet, size_t *length) {
    // IPMI v2 rev 1
    // Section 13.1.3 RMCP Header
    // 0x06 /* Version */
    // 0x00 /* Reserved */
    // 0xFF /* Sequence Number. Not used in this request. */
    // 0x?? /* Class of message */
    //  -> bit 7: Normal (0) or ACK (1)
    //  -> bits 6:5: Reserved/unused
    //  -> bits 4:0: 0-5 reserved, 6 ASF, 7 IPMI, 8 OEM, Others reserved.

    /* Session Request Data:
     * [1 byte] Auth Type
     *  -> none (0), md2 (1), md5 (2), reserved (3), password (4), oem (5), rcmp+ (6)
     * [4 byte] session sequence number
     * [4 byte] session id
     * [1 byte] payload length
     * [x byte] payload
     * [1 byte] "legacy pad"
     */

    /* IPMB message format
     * [1 byte] 'rsAddr' 
     * [1 byte] 'event/rsLUN' aka netFn
     * [1 byte] 'header checksum'
     * [1 byte] rqAddr
     * [1 byte] rqSeq/rqLUN 
     * [1 byte] command
     * [0+ byte] request data bytes
     * [1 byte] checksum
     */
    
    /* Request data
     * Channel number [1 byte]
     *  -> bit 7: ipmi 1.5 (0), ipmi 2.0+ (1)
     *  -> bit [6:4] reserved
     *  -> bit [3:0] channel number (0 through 0xB, 0xF)
     * Requested Maximum Privilege Level
     *  -> bit [7:4] reserved
     *  -> bit [3:0] requested level:
     *    reserved(0), callback(1), user(2), operator(3), administrator(4), oem(5)
     */

    /* Per IPMI v2r1 spec:
     * > for IPMI ... LAN connections the responder's address byte should be set
     * > to 81h, which is the software ID (SWID) for the remote console software.
     *
     * Also there are several references that address 20h is the BMC address.
     *
     * So I think the request source must be 81h and target is 20h for commands like reset.
     * Sniffing the packets of ipmiutil shows this to be the case (`ipmiutil reset ...`)
     */

    /* Payload size:
     * 4 (RMCP header)
     * 10 (IPMI session header)
     * ? (IPMI payload size)
     *   6 IPMB source+target+checksum+command
     *   ? command data
     *   1 checksum
     */

    /* The command here is `Get Channel Authentication Capabilities`
     * In the spec, Table G shows this to be:
     * NetFn: App, CMD 38h
     * This command has 2 byte payload: channel number, and requested maximum privilege level
     */

    *length = 4 + 10 + 7 + 2;
    uint8_t *p = *packet = (uint8_t *) calloc(1, *length);
    if (p == NULL) {
      // calloc failed. Nothing for us to do now but abandon.
      *length = 0;
      return;
    }

    p[0] = 0x06; /* version */
    p[1] = 0x00; /* reserved */
    p[2] = 0xFF; /* Sequence Number; not used in this request. Spec says to set to 255 in this case. */
    p[3] = 0x7; /* Message Class: Normal (0 @ bit 7) | IPMI (0x7) */

    p[4] = 0; /* Authentication Type NONE. Follows spec for Get Channel Authentication Capabilities Command */
    // bytes 5-8 stay zero (sequence number unused in this request)
    // bytes 9-12 stay zero (session id unused in this request)
    // there is no authentication code when auth type is NONE.

    p[13] = (uint8_t) 9; /* payload length: 7 (header) + 2 (command args) */
    p[14] = 0x20; /* BMC's  responder address (i2c terminology) */
    // combo field: NetFN + LUN. Lower 2 bits are the LUN. Upper 6 is the NetFN */
    p[15] = 0x06 << 2; /* `App` - Application Request Network Function */
    p[16] = -(p[14] + p[15]);
    /* Spec: "When the checksum and the bytes are added together, modulo 256, the result should be 0" */
    insist((uint8_t)(p[14] + p[15] + p[16]) == 0, "IPMB requester-checksum failed: %d + %d + %d != 0 (%d)", p[14], p[15], p[16], (p[14] + p[15] + p[16]));

    p[17] = 0x81; /* Requester address. 0x81 == "software id for the remote console" */
    // combo field: Sequence + LUN. Lower 2 bits are the LUN. Upper 6 is the sequence number */
    p[18] = 0x01 << 2; /* Requester sequence + LUN */
    p[19] = 0x38; /* Get Channel Authentication Capabilities command */
    p[20] = 0x0e; /* Use current channel */
    p[21] = (uint8_t) AuthenticationCapability::Administrator; /* Request Administrator privileges */
    p[22] = -(p[17] + p[18] + p[19] + p[20] + p[21]);
    insist((uint8_t)((p[17] + p[18] + p[19] + p[20] + p[21]) + p[22]) == 0, "IPMB requester-command checksum failed.");
  }
}


#endif 
