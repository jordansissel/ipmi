#pragma once
#include "mongoose.h"
#include "ipmi.h"

struct rmcp getChannelAuthenticationCapabilities(IPMI::AuthenticationCapability authCap);

void parsePacket(struct mbuf);

#pragma pack(1)
struct ipmi_message {
    uint8_t target;
    uint8_t targetLun : 2;
    uint8_t netFn : 6;
    uint8_t checksum1;

    uint8_t source;
    uint8_t sourceLun : 2;
    uint8_t sequence : 6;
    uint8_t command;

    union parameters {
        struct GetChannelAuthenticationCapabilities {
            uint8_t channel;
            uint8_t privileges;
            uint8_t checksum;
        } GetChannelAuthenticationCapabilities;
    } parameters;
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
