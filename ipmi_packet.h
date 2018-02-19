#pragma once
#include "mongoose.h"

void parsePacket(struct mbuf);

#define AUTH_TYPE_MD5(value) (value & 1<<2)

#pragma pack(1)
union ActivateSession {
    struct Request {
        uint8_t auth_code;
        uint8_t auth_type;
        uint8_t privilege;
        uint8_t challenge;
        uint32_t sequence;
    };
};
union GetChannelAuthenticationCapabilities {
    struct Request {
        uint8_t channel;
        uint8_t privileges;
        uint8_t checksum;
    } request;

    struct Response {
        uint8_t completion_code;
        uint8_t channel;
        uint8_t auth_type1;
        uint8_t auth_type2;
        uint8_t reserved;
        uint8_t oem1, oem2, oem3;
        uint8_t oem_aux;
    } response;
};

/* IPMI 2nd gen v2r1 section 22.16 */
union GetSessionChallenge {
    struct Request {
        uint8_t auth_type;
        uint8_t username[16];
        uint8_t checksum;
    } request;
    struct Response {
        uint8_t completion_code;
        uint32_t session_id;
        uint8_t challenge[16];
    } response;
};

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
        union GetChannelAuthenticationCapabilities getChannelAuthenticationCapabilities;
        union GetSessionChallenge getSessionChallenge;
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
    } session;
    struct ipmi_message message;
};

struct rmcp_with_auth {
    uint8_t version;
    uint8_t reserved;
    uint8_t sequence;

    uint8_t message_type : 7;
    uint8_t message_class : 1;

    struct ipmi_session {
        uint8_t authentication_type;
        uint32_t sequence_number;
        uint32_t session_id;

        /* MD5 AuthCode: hash(password + Session ID + IPMI Message Data + session seq# + password) */
        uint8_t auth_code[16];
        uint8_t length;
    } session;

    struct ipmi_message message;
}
#pragma pack()