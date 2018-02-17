#pragma once
#include "mongoose.h"
#include "ipmi.h"

struct mbuf getChannelAuthenticationCapabilities(IPMI::AuthenticationCapability authCap);

void parsePacket(struct mbuf);