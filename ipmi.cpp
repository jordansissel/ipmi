#include "insist.h"
#include "ipmi.h"
#include <stdint.h>
#include <string>

namespace IPMI {
  void Client::chassisControl(ChassisControlCommand command) {
    /**
     * mg_connect_opt w/ Client as user_data
     * On MG_EV_CONNET, send GetChannelAuthCapabilities
     * on recv, process, then send GetSessionChallenge
     * on recv, process, then send ActivateSession
     * on recv, process, then send SetSessionPrivilegeLevel
     * on recv, process, then send the command.
     */

  };
};

