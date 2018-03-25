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
#include "client.h"
#include "mongoose/mongoose.h"

#if CS_PLATFORM == CS_P_UNIX || CS_PLATFORM == CS_P_WINDOWS
void ipmi_client_connection_handler(struct mg_connection *nc, int ev,
                                    void *ev_data) {
  auto client = (IPMI::Client *)nc->user_data;
#else
void ipmi_client_connection_handler(struct mg_connection *nc, int ev,
                                    void *ev_data, void *user_data) {
  auto client = (IPMI::Client *)user_data;
#endif
  switch (ev) {
  case MG_EV_CONNECT:
    printf("handler CONNECT(%d)\n", ev);
    client->setConnection(nc);
    break;
  case MG_EV_RECV:
    printf("handler RECV(%d) %zd bytes\n", ev, nc->recv_mbuf.len);
    client->receivePacket(nc->recv_mbuf);
    // Remove packet from buffer after processing:
    mbuf_remove(&nc->recv_mbuf, nc->recv_mbuf.len);
    break;
  case MG_EV_SEND:
    printf("handler SEND(%d) %d bytes\n", ev, *(int *)ev_data);
    break;
  case MG_EV_POLL:
    // printf("handler POLL(%d)\n", ev);
    break;
  default:
    // printf("handler ??? (%d)\n", ev);
    break;
  }
  (void)ev_data;
  (void)nc;
}
