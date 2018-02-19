#include "mongoose.h"
#include "client.h"

extern "C" {
  void ipmi_client_connection_handler(struct mg_connection *nc, int ev, void *ev_data) {
    auto client = (IPMI::Client *) nc->user_data;
    switch (ev) {
      case MG_EV_CONNECT:
        printf("handler CONNECT(%d)\n", ev);
        client->setConnection(nc);
        break;
      case MG_EV_RECV:
        printf("handler RECV(%d) %zd bytes\n", ev, nc->recv_mbuf.len);
        client->receivePacket(nc->recv_mbuf);
        break;
      case MG_EV_SEND:
        printf("handler SEND(%d) %d bytes\n", ev, * (int *) ev_data);
        break;
      case MG_EV_POLL:
        printf("handler POLL(%d)\n", ev);
        break;
      default:
        printf("handler ??? (%d)\n", ev);
        break;
    }
    (void) client;
    (void) nc;
  }
}
