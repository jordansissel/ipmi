#ifndef _IPMI_MONGOOSE_H_
#define _IPMI_MONGOOSE_H_
extern "C" {
  void ipmi_client_connection_handler(struct mg_connection *nc, int ev, void *ev_data);
}
#endif /* _IPMI_MONGOOSE_H_ */
