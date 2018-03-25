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
#pragma once
#if CS_PLATFORM == CS_P_UNIX || CS_PLATFORM == CS_P_WINDOWS
void ipmi_client_connection_handler(struct mg_connection *nc, int ev,
                                    void *ev_data);
#else
void ipmi_client_connection_handler(struct mg_connection *nc, int ev,
                                    void *ev_data, void *user_data);

extern "C" {
bool mgos_ipmi_init();
}
#endif