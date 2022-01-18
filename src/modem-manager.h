#ifndef HAVE_PCAT_MODEM_MANAGER_H
#define HAVE_PCAT_MODEM_MANAGER_H

#include <glib.h>

G_BEGIN_DECLS

typedef enum
{
    PCAT_MODEM_MANAGER_MODE_NONE,
    PCAT_MODEM_MANAGER_MODE_2G,
    PCAT_MODEM_MANAGER_MODE_3G,
    PCAT_MODEM_MANAGER_MODE_LTE,
    PCAT_MODEM_MANAGER_MODE_5G
}PCatModemManagerMode;

typedef enum {
    PCAT_MODEM_MANAGER_SIM_STATE_ABSENT = 0,
    PCAT_MODEM_MANAGER_SIM_STATE_NOT_READY = 1,
    PCAT_MODEM_MANAGER_SIM_STATE_READY = 2,
    PCAT_MODEM_MANAGER_SIM_STATE_PIN = 3,
    PCAT_MODEM_MANAGER_SIM_STATE_PUK = 4,
    PCAT_MODEM_MANAGER_SIM_STATE_NETWORK_PERSONALIZATION = 5,
    PCAT_MODEM_MANAGER_SIM_STATE_BAD = 6,
}PCatModemManagerSIMState;

gboolean pcat_modem_manager_init();
void pcat_modem_manager_uninit();
gboolean pcat_modem_manager_status_get(PCatModemManagerMode *mode,
    PCatModemManagerSIMState *sim_state, gint *signal_strength,
    gchar **isp_name, gchar **isp_plmn);

G_END_DECLS

#endif

