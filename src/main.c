#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <glib.h>
#include <glib-unix.h>
#include <pthread.h>
#include <errno.h>
#include <json.h>
#include "common.h"
#include "modem-manager.h"
#include "pmu-manager.h"
#include "controller.h"

#define PCAT_MAIN_MWAN_STATUS_CHECK_TIMEOUT 30
#define PCAT_MAIN_MWAN_STATUS_CHECK_BOOT_WAIT 120

#define PCAT_MAIN_CONFIG_FILE "/etc/pcat-manager.conf"
#define PCAT_MAIN_USER_CONFIG_FILE "/etc/pcat-manager-userdata.conf"

#define PCAT_MAIN_LOG_FILE "/tmp/pcat-manager.log"

typedef enum
{
    PCAT_MAIN_IFACE_WIRED,
    PCAT_MAIN_IFACE_WIRED_V6,
    PCAT_MAIN_IFACE_MOBILE_5G,
    PCAT_MAIN_IFACE_MOBILE_5G_V6,
    PCAT_MAIN_IFACE_MOBILE_LTE,
    PCAT_MAIN_IFACE_MOBILE_LTE_V6,
    PCAT_MAIN_IFACE_LAST
}PCatMainIfaceType;

const gchar * const g_pcat_main_iface_names[
    PCAT_MAIN_IFACE_LAST] =
{
    "wan",
    "wan6",
    "wwan_5g",
    "wwan_5g_v6",
    "wwan_lte",
    "wwan_lte_v6"
};

const gboolean g_pcat_main_iface_is_ipv6[PCAT_MAIN_IFACE_LAST] =
{
    FALSE,
    TRUE,
    FALSE,
    TRUE,
    FALSE,
    TRUE
};

const PCatManagerRouteMode g_pcat_main_iface_route_mode[
    PCAT_MAIN_IFACE_LAST] =
{
    PCAT_MANAGER_ROUTE_MODE_WIRED,
    PCAT_MANAGER_ROUTE_MODE_WIRED,
    PCAT_MANAGER_ROUTE_MODE_MOBILE,
    PCAT_MANAGER_ROUTE_MODE_MOBILE,
    PCAT_MANAGER_ROUTE_MODE_MOBILE,
    PCAT_MANAGER_ROUTE_MODE_MOBILE
};

static gboolean g_pcat_main_cmd_daemonsize = FALSE;
static gboolean g_pcat_main_cmd_distro = FALSE;

static GMainLoop *g_pcat_main_loop = NULL;

static gboolean g_pcat_main_net_status_led_work_mode = TRUE;
static guint g_pcat_main_status_check_timeout_id = 0;
static PCatManagerRouteMode g_pcat_main_net_status_led_applied_mode =
    PCAT_MANAGER_ROUTE_MODE_NONE;

static PCatManagerRouteMode g_pcat_main_network_route_mode =
    PCAT_MANAGER_ROUTE_MODE_NONE;
static gboolean g_pcat_main_mwan_route_check_flag = TRUE;
static gboolean g_pcat_main_connection_check_flag = TRUE;
static gboolean g_pcat_main_network_modem_iface_auto_stop = TRUE;

static PCatManagerMainConfigData g_pcat_main_config_data = {0};
static PCatManagerUserConfigData g_pcat_main_user_config_data =
    {0};

static FILE *g_pcat_main_debug_log_file_fp = NULL;

static GOptionEntry g_pcat_cmd_entries[] =
{
    { "daemon", 'D', 0, G_OPTION_ARG_NONE, &g_pcat_main_cmd_daemonsize,
        "Run as a daemon", NULL },
    { "distro", 0, 0, G_OPTION_ARG_NONE, &g_pcat_main_cmd_distro,
        "Run this program on normal Linux distros (not OpenWRT)", NULL },
    { NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL }
};

static void pcat_main_config_data_clear()
{
    g_pcat_main_config_data.valid = FALSE;
}

static gboolean pcat_main_config_data_load()
{
    GKeyFile *keyfile;
    GError *error = NULL;
    gint ivalue;

    g_pcat_main_config_data.valid = FALSE;

    keyfile = g_key_file_new();

    if(!g_key_file_load_from_file(keyfile, PCAT_MAIN_CONFIG_FILE,
        G_KEY_FILE_NONE, &error))
    {
        g_warning("Failed to load keyfile %s: %s!",
            PCAT_MAIN_CONFIG_FILE,
            error->message!=NULL ? error->message : "Unknown");

        g_clear_error(&error);

        return FALSE;
    }

    memset(g_pcat_main_config_data.pm_battery_discharge_table_normal, 0,
        sizeof(guint) * 11);
    memset(g_pcat_main_config_data.pm_battery_discharge_table_5g, 0,
        sizeof(guint) * 11);
    memset(g_pcat_main_config_data.pm_battery_charge_table, 0,
        sizeof(guint) * 11);

    ivalue = g_key_file_get_integer(keyfile, "PowerManager",
        "AutoShutdownVoltageGeneral", NULL);
    if(ivalue >= 3000 && ivalue < 3700)
    {
        g_pcat_main_config_data.pm_auto_shutdown_voltage_general = ivalue;
    }
    else
    {
        g_pcat_main_config_data.pm_auto_shutdown_voltage_general = 0;
    }

    ivalue = g_key_file_get_integer(keyfile, "PowerManager",
        "AutoShutdownVoltageLTE", NULL);
    if(ivalue >= 3000 && ivalue < 3700)
    {
        g_pcat_main_config_data.pm_auto_shutdown_voltage_lte = ivalue;
    }
    else
    {
        g_pcat_main_config_data.pm_auto_shutdown_voltage_lte = 0;
    }

    ivalue = g_key_file_get_integer(keyfile, "PowerManager",
        "AutoShutdownVoltage5G", NULL);
    if(ivalue >= 3000 && ivalue < 3700)
    {
        g_pcat_main_config_data.pm_auto_shutdown_voltage_5g = ivalue;
    }
    else
    {
        g_pcat_main_config_data.pm_auto_shutdown_voltage_5g = 0;
    }

    ivalue = g_key_file_get_integer(keyfile, "PowerManager",
        "LEDHighVoltage", NULL);
    if(ivalue!=0)
    {
        g_pcat_main_config_data.pm_led_high_voltage = ivalue;
    }
    else
    {
        g_pcat_main_config_data.pm_led_high_voltage = 0;
    }

    ivalue = g_key_file_get_integer(keyfile, "PowerManager",
        "LEDMediumVoltage", NULL);
    if(ivalue!=0)
    {
        g_pcat_main_config_data.pm_led_medium_voltage = ivalue;
    }
    else
    {
        g_pcat_main_config_data.pm_led_medium_voltage = 0;
    }

    ivalue = g_key_file_get_integer(keyfile, "PowerManager",
        "LEDLowVoltage", NULL);
    if(ivalue!=0)
    {
        g_pcat_main_config_data.pm_led_low_voltage = ivalue;
    }
    else
    {
        g_pcat_main_config_data.pm_led_low_voltage = 0;
    }

    ivalue = g_key_file_get_integer(keyfile, "PowerManager",
        "LEDWorkLowVoltage", NULL);
    if(ivalue!=0)
    {
        g_pcat_main_config_data.pm_led_work_low_voltage = ivalue;
    }
    else
    {
        g_pcat_main_config_data.pm_led_work_low_voltage = 0;
    }

    ivalue = g_key_file_get_integer(keyfile, "PowerManager",
        "StartupVoltage", NULL);
    if(ivalue!=0)
    {
        g_pcat_main_config_data.pm_startup_voltage = ivalue;
    }
    else
    {
        g_pcat_main_config_data.pm_startup_voltage = 0;
    }

    ivalue = g_key_file_get_integer(keyfile, "PowerManager",
        "ChargerLimitVoltage", NULL);
    if(ivalue!=0)
    {
        g_pcat_main_config_data.pm_charger_limit_voltage = ivalue;
    }
    else
    {
        g_pcat_main_config_data.pm_charger_limit_voltage = 0;
    }

    ivalue = g_key_file_get_integer(keyfile, "PowerManager",
        "ChargerFastVoltage", NULL);
    if(ivalue!=0)
    {
        g_pcat_main_config_data.pm_charger_fast_voltage = ivalue;
    }
    else
    {
        g_pcat_main_config_data.pm_charger_fast_voltage = 0;
    }

    ivalue = g_key_file_get_integer(keyfile, "PowerManager",
        "BatteryFullThreshold", NULL);
    if(ivalue!=0)
    {
        g_pcat_main_config_data.pm_battery_full_threshold = ivalue;
    }
    else
    {
        g_pcat_main_config_data.pm_battery_full_threshold = 0;
    }

    ivalue = g_key_file_get_integer(keyfile, "PowerManager",
        "BatteryChargeDetectionThreshold", NULL);
    if(ivalue!=0)
    {
        g_pcat_main_config_data.pm_battery_charge_detection_threshold =
           ivalue;
    }
    else
    {
        g_pcat_main_config_data.pm_battery_charge_detection_threshold = 4200;
    }

    ivalue = g_key_file_get_integer(keyfile, "Debug",
        "ModemExternalExecStdoutLog", NULL);
    g_pcat_main_config_data.debug_modem_external_exec_stdout_log =
        ivalue;

    ivalue = g_key_file_get_integer(keyfile, "Debug",
        "OutputLog", NULL);
    g_pcat_main_config_data.debug_output_log = ivalue;

    g_key_file_unref(keyfile);

    g_pcat_main_config_data.valid = TRUE;

    return TRUE;
}

static gboolean pcat_main_user_config_data_load()
{
    GKeyFile *keyfile;
    GError *error = NULL;
    gint iv;
    gchar *sv;
    guint i;
    gchar item_name[32] = {0};
    PCatManagerUserConfigData *uconfig_data =
        &g_pcat_main_user_config_data;
    PCatManagerPowerScheduleData *sdata;

    uconfig_data->valid = FALSE;

    keyfile = g_key_file_new();

    if(!g_key_file_load_from_file(keyfile, PCAT_MAIN_USER_CONFIG_FILE,
        G_KEY_FILE_NONE, &error))
    {
        g_warning("Failed to load keyfile %s: %s!",
            PCAT_MAIN_USER_CONFIG_FILE,
            error->message!=NULL ? error->message : "Unknown");

        g_clear_error(&error);

        return FALSE;
    }

    if(uconfig_data->power_schedule_data!=NULL)
    {
        g_ptr_array_unref(uconfig_data->power_schedule_data);
    }
    uconfig_data->power_schedule_data = g_ptr_array_new_with_free_func(g_free);

    for(i=0;;i++)
    {
        g_snprintf(item_name, 31, "EnableBits%u", i);
        if(!g_key_file_has_key(keyfile, "Schedule", item_name, NULL))
        {
            break;
        }

        sdata = g_new0(PCatManagerPowerScheduleData, 1);

        iv = g_key_file_get_integer(keyfile, "Schedule", item_name, NULL);

        if(iv & PCAT_MANAGER_POWER_SCHEDULE_ENABLE_MINUTE)
        {
            sdata->enabled = TRUE;
        }
        else
        {
            sdata->enabled = FALSE;
        }

        sdata->enable_bits = iv & 0xFF;

        g_snprintf(item_name, 31, "Date%u", i);
        iv = g_key_file_get_integer(keyfile, "Schedule", item_name, NULL);
        sdata->year = (iv / 10000) % 10000;
        sdata->month = (iv / 100) % 100;
        sdata->day = iv % 100;

        g_snprintf(item_name, 31, "Time%u", i);
        iv = g_key_file_get_integer(keyfile, "Schedule", item_name, NULL);
        sdata->hour = (iv / 100) % 100;
        sdata->minute = iv % 100;

        g_snprintf(item_name, 31, "DOWBits%u", i);
        iv = g_key_file_get_integer(keyfile, "Schedule", item_name, NULL);
        sdata->dow_bits = iv & 0xFF;

        g_snprintf(item_name, 31, "Action%u", i);
        iv = g_key_file_get_integer(keyfile, "Schedule", item_name, NULL);
        sdata->action = (iv!=0);

        g_ptr_array_add(uconfig_data->power_schedule_data, sdata);
    }

    uconfig_data->charger_on_auto_start = (g_key_file_get_integer(keyfile,
        "General", "ChargerOnAutoStart", NULL)!=0);
    uconfig_data->charger_on_auto_start_timeout =
        g_key_file_get_integer(keyfile, "General",
        "ChargerOnAutoStartTimeout", NULL);

    g_free(uconfig_data->modem_dial_apn);
    sv = g_key_file_get_string(keyfile, "Modem", "APN", NULL);
    if(sv!=NULL && *sv!='\0')
    {
        uconfig_data->modem_dial_apn = sv;
    }
    else
    {
        uconfig_data->modem_dial_apn = NULL;
    }

    g_free(uconfig_data->modem_dial_user);
    sv = g_key_file_get_string(keyfile, "Modem", "User", NULL);
    if(sv!=NULL && *sv!='\0')
    {
        uconfig_data->modem_dial_user = sv;
    }
    else
    {
        uconfig_data->modem_dial_user = NULL;
    }

    g_free(uconfig_data->modem_dial_password);
    sv = g_key_file_get_string(keyfile, "Modem", "Password", NULL);
    if(sv!=NULL && *sv!='\0')
    {
        uconfig_data->modem_dial_password = sv;
    }
    else
    {
        uconfig_data->modem_dial_password = NULL;
    }

    g_free(uconfig_data->modem_dial_auth);
    sv = g_key_file_get_string(keyfile, "Modem", "Auth", NULL);
    if(sv!=NULL && *sv!='\0')
    {
        uconfig_data->modem_dial_auth = sv;
    }
    else
    {
        uconfig_data->modem_dial_auth = NULL;
    }

    uconfig_data->modem_disable_ipv6 = (g_key_file_get_integer(keyfile,
        "Modem", "DisableIPv6", NULL)!=0);

    uconfig_data->modem_disable_5g_fail_auto_reset =
        (g_key_file_get_integer(keyfile, "Modem",
        "Disable5GFailAutoReset", NULL)!=0);
    uconfig_data->modem_5g_fail_timeout = g_key_file_get_integer(
        keyfile, "Modem", "Connection5GFailTimeout", NULL);

    uconfig_data->modem_iface_auto_stop = TRUE;
    if(g_key_file_has_key(keyfile, "Modem", "IfaceAutoStop", NULL))
    {
        uconfig_data->modem_iface_auto_stop = g_key_file_get_integer(
            keyfile, "Modem", "IfaceAutoStop", NULL);
    }

    if(uconfig_data->modem_5g_fail_timeout < 60)
    {
        uconfig_data->modem_5g_fail_timeout = 600;
    }

    g_key_file_unref(keyfile);

    uconfig_data->valid = TRUE;
    uconfig_data->dirty = FALSE;

    return TRUE;
}

static gboolean pcat_main_user_config_data_save()
{
    GKeyFile *keyfile;
    GError *error = NULL;
    guint i;
    gchar item_name[32] = {0};
    PCatManagerUserConfigData *uconfig_data =
        &g_pcat_main_user_config_data;
    PCatManagerPowerScheduleData *sdata;
    gboolean ret;

    if(!uconfig_data->dirty)
    {
        return TRUE;
    }

    keyfile = g_key_file_new();

    if(uconfig_data->power_schedule_data!=NULL)
    {
        for(i=0;i<uconfig_data->power_schedule_data->len;i++)
        {
            sdata = g_ptr_array_index(uconfig_data->power_schedule_data, i);

            g_snprintf(item_name, 31, "EnableBits%u", i);
            g_key_file_set_integer(keyfile, "Schedule", item_name,
                sdata->enable_bits);

            g_snprintf(item_name, 31, "Date%u", i);
            g_key_file_set_integer(keyfile, "Schedule", item_name,
                (gint)sdata->year * 10000 + (gint)sdata->month * 100 +
                (gint)sdata->day);

            g_snprintf(item_name, 31, "Time%u", i);
            g_key_file_set_integer(keyfile, "Schedule", item_name,
                (gint)sdata->hour * 100 + (gint)sdata->minute);

            g_snprintf(item_name, 31, "DOWBits%u", i);
            g_key_file_set_integer(keyfile, "Schedule", item_name,
                sdata->dow_bits);

            g_snprintf(item_name, 31, "Action%u", i);
            g_key_file_set_integer(keyfile, "Schedule", item_name,
                sdata->action ? 1 : 0);
        }
    }

    g_key_file_set_integer(keyfile, "General", "ChargerOnAutoStart",
        uconfig_data->charger_on_auto_start ? 1 : 0);
    g_key_file_set_integer(keyfile, "General", "ChargerOnAutoStartTimeout",
        uconfig_data->charger_on_auto_start_timeout);

    if(uconfig_data->modem_dial_apn!=NULL)
    {
        g_key_file_set_string(keyfile, "Modem", "APN",
            uconfig_data->modem_dial_apn);
    }
    if(uconfig_data->modem_dial_user!=NULL)
    {
        g_key_file_set_string(keyfile, "Modem", "User",
            uconfig_data->modem_dial_user);
    }
    if(uconfig_data->modem_dial_password!=NULL)
    {
        g_key_file_set_string(keyfile, "Modem", "Password",
            uconfig_data->modem_dial_password);
    }
    if(uconfig_data->modem_dial_auth!=NULL)
    {
        g_key_file_set_string(keyfile, "Modem", "Auth",
            uconfig_data->modem_dial_auth);
    }

    g_key_file_set_integer(keyfile, "Modem", "DisableIPv6",
        uconfig_data->modem_disable_ipv6 ? 1 : 0);
    g_key_file_set_integer(keyfile, "Modem", "Disable5GFailAutoReset",
        uconfig_data->modem_disable_5g_fail_auto_reset ? 1 : 0);
    g_key_file_set_integer(keyfile, "Modem", "Connection5GFailTimeout",
        uconfig_data->modem_5g_fail_timeout);
    g_key_file_set_integer(keyfile, "Modem", "IfaceAutoStop",
        uconfig_data->modem_iface_auto_stop);

    ret = g_key_file_save_to_file(keyfile, PCAT_MAIN_USER_CONFIG_FILE,
        &error);
    if(ret)
    {
        uconfig_data->dirty = FALSE;
    }
    else
    {
        g_warning("Failed to save user configuration data to file %s: %s",
            PCAT_MAIN_USER_CONFIG_FILE, error->message!=NULL ?
            error->message : "Unknown");
    }

    g_key_file_unref(keyfile);

    return TRUE;
}

static gboolean pcat_main_sigterm_func(gpointer user_data)
{
    g_message("SIGTERM detected.");

    if(g_pcat_main_loop!=NULL)
    {
        g_main_loop_quit(g_pcat_main_loop);
    }

    return TRUE;
}

static void *pcat_main_mwan_policy_check_thread_func(void *user_data)
{
    guint i;
    gchar *command;
    gchar *interface_status_stdout = NULL;
    struct json_tokener *tokener;
    struct json_object *root, *child;
    const gchar *iface_protocol_type;
    gboolean wan_ethernet_available;

    while(g_pcat_main_mwan_route_check_flag)
    {
        wan_ethernet_available = FALSE;

        for(i=0;i<PCAT_MAIN_IFACE_LAST;i++)
        {
            command = g_strdup_printf("ubus call network.interface.%s status",
                g_pcat_main_iface_names[i]);
            g_spawn_command_line_sync(command, &interface_status_stdout,
                NULL, NULL, NULL);
            g_free(command);

            G_STMT_START
            {
                if(interface_status_stdout==NULL)
                {
                    break;
                }

                tokener = json_tokener_new();
                root = json_tokener_parse_ex(tokener, interface_status_stdout,
                    strlen(interface_status_stdout));
                json_tokener_free(tokener);

                if(root==NULL)
                {
                    break;
                }

                if(json_object_object_get_ex(root, "up", &child))
                {
                    if(!json_object_get_boolean(child))
                    {
                        json_object_put(root);

                        break;
                    }
                }
                else
                {
                    json_object_put(root);

                    break;
                }

                iface_protocol_type = g_pcat_main_iface_is_ipv6[i] ?
                    "ipv6-address" : "ipv4-address";
                if(json_object_object_get_ex(root, iface_protocol_type,
                    &child))
                {
                    if(json_object_get_type(child)==json_type_array &&
                       json_object_array_length(child) > 0)
                    {
                        if(i==0)
                        {
                            wan_ethernet_available = TRUE;
                        }
                    }
                }

                json_object_put(root);
            }
            G_STMT_END;

            g_free(interface_status_stdout);
        }

        if(g_pcat_main_network_modem_iface_auto_stop)
        {
            if(wan_ethernet_available &&
                g_pcat_main_network_route_mode!=PCAT_MANAGER_ROUTE_MODE_WIRED)
            {
                for(i=0;i<PCAT_MAIN_IFACE_LAST;i++)
                {
                    if(g_pcat_main_iface_route_mode[i]!=
                        PCAT_MANAGER_ROUTE_MODE_MOBILE)
                    {
                        continue;
                    }

                    command = g_strdup_printf(
                        "ubus call network.interface.%s down",
                        g_pcat_main_iface_names[i]);
                    g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
                    g_free(command);
                }

                g_message("Living WAN detected, taking WWAN down.");
            }

            if(!wan_ethernet_available &&
                g_pcat_main_network_route_mode!=PCAT_MANAGER_ROUTE_MODE_MOBILE)
            {
                for(i=0;i<PCAT_MAIN_IFACE_LAST;i++)
                {
                    if(g_pcat_main_iface_route_mode[i]!=
                        PCAT_MANAGER_ROUTE_MODE_MOBILE)
                    {
                        continue;
                    }

                    command = g_strdup_printf(
                        "ubus call network.interface.%s up",
                        g_pcat_main_iface_names[i]);
                    g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
                    g_free(command);
                }

                g_message("WAN disconnected, set WWAN up.");
            }

            pcat_modem_manager_iface_state_set(!wan_ethernet_available);
        }
        else
        {
            pcat_modem_manager_iface_state_set(TRUE);
        }

        g_pcat_main_network_route_mode = wan_ethernet_available ?
            PCAT_MANAGER_ROUTE_MODE_WIRED : PCAT_MANAGER_ROUTE_MODE_MOBILE;
    }

    return NULL;
}

static gboolean pcat_main_status_check_timeout_func(gpointer user_data)
{
    if(g_pcat_main_net_status_led_applied_mode!=
           g_pcat_main_network_route_mode)
    {
        switch(g_pcat_main_network_route_mode)
        {
            case PCAT_MANAGER_ROUTE_MODE_WIRED:
            {
                if(g_pcat_main_net_status_led_work_mode)
                {
                    pcat_pmu_manager_net_status_led_setup(
                        50, 50, 0);
                }

                break;
            }
            case PCAT_MANAGER_ROUTE_MODE_MOBILE:
            {
                if(g_pcat_main_net_status_led_work_mode)
                {
                    pcat_pmu_manager_net_status_led_setup(
                        20, 380, 0);
                }

                break;
            }
            case PCAT_MANAGER_ROUTE_MODE_UNKNOWN:
            {
                if(g_pcat_main_net_status_led_work_mode)
                {
                    pcat_pmu_manager_net_status_led_setup(
                        100, 0, 0);
                }

                break;
            }
            default:
            {
                if(g_pcat_main_net_status_led_work_mode)
                {
                    pcat_pmu_manager_net_status_led_setup(
                        0, 100, 0);
                }

                break;
            }
        }

        g_pcat_main_net_status_led_applied_mode =
            g_pcat_main_network_route_mode;
    }

    return TRUE;
}

static void pcat_main_log_handle_func(const gchar *log_domain,
    GLogLevelFlags log_level, const gchar *message, gpointer user_data)
{
    const char *level = "";
    GLogLevelFlags minlevel = G_LOG_LEVEL_INFO;
    gchar buffer[16384] = {0};
    gint outsize;
    GDateTime *dt;
    gchar *dtstr;

    switch(log_level)
    {
        case G_LOG_LEVEL_DEBUG:
        {
            level = "DEBUG";
            break;
        }
        case G_LOG_LEVEL_INFO:
        {
            level = "INFO";
            break;
        }
        case G_LOG_LEVEL_MESSAGE:
        {
            level = "MESSAGE";
            break;
        }
        case G_LOG_LEVEL_WARNING:
        {
            level = "WARNING";
            break;
        }
        case G_LOG_LEVEL_CRITICAL:
        {
            level = "CRITICAL";
            break;
        }
        case G_LOG_LEVEL_ERROR:
        {
            level = "ERROR";
            break;
        }
        default:
        {
            level = "UNKNOWN";
            break;
        }
    }

    if(log_domain==NULL)
    {
        log_domain = "";
    }

    dt = g_date_time_new_now_local();
    dtstr = g_date_time_format(dt, "%Y/%m/%d %H:%M:%S");
    g_date_time_unref(dt);

    outsize = g_snprintf(buffer, 16383, "[%s] %s-%s: %s\n", dtstr,
        log_domain, level, message);
    g_free(dtstr);

    if(g_pcat_main_debug_log_file_fp !=NULL && outsize > 0)
    {
        fwrite(buffer, 1, outsize, g_pcat_main_debug_log_file_fp);
        fflush(g_pcat_main_debug_log_file_fp);
    }

    if(log_level <= minlevel && outsize > 0)
    {
        fprintf(stderr, "%s", buffer);
    }
    if(log_level <= G_LOG_LEVEL_ERROR)
    {
        fprintf(stderr, "%s", buffer);
        abort();
    }
}


int main(int argc, char *argv[])
{
    GError *error = NULL;
    GOptionContext *context;
    pthread_t mwan_policy_check_thread;

    context = g_option_context_new("- PCat System Manager");
    g_option_context_set_ignore_unknown_options(context, TRUE);
    g_option_context_add_main_entries(context, g_pcat_cmd_entries, "PCATM");
    if(!g_option_context_parse(context, &argc, &argv, &error))
    {
        g_warning("Option parsing failed: %s", error->message);
        g_clear_error(&error);
    }

    if(!pcat_main_config_data_load())
    {
        g_warning("Failed to load main config data!");

        return 1;
    }

    if(g_pcat_main_config_data.debug_output_log)
    {
        g_pcat_main_debug_log_file_fp = fopen(PCAT_MAIN_LOG_FILE, "w");

        g_log_set_handler(NULL, G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL |
            G_LOG_FLAG_RECURSION, pcat_main_log_handle_func, NULL);

    }

    if(!pcat_main_user_config_data_load())
    {
        g_warning("Failed to load user config data, use default one!");
    }

    if(g_pcat_main_cmd_daemonsize)
    {
        daemon(0, 0);
    }

    signal(SIGPIPE, SIG_IGN);
    g_unix_signal_add(SIGTERM, pcat_main_sigterm_func, NULL);

    g_pcat_main_loop = g_main_loop_new(NULL, FALSE);

    if(!pcat_pmu_manager_init())
    {
        g_warning("Failed to initialize PMU manager, "
            "power management may not work!");
    }

    if(!pcat_modem_manager_init())
    {
        g_warning("Failed to initialize modem manager, "
            "LTE/5G modem may not work!");
    }
    if(!pcat_controller_init())
    {
        g_warning("Failed to initialize controller, may not be able to "
            "communicate with other processes.");
    }

    if(g_pcat_main_user_config_data.valid)
    {
        g_pcat_main_network_modem_iface_auto_stop =
            g_pcat_main_user_config_data.modem_iface_auto_stop;
    }

    if(!g_pcat_main_cmd_distro)
    {
        if(pthread_create(&mwan_policy_check_thread, NULL,
            pcat_main_mwan_policy_check_thread_func, NULL)!=0)
        {
            g_warning("Failed to create MWAN policy check thread, routing "
                "check will not work!");
        }
        else
        {
            pthread_detach(mwan_policy_check_thread);
        }

        g_pcat_main_status_check_timeout_id =
            g_timeout_add_seconds(2, pcat_main_status_check_timeout_func, NULL);
    }

    g_main_loop_run(g_pcat_main_loop);

    if(g_pcat_main_status_check_timeout_id > 0)
    {
        g_source_remove(g_pcat_main_status_check_timeout_id);
        g_pcat_main_status_check_timeout_id = 0;
    }

    g_pcat_main_mwan_route_check_flag = FALSE;
    g_pcat_main_connection_check_flag = FALSE;

    g_main_loop_unref(g_pcat_main_loop);
    g_pcat_main_loop = NULL;

    pcat_controller_uninit();
    pcat_modem_manager_uninit();
    pcat_pmu_manager_uninit();
    g_option_context_free(context);
    pcat_main_config_data_clear();

    if(g_pcat_main_debug_log_file_fp!=NULL)
    {
        fclose(g_pcat_main_debug_log_file_fp);
        g_pcat_main_debug_log_file_fp = NULL;
    }

    return 0;
}

PCatManagerMainConfigData *pcat_main_config_data_get()
{
    return &g_pcat_main_config_data;
}

PCatManagerUserConfigData *pcat_main_user_config_data_get()
{
    return &g_pcat_main_user_config_data;
}

void pcat_main_user_config_data_sync()
{
    pcat_main_user_config_data_save();
}

PCatManagerRouteMode pcat_main_network_route_mode_get()
{
    return g_pcat_main_network_route_mode;
}

gboolean pcat_main_is_running_on_distro()
{
    return g_pcat_main_cmd_distro;
}

void pcat_main_network_modem_iface_auto_stop_set(gboolean enabled)
{
    g_pcat_main_network_modem_iface_auto_stop = enabled;
}
