#include <stdio.h>
#include <errno.h>
#include <termios.h>
#include <libusb.h>
#include <gio/gio.h>
#include "modem-manager.h"
#include "common.h"

#define PCAT_MODEM_MANAGER_POWER_WAIT_TIME 50
#define PCAT_MODEM_MANAGER_POWER_READY_TIME 30
#define PCAT_MODEM_MANAGER_RESET_ON_TIME 3
#define PCAT_MODEM_MANAGER_RESET_WAIT_TIME 30

typedef enum
{
    PCAT_MODEM_MANAGER_STATE_NONE,
    PCAT_MODEM_MANAGER_STATE_READY,
    PCAT_MODEM_MANAGER_STATE_RUN
}PCatModemManagerState;

typedef struct _PCatModemManagerUSBData
{
    PCatModemManagerDeviceType device_type;
    guint16 id_vendor;
    guint16 id_product;
    guint power_usage;
    const gchar *external_control_exec;
    gboolean external_control_exec_is_daemon;
}PCatModemManagerUSBData;

typedef struct _PCatModemManagerData
{
    gboolean initialized;
    gboolean work_flag;
    GMutex mutex;
    PCatModemManagerState state;
    GThread *modem_work_thread;
    GHashTable *modem_mode_table;
    gboolean modem_exist;
    gboolean system_first_run;
    gboolean modem_first_run;
    PCatModemManagerMode modem_mode;
    gboolean modem_rfkill_state;
    gint modem_signal_strength;
    PCatModemManagerSIMState sim_state;
    gchar *isp_name;
    gchar *isp_plmn;

    libusb_context *usb_ctx;

    GSubprocess *external_control_exec_process;
    GInputStream *external_control_exec_stdout_stream;
    GSource *external_control_exec_stdout_read_source;
    GString *external_control_exec_stdout_buffer;

    FILE *external_control_exec_stdout_log_file;
    PCatModemManagerDeviceType device_type;
    gboolean modem_have_5g_connected;
    gint64 modem_5g_connection_timestamp;

    guint scanning_timeout_id;
    guint modem_power_usage;
    gboolean modem_iface_enabled;
}PCatModemManagerData;

static PCatModemManagerUSBData g_pcat_modem_manager_supported_dev_list[] =
{
    {
        .device_type = PCAT_MODEM_MANAGER_DEVICE_5G,
        .id_vendor = 0x2C7C,
        .id_product = 0x900,
        .power_usage = 2,
        .external_control_exec = "quectel-cm",
        .external_control_exec_is_daemon = FALSE
    },
    {
        .device_type = PCAT_MODEM_MANAGER_DEVICE_5G,
        .id_vendor = 0x2C7C,
        .id_product = 0x800,
        .power_usage = 1,
        .external_control_exec = "quectel-cm",
        .external_control_exec_is_daemon = FALSE
    },
    {
        .device_type = PCAT_MODEM_MANAGER_DEVICE_5G,
        .id_vendor = 0x2C7C,
        .id_product = 0x801,
        .power_usage = 1,
        .external_control_exec = "quectel-cm",
        .external_control_exec_is_daemon = FALSE
    },
    {
        .device_type = PCAT_MODEM_MANAGER_DEVICE_GENERAL,
        .id_vendor = 0x2C7C,
        .id_product = 0,
        .power_usage = 1,
        .external_control_exec = "quectel-cm",
        .external_control_exec_is_daemon = FALSE
    }
};

static PCatModemManagerData g_pcat_modem_manager_data = {0};

static inline void pcat_modem_manager_external_control_exec_line_parser(
    PCatModemManagerData *mm_data, const guint8 *buffer, gssize size)
{
    gsize i, j;
    GString *str = mm_data->external_control_exec_stdout_buffer;
    gsize used_size = 0;
    const gchar *start;
    gchar **fields, **values;
    GHashTable *table;
    const gchar *cmd, *smode, *value_raw_str;
    gint signal_raw;
    gint signal_value;
    gint sim_state;
    gint isp_name_is_ucs2 = 0;
    PCatModemManagerMode modem_mode;
    gboolean downgrade_from_5g = FALSE;

    if(mm_data->external_control_exec_stdout_log_file!=NULL)
    {
        fwrite(buffer, size, 1,
            mm_data->external_control_exec_stdout_log_file);
        fflush(mm_data->external_control_exec_stdout_log_file);
    }

    g_string_append_len(str, (const gchar *)buffer, size);

    if(str->len > 1048576)
    {
        str->len = 0;
    }

    start = str->str;
    for(i=0;i<str->len;i++)
    {
        if(str->str[i]=='\n')
        {
            str->str[i] = '\0';

            fields = g_strsplit(start, ",", -1);

            if(fields!=NULL)
            {
                table = g_hash_table_new_full(g_str_hash, g_str_equal,
                    g_free, g_free);

                for(j=0;fields[j]!=NULL;j++)
                {
                    values = g_strsplit(fields[j], "=", 2);
                    if(values!=NULL)
                    {
                        if(values[0]!=NULL && values[1]!=NULL)
                        {
                            g_hash_table_replace(table, g_strdup(values[0]),
                                g_strdup(values[1]));
                        }

                        g_strfreev(values);
                    }
                }
                g_strfreev(fields);

                cmd = g_hash_table_lookup(table, "CMD");

                if(g_strcmp0(cmd, "SIGNALINFO")==0)
                {
                    signal_value = 0;

                    smode = g_hash_table_lookup(table, "MODE");
                    modem_mode = GPOINTER_TO_UINT(
                        g_hash_table_lookup(mm_data->modem_mode_table, smode));

                    if(modem_mode==PCAT_MODEM_MANAGER_MODE_5G &&
                       mm_data->modem_mode < PCAT_MODEM_MANAGER_MODE_5G)
                    {
                        downgrade_from_5g = TRUE;
                    }

                    mm_data->modem_mode = modem_mode;

                    if(mm_data->modem_mode==PCAT_MODEM_MANAGER_MODE_5G)
                    {
                        mm_data->modem_have_5g_connected = TRUE;
                        mm_data->modem_5g_connection_timestamp =
                            g_get_monotonic_time();
                    }
                    else
                    {
                        if(mm_data->modem_have_5g_connected &&
                            downgrade_from_5g)
                        {
                            mm_data->modem_5g_connection_timestamp =
                                g_get_monotonic_time();
                        }
                    }

                    /* Signal strength calculation based on cellular industry standards
                     * References:
                     * - https://www.digi.com/support/knowledge-base/understanding-lte-signal-strength-values
                     * - https://wiki.teltonika-networks.com/view/RSRP_and_RSRQ
                     * - https://poynting.tech/articles/antenna-faq/signal-strength-measure-rsrp-rsrq-and-sinr-reference-for-lte-cheat-sheet/
                     */
                    mm_data->modem_signal_strength = 0;

                    signal_value = 0;
                    value_raw_str = g_hash_table_lookup(table, "RSSI");
                    if(value_raw_str!=NULL)
                    {
                        if(sscanf(value_raw_str, "%d", &signal_raw)>0)
                        {
                            if(signal_raw >= -55)
                            {
                                signal_value = 100;
                            }
                            else if(signal_raw >= -95)
                            {
                                signal_value = (signal_raw + 95) * 100 / 40;
                            }
                        }
                    }
                    if(mm_data->modem_signal_strength < signal_value)
                    {
                        mm_data->modem_signal_strength = signal_value;
                    }

                    signal_value = 0;
                    value_raw_str = g_hash_table_lookup(table, "RSRQ");
                    if(value_raw_str!=NULL)
                    {
                        if(sscanf(value_raw_str, "%d", &signal_raw)>0)
                        {
                            if(signal_raw >= -8)
                            {
                                signal_value = 100;
                            }
                            else if(signal_raw >= -18)
                            {
                                signal_value = (signal_raw + 18) * 10;
                            }
                        }
                    }
                    if(mm_data->modem_signal_strength < signal_value)
                    {
                        mm_data->modem_signal_strength = signal_value;
                    }

                    signal_value = 0;
                    value_raw_str = g_hash_table_lookup(table, "RSRP");
                    if(value_raw_str!=NULL)
                    {
                        if(sscanf(value_raw_str, "%d", &signal_raw)>0)
                        {
                            if(signal_raw >= -70)
                            {
                                signal_value = 100;
                            }
                            else if(signal_raw >= -110)
                            {
                                signal_value = (signal_raw + 110) * 100 / 40;
                            }
                        }
                    }
                    if(mm_data->modem_signal_strength < signal_value)
                    {
                        mm_data->modem_signal_strength = signal_value;
                    }

                    signal_value = 0;
                    value_raw_str = g_hash_table_lookup(table, "RSCP");
                    if(value_raw_str!=NULL)
                    {
                        if(sscanf(value_raw_str, "%d", &signal_raw)>0)
                        {
                            if(signal_raw >= -60)
                            {
                                signal_value = 100;
                            }
                            else if(signal_raw >= -100)
                            {
                                signal_value = (signal_raw + 100) * 100 / 40;
                            }
                        }
                    }
                    if(mm_data->modem_signal_strength < signal_value)
                    {
                        mm_data->modem_signal_strength = signal_value;
                    }

                    g_message("Modem signal strength: %d", mm_data->modem_signal_strength);
                }
                else if(g_strcmp0(cmd, "SIMSTATUS")==0)
                {
                    value_raw_str = g_hash_table_lookup(table, "STATE");

                    if(value_raw_str!=NULL)
                    {
                        if(sscanf(value_raw_str, "%d", &sim_state) > 0)
                        {
                            mm_data->sim_state = sim_state;

                            g_message("SIM card state changed to %d.",
                                sim_state);
                        }
                    }
                }
                else if(g_strcmp0(cmd, "ISPINFO")==0)
                {
                    value_raw_str = g_hash_table_lookup(table, "ALPHABET");
                    if(value_raw_str!=NULL)
                    {
                        sscanf(value_raw_str, "%d", &isp_name_is_ucs2);
                    }

                    value_raw_str = g_hash_table_lookup(table, "FNN");
                    if(value_raw_str!=NULL)
                    {
                        if(mm_data->isp_name!=NULL)
                        {
                            g_free(mm_data->isp_name);
                        }
                        mm_data->isp_name = g_strdup(value_raw_str);
                    }

                    value_raw_str = g_hash_table_lookup(table, "RPLMN");
                    if(value_raw_str!=NULL)
                    {
                        if(mm_data->isp_plmn!=NULL)
                        {
                            g_free(mm_data->isp_plmn);
                        }
                        mm_data->isp_plmn = g_strdup(value_raw_str);
                    }
                }

                g_hash_table_unref(table);
            }
            start = str->str + i + 1;
            used_size = i + 1;
        }
    }

    if(used_size > 0)
    {
        g_string_erase(str, 0, used_size);
    }
}

static gboolean pcat_modem_manager_external_control_exec_stdout_watch_func(
    GObject *object, gpointer user_data)
{
    PCatModemManagerData *mm_data = (PCatModemManagerData *)user_data;
    gssize rsize;
    guint8 buffer[4096];
    GError *error = NULL;

    while((rsize=g_pollable_input_stream_read_nonblocking(
        G_POLLABLE_INPUT_STREAM(object), buffer, 4096, NULL, &error))>0)
    {
        pcat_modem_manager_external_control_exec_line_parser(mm_data,
            buffer, rsize);
    }

    if(error!=NULL)
    {
        g_clear_error(&error);
    }

    return TRUE;
}

static void pcat_modem_manager_external_control_exec_wait_func(
    GObject *source_object, GAsyncResult *res, gpointer user_data)
{
    PCatModemManagerData *mm_data = (PCatModemManagerData *)user_data;

    g_subprocess_wait_check_finish(G_SUBPROCESS(source_object), res, NULL);

    g_mutex_lock(&(mm_data->mutex));
    g_object_unref(source_object);
    if(mm_data->external_control_exec_stdout_read_source!=NULL)
    {
        g_source_destroy(mm_data->external_control_exec_stdout_read_source);
        g_source_unref(mm_data->external_control_exec_stdout_read_source);
        mm_data->external_control_exec_stdout_read_source = NULL;
    }
    mm_data->external_control_exec_stdout_stream = NULL;

    if(mm_data->external_control_exec_process!=NULL)
    {
        mm_data->external_control_exec_process = NULL;
    }
    g_mutex_unlock(&(mm_data->mutex));
}

static inline gboolean pcat_modem_manager_run_external_exec(
    PCatModemManagerData *mm_data, const PCatModemManagerUSBData *usb_data)
{
    GError *error = NULL;
    gboolean ret = TRUE;
    PCatManagerUserConfigData *uconfig_data;

    if(mm_data==NULL || usb_data==NULL ||
        usb_data->external_control_exec==NULL)
    {
        return FALSE;
    }

    uconfig_data = pcat_main_user_config_data_get();

    if(!usb_data->external_control_exec_is_daemon)
    {
        G_STMT_START
        {
            g_mutex_lock(&(mm_data->mutex));
            if(mm_data->external_control_exec_process!=NULL)
            {
                g_mutex_unlock(&(mm_data->mutex));
                break;
            }

            if(usb_data->id_vendor==0x2C7C &&
                uconfig_data->modem_dial_apn!=NULL)
            {
                if(uconfig_data->modem_dial_user!=NULL &&
                    uconfig_data->modem_dial_password!=NULL &&
                    uconfig_data->modem_dial_auth!=NULL)
                {
                    if(!uconfig_data->modem_disable_ipv6)
                    {
                        mm_data->external_control_exec_process =
                            g_subprocess_new(
                            G_SUBPROCESS_FLAGS_STDOUT_PIPE |
                            G_SUBPROCESS_FLAGS_STDERR_MERGE, &error,
                            usb_data->external_control_exec, "-4", "-6", "-s",
                            uconfig_data->modem_dial_apn,
                            uconfig_data->modem_dial_user,
                            uconfig_data->modem_dial_password,
                            uconfig_data->modem_dial_auth, NULL);
                    }
                    else
                    {
                        mm_data->external_control_exec_process =
                            g_subprocess_new(
                            G_SUBPROCESS_FLAGS_STDOUT_PIPE |
                            G_SUBPROCESS_FLAGS_STDERR_MERGE, &error,
                            usb_data->external_control_exec, "-s",
                            uconfig_data->modem_dial_apn,
                            uconfig_data->modem_dial_user,
                            uconfig_data->modem_dial_password,
                            uconfig_data->modem_dial_auth, NULL);
                    }
                }
                else
                {
                    if(!uconfig_data->modem_disable_ipv6)
                    {
                        mm_data->external_control_exec_process =
                            g_subprocess_new(G_SUBPROCESS_FLAGS_STDOUT_PIPE |
                            G_SUBPROCESS_FLAGS_STDERR_MERGE, &error,
                            usb_data->external_control_exec, "-4", "-6", "-s",
                            uconfig_data->modem_dial_apn, NULL);
                    }
                    else
                    {
                        mm_data->external_control_exec_process =
                            g_subprocess_new(G_SUBPROCESS_FLAGS_STDOUT_PIPE |
                            G_SUBPROCESS_FLAGS_STDERR_MERGE, &error,
                            usb_data->external_control_exec, "-s",
                            uconfig_data->modem_dial_apn, NULL);
                    }
                }
            }
            else
            {
                if(!uconfig_data->modem_disable_ipv6)
                {
                    mm_data->external_control_exec_process = g_subprocess_new(
                        G_SUBPROCESS_FLAGS_STDOUT_PIPE |
                        G_SUBPROCESS_FLAGS_STDERR_MERGE, &error,
                        usb_data->external_control_exec, "-4", "-6", NULL);
                }
                else
                {
                    mm_data->external_control_exec_process = g_subprocess_new(
                        G_SUBPROCESS_FLAGS_STDOUT_PIPE |
                        G_SUBPROCESS_FLAGS_STDERR_MERGE, &error,
                        usb_data->external_control_exec, NULL);
                }
            }


            if(mm_data->external_control_exec_process==NULL)
            {
                g_mutex_unlock(&(mm_data->mutex));
                g_warning("Failed to run external modem control "
                    "executable file %s: %s",
                    usb_data->external_control_exec,
                    error!=NULL ? error->message: "Unknown");
                g_clear_error(&error);
                ret = FALSE;

                break;
            }

            mm_data->external_control_exec_stdout_stream =
                g_subprocess_get_stdout_pipe(
                mm_data->external_control_exec_process);
            if(mm_data->external_control_exec_stdout_stream!=NULL)
            {
                mm_data->external_control_exec_stdout_read_source =
                    g_pollable_input_stream_create_source(
                    G_POLLABLE_INPUT_STREAM(
                    mm_data->external_control_exec_stdout_stream),
                    NULL);

                g_source_set_callback(
                    mm_data->external_control_exec_stdout_read_source,
                    (GSourceFunc)
                    pcat_modem_manager_external_control_exec_stdout_watch_func,
                    mm_data, NULL);
                g_source_attach(
                    mm_data->external_control_exec_stdout_read_source, NULL);
            }

            g_subprocess_wait_async(
                mm_data->external_control_exec_process, NULL,
                pcat_modem_manager_external_control_exec_wait_func,
                mm_data);
            g_mutex_unlock(&(mm_data->mutex));

            mm_data->modem_first_run = FALSE;
        }
        G_STMT_END;

    }
    else if(mm_data->modem_first_run)
    {
        /* TODO: Run external control exec as daemon. */

        mm_data->modem_first_run = FALSE;
    }

    return ret;
}

static void pcat_modem_manager_external_control_terminate(
    PCatModemManagerData *mm_data)
{
    g_mutex_lock(&(mm_data->mutex));
    if(mm_data->external_control_exec_stdout_read_source!=NULL)
    {
        g_source_destroy(mm_data->external_control_exec_stdout_read_source);
        g_source_unref(mm_data->external_control_exec_stdout_read_source);
        mm_data->external_control_exec_stdout_read_source = NULL;
    }
    mm_data->external_control_exec_stdout_stream = NULL;

    if(mm_data->external_control_exec_process!=NULL)
    {
        g_subprocess_force_exit(mm_data->external_control_exec_process);
        mm_data->external_control_exec_process = NULL;
    }
    g_mutex_unlock(&(mm_data->mutex));
}

static gboolean pcat_modem_manager_scan_usb_devs(PCatModemManagerData *mm_data)
{
    libusb_device *dev;
    guint i;
    ssize_t cnt;
    struct libusb_device_descriptor desc;
    int r;
    libusb_device **devs = NULL;
    const PCatModemManagerUSBData *usb_data;
    guint uc;
    gboolean detected;
    PCatModemManagerDeviceType device_type = PCAT_MODEM_MANAGER_DEVICE_NONE;
    gboolean modem_exist = FALSE;

    cnt = libusb_get_device_list(NULL, &devs);
    if(cnt < 0)
    {
        return FALSE;
    }

    mm_data->modem_power_usage = 0;

    for(i=0;devs[i]!=NULL && !modem_exist;i++)
    {
        detected = FALSE;
        dev = devs[i];

        r = libusb_get_device_descriptor(dev, &desc);
        if(r < 0)
        {
            g_warning("Failed to get USB device descriptor!");

            continue;
        }

        for(uc=0;uc < sizeof(g_pcat_modem_manager_supported_dev_list) /
            sizeof(PCatModemManagerUSBData);uc++)
        {
            usb_data = &(g_pcat_modem_manager_supported_dev_list[uc]);

            if(usb_data->id_vendor==desc.idVendor &&
               (usb_data->id_product==0 ||
                usb_data->id_product==desc.idProduct))
            {
                detected = TRUE;
                device_type = usb_data->device_type;

                break;
            }
        }

        if(!detected)
        {
            continue;
        }

        switch(usb_data->device_type)
        {
            case PCAT_MODEM_MANAGER_DEVICE_5G:
            {
                break;
            }
            case PCAT_MODEM_MANAGER_DEVICE_GENERAL:
            {
                break;
            }
            default:
            {
                break;
            }
        }
        if(usb_data->external_control_exec!=NULL)
        {
            if(mm_data->system_first_run)
            {
                g_spawn_command_line_async("ModemManagerSwitch.sh disable",
                    NULL);
                mm_data->system_first_run = FALSE;
            }
            pcat_modem_manager_run_external_exec(mm_data, usb_data);
        }
        else
        {
            if(mm_data->system_first_run)
            {
                g_spawn_command_line_async("ModemManagerSwitch.sh enable",
                    NULL);
                mm_data->system_first_run = FALSE;
            }
        }

        modem_exist = TRUE;
        mm_data->modem_power_usage = usb_data->power_usage;
    }

    libusb_free_device_list(devs, 1);

    mm_data->device_type = device_type;
    mm_data->modem_exist = modem_exist;

    return modem_exist;
}

static gpointer pcat_modem_manager_modem_work_thread_func(
    gpointer user_data)
{
    PCatModemManagerData *mm_data = (PCatModemManagerData *)user_data;
    guint i;

    while(mm_data->work_flag)
    {
        switch(mm_data->state)
        {
            case PCAT_MODEM_MANAGER_STATE_NONE:
            {
                mm_data->state = PCAT_MODEM_MANAGER_STATE_READY;

                break;
            }

            case PCAT_MODEM_MANAGER_STATE_READY:
            {
                if(!mm_data->modem_rfkill_state &&
                    mm_data->modem_iface_enabled)
                {
                    mm_data->modem_first_run = TRUE;
                    mm_data->modem_5g_connection_timestamp =
                        g_get_monotonic_time();
                    mm_data->state = PCAT_MODEM_MANAGER_STATE_RUN;
                }

                if(mm_data->modem_rfkill_state ||
                    !mm_data->modem_iface_enabled)
                {
                    pcat_modem_manager_external_control_terminate(mm_data);

                    for(i=0;i<10 && mm_data->work_flag;i++)
                    {
                        g_usleep(100000);
                    }
                }

                break;
            }

            case PCAT_MODEM_MANAGER_STATE_RUN:
            {
                if(pcat_main_is_running_on_distro())
                {
                    g_usleep(1000000);
                    break;
                }

                if(mm_data->modem_iface_enabled)
                {
                    pcat_modem_manager_scan_usb_devs(mm_data);
                }
                else
                {
                    mm_data->state = PCAT_MODEM_MANAGER_STATE_READY;
                }

                if(!mm_data->work_flag)
                {
                    break;
                }

                g_usleep(1000000);

                break;
            }

            default:
            {
                break;
            }
        }
    }

    pcat_modem_manager_external_control_terminate(mm_data);

    return NULL;
}

static gboolean pcat_modem_scan_timeout_func(gpointer user_data)
{
    PCatModemManagerData *mm_data = (PCatModemManagerData *)user_data;
    const PCatManagerUserConfigData *uconfig_data;
    gint64 now;
    gint64 modem_5g_fail_timeout;

    uconfig_data = pcat_main_user_config_data_get();
    now = g_get_monotonic_time();

    if(uconfig_data->modem_5g_fail_timeout > 60)
    {
        modem_5g_fail_timeout = (gint64)uconfig_data->modem_5g_fail_timeout *
            1e6;
    }
    else
    {
        modem_5g_fail_timeout = (gint64)600 * 1e6;
    }

    if(!uconfig_data->modem_disable_5g_fail_auto_reset)
    {
        if(mm_data->modem_mode==PCAT_MODEM_MANAGER_MODE_5G)
        {
            mm_data->modem_5g_connection_timestamp = now;
        }
        else
        {
            if(mm_data->modem_have_5g_connected &&
                !mm_data->modem_rfkill_state)
            {
                if(now > mm_data->modem_5g_connection_timestamp +
                    modem_5g_fail_timeout)
                {
                    mm_data->modem_5g_connection_timestamp = now;
                    mm_data->modem_have_5g_connected = FALSE;

                    pcat_modem_manager_device_rfkill_mode_set(TRUE);
                    g_usleep(500000);
                    pcat_modem_manager_device_rfkill_mode_set(FALSE);
                }
            }
        }
    }

    return TRUE;
}

static gboolean pcat_modem_manager_delayed_modem_unblock_func(
    gpointer user_data)
{
    gchar *command[] = {"/usr/sbin/rfkill", "unblock", "wwan", NULL};

    g_spawn_async(NULL, command, NULL, G_SPAWN_DEFAULT, NULL, NULL,
        NULL, NULL);

    return FALSE;
}

gboolean pcat_modem_manager_init()
{
    int errcode;
    PCatManagerMainConfigData *main_config_data;
    gchar *command[] = {"/usr/sbin/rfkill", "block", "wwan", NULL};

    if(g_pcat_modem_manager_data.initialized)
    {
        g_message("Modem Manager is already initialized!");

        return TRUE;
    }

    main_config_data = pcat_main_config_data_get();

    g_pcat_modem_manager_data.work_flag = TRUE;
    g_mutex_init(&(g_pcat_modem_manager_data.mutex));

    g_pcat_modem_manager_data.modem_exist = FALSE;
    g_pcat_modem_manager_data.system_first_run = TRUE;
    g_pcat_modem_manager_data.modem_iface_enabled = TRUE;
    g_pcat_modem_manager_data.modem_mode_table = g_hash_table_new_full(
        g_str_hash, g_str_equal, NULL, NULL);
    g_hash_table_insert(g_pcat_modem_manager_data.modem_mode_table,
        "NR5G-SA", GUINT_TO_POINTER(PCAT_MODEM_MANAGER_MODE_5G));
    g_hash_table_insert(g_pcat_modem_manager_data.modem_mode_table,
        "NR5G-NSA", GUINT_TO_POINTER(PCAT_MODEM_MANAGER_MODE_5G));
    g_hash_table_insert(g_pcat_modem_manager_data.modem_mode_table,
        "LTE", GUINT_TO_POINTER(PCAT_MODEM_MANAGER_MODE_LTE));
    g_hash_table_insert(g_pcat_modem_manager_data.modem_mode_table,
        "WCDMA", GUINT_TO_POINTER(PCAT_MODEM_MANAGER_MODE_3G));
    g_hash_table_insert(g_pcat_modem_manager_data.modem_mode_table,
        "TDSCDMA", GUINT_TO_POINTER(PCAT_MODEM_MANAGER_MODE_3G));
    g_hash_table_insert(g_pcat_modem_manager_data.modem_mode_table,
        "GSM", GUINT_TO_POINTER(PCAT_MODEM_MANAGER_MODE_2G));
    g_hash_table_insert(g_pcat_modem_manager_data.modem_mode_table,
        "HDR", GUINT_TO_POINTER(PCAT_MODEM_MANAGER_MODE_2G));
    g_hash_table_insert(g_pcat_modem_manager_data.modem_mode_table,
        "CDMA", GUINT_TO_POINTER(PCAT_MODEM_MANAGER_MODE_2G));

    if(main_config_data->debug_modem_external_exec_stdout_log)
    {
        g_pcat_modem_manager_data.external_control_exec_stdout_log_file =
            fopen("/tmp/pcat-modem-external-exec-stdout.log", "w+");
    }

    errcode = libusb_init(&g_pcat_modem_manager_data.usb_ctx);
    if(errcode!=0)
    {
        g_warning("Failed to initialize libusb: %s, 5G modem may not work!",
            libusb_strerror(errcode));
    }

    g_pcat_modem_manager_data.external_control_exec_stdout_buffer =
        g_string_new(NULL);

    g_pcat_modem_manager_data.modem_work_thread = g_thread_new(
        "pcat-modem-manager-work-thread",
        pcat_modem_manager_modem_work_thread_func,
        &g_pcat_modem_manager_data);

    g_spawn_async(NULL, command, NULL, G_SPAWN_DEFAULT,
        NULL, NULL, NULL, NULL);

    g_pcat_modem_manager_data.scanning_timeout_id = g_timeout_add_seconds(5,
        pcat_modem_scan_timeout_func, &g_pcat_modem_manager_data);

    g_timeout_add_seconds(5, pcat_modem_manager_delayed_modem_unblock_func,
        &g_pcat_modem_manager_data);

    g_pcat_modem_manager_data.initialized = TRUE;

    return TRUE;
}

void pcat_modem_manager_uninit()
{
    if(!g_pcat_modem_manager_data.initialized)
    {
        return;
    }

    if(g_pcat_modem_manager_data.scanning_timeout_id > 0)
    {
        g_source_remove(g_pcat_modem_manager_data.scanning_timeout_id);
        g_pcat_modem_manager_data.scanning_timeout_id = 0;
    }

    g_pcat_modem_manager_data.work_flag = FALSE;

    if(g_pcat_modem_manager_data.modem_work_thread!=NULL)
    {
        g_thread_join(g_pcat_modem_manager_data.modem_work_thread);
        g_pcat_modem_manager_data.modem_work_thread = NULL;
    }

    g_mutex_clear(&(g_pcat_modem_manager_data.mutex));

    if(g_pcat_modem_manager_data.usb_ctx!=NULL)
    {
        libusb_exit(g_pcat_modem_manager_data.usb_ctx);
        g_pcat_modem_manager_data.usb_ctx = NULL;
    }

    if(g_pcat_modem_manager_data.external_control_exec_stdout_buffer!=NULL)
    {
        g_string_free(
            g_pcat_modem_manager_data.external_control_exec_stdout_buffer,
            TRUE);
        g_pcat_modem_manager_data.external_control_exec_stdout_buffer = NULL;
    }

    if(g_pcat_modem_manager_data.external_control_exec_stdout_log_file!=NULL)
    {
        fclose(
            g_pcat_modem_manager_data.external_control_exec_stdout_log_file);
        g_pcat_modem_manager_data.external_control_exec_stdout_log_file =
            NULL;
    }

    g_pcat_modem_manager_data.initialized = FALSE;
}

gboolean pcat_modem_manager_status_get(PCatModemManagerMode *mode,
    PCatModemManagerSIMState *sim_state, gboolean *rfkill_state,
    gint *signal_strength, gchar **isp_name, gchar **isp_plmn)
{
    if(!g_pcat_modem_manager_data.initialized)
    {
        return FALSE;
    }

    if(mode!=NULL)
    {
        *mode = g_pcat_modem_manager_data.modem_mode;
    }
    if(sim_state!=NULL)
    {
        *sim_state = g_pcat_modem_manager_data.sim_state;
    }
    if(rfkill_state!=NULL)
    {
        *rfkill_state = g_pcat_modem_manager_data.modem_rfkill_state;
    }
    if(signal_strength!=NULL)
    {
        *signal_strength = g_pcat_modem_manager_data.modem_signal_strength;
    }
    if(isp_name!=NULL)
    {
        if(g_pcat_modem_manager_data.isp_name != NULL)
        {
            *isp_name = g_strdup(g_pcat_modem_manager_data.isp_name);
        }
        else if(g_pcat_modem_manager_data.isp_plmn != NULL)
        {
            *isp_name = g_strdup(g_pcat_modem_manager_data.isp_plmn);
        }
        else
        {
            *isp_name = g_strdup("Unknown");
        }
    }
    if(isp_plmn!=NULL)
    {
        *isp_plmn = g_strdup(g_pcat_modem_manager_data.isp_plmn);
    }

    return TRUE;
}

PCatModemManagerDeviceType pcat_modem_manager_device_type_get()
{
    return g_pcat_modem_manager_data.device_type;
}

void pcat_modem_manager_device_rfkill_mode_set(gboolean state)
{
    gchar *command[] = {"/usr/sbin/rfkill", "unblock", "wwan", NULL};

    if(!!g_pcat_modem_manager_data.modem_rfkill_state==!!state)
    {
        return;
    }

    g_pcat_modem_manager_data.modem_rfkill_state = state;

    if(state)
    {
        command[1] = "block";
    }
    g_spawn_async(NULL, command, NULL, G_SPAWN_DEFAULT,
        NULL, NULL, NULL, NULL);

    if(state)
    {
        if(g_pcat_modem_manager_data.state >= PCAT_MODEM_MANAGER_STATE_RUN)
        {
            g_pcat_modem_manager_data.state = PCAT_MODEM_MANAGER_STATE_READY;
        }
    }
}

guint pcat_modem_manager_device_power_usage_get()
{
    return g_pcat_modem_manager_data.modem_power_usage;
}

void pcat_modem_manager_iface_state_set(gboolean enabled)
{
    g_pcat_modem_manager_data.modem_iface_enabled = enabled;
}

gboolean pcat_modem_manager_iface_state_get()
{
    return g_pcat_modem_manager_data.modem_iface_enabled;
}
