#include <string.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <gio/gunixsocketaddress.h>
#include <json.h>
#include "controller.h"
#include "pmu-manager.h"
#include "modem-manager.h"
#include "common.h"

#define PCAT_CONTROLLER_SOCKET_FILE "/tmp/pcat-manager.sock"

typedef struct _PCatControllerConnectionData
{
    GSocketConnection *connection;
    GInputStream *input_stream;
    GOutputStream *output_stream;
    GSource *input_stream_source;
    GSource *output_stream_source;
    GByteArray *input_buffer;
    GByteArray *output_buffer;
}PCatControllerConnectionData;

typedef struct _PCatControllerData
{
    gboolean initialized;
    GSocketService *control_socket_service;
    GHashTable *control_connection_table;
    guint connection_check_timeout_id;
    GHashTable *command_table;
}PCatControllerData;

typedef void (*PCatControllerCommandCallback)(PCatControllerData *ctrl_data,
    PCatControllerConnectionData *connection_data, const gchar *command,
    struct json_object *root);

typedef struct _PCatControllerCommandData
{
    const gchar *command;
    PCatControllerCommandCallback callback;
}PCatControllerCommandData;

static PCatControllerData g_pcat_controller_data = {0};

static void pcat_controller_connection_data_free(
    PCatControllerConnectionData *data)
{
    if(data==NULL)
    {
        return;
    }

    if(data->output_stream_source!=NULL)
    {
        g_source_destroy(data->output_stream_source);
        g_source_unref(data->output_stream_source);
    }
    if(data->input_stream_source!=NULL)
    {
        g_source_destroy(data->input_stream_source);
        g_source_unref(data->input_stream_source);
    }

    if(data->output_buffer!=NULL)
    {
        g_byte_array_unref(data->output_buffer);
    }
    if(data->input_buffer!=NULL)
    {
        g_byte_array_unref(data->input_buffer);
    }

    if(data->connection!=NULL)
    {
        g_object_unref(data->connection);
    }

    g_free(data);
}

static gboolean pcat_controller_unix_socket_output_watch_func(
    GObject *stream, gpointer user_data)
{
    PCatControllerData *ctrl_data = &g_pcat_controller_data;
    PCatControllerConnectionData *connection_data =
        (PCatControllerConnectionData *)user_data;
    gssize wsize = 0;
    gsize total_write_size = 0, remaining_size;
    GError *error = NULL;
    gboolean ret = FALSE;
    gboolean need_close = FALSE;

    do
    {
        if(total_write_size >= connection_data->output_buffer->len)
        {
            break;
        }

        remaining_size = connection_data->output_buffer->len -
            total_write_size;

        wsize = g_pollable_output_stream_write_nonblocking(
            G_POLLABLE_OUTPUT_STREAM(stream),
            connection_data->output_buffer->data + total_write_size,
            remaining_size > 4096 ? 4096 : remaining_size, NULL, &error);
        if(wsize > 0)
        {
            total_write_size += wsize;
        }
    }
    while(wsize > 0);

    if(total_write_size > 0)
    {
        g_byte_array_remove_range(connection_data->output_buffer, 0,
            total_write_size);
    }

    if(error!=NULL)
    {
        if(g_error_matches(error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
        {
            ret = TRUE;
        }
        else if(g_error_matches(error, G_IO_ERROR,
            G_IO_ERROR_CONNECTION_CLOSED))
        {
            ret = FALSE;
            need_close = TRUE;

            g_message("A Unix socket connection closed.");
        }
        else
        {
            ret = FALSE;
            need_close = TRUE;

            g_warning("A Unix socket connection broke with error %s!",
                error->message);
        }

        g_clear_error(&error);
    }
    else if(wsize==0)
    {
        ret = FALSE;
        need_close = TRUE;

        g_message("A Unix socket connection closed.");
    }

    if(need_close)
    {
        g_hash_table_remove(ctrl_data->control_connection_table,
            connection_data->connection);
    }
    else if(!ret)
    {
        g_source_destroy(connection_data->output_stream_source);
        g_source_unref(connection_data->output_stream_source);
        connection_data->output_stream_source = NULL;
    }

    return ret;
}

static void pcat_controller_unix_socket_output_json_push(
    PCatControllerData *ctrl_data,
    PCatControllerConnectionData *connection_data, struct json_object *root)
{
    GHashTableIter iter;
    const gchar *json_data;

    if(ctrl_data==NULL || root==NULL)
    {
        return;
    }

    json_data = json_object_to_json_string(root);
    if(json_data==NULL)
    {
        return;
    }

    if(connection_data!=NULL)
    {
        if(connection_data->output_buffer->len > 2097152)
        {
            connection_data->output_buffer->len = 0;
        }

        g_byte_array_append(connection_data->output_buffer,
            (const guint8 *)json_data, strlen(json_data)+1);

        if(connection_data->output_stream_source==NULL)
        {
            connection_data->output_stream_source =
                g_pollable_output_stream_create_source(
                G_POLLABLE_OUTPUT_STREAM(connection_data->output_stream),
                NULL);
            g_source_set_callback(connection_data->output_stream_source,
                (GSourceFunc)pcat_controller_unix_socket_output_watch_func,
                connection_data, NULL);
            g_source_attach(connection_data->output_stream_source, NULL);
        }
    }
    else
    {
        g_hash_table_iter_init(&iter, ctrl_data->control_connection_table);
        while(g_hash_table_iter_next(&iter, NULL,
            (gpointer *)&connection_data))
        {
            g_byte_array_append(connection_data->output_buffer,
                (const guint8 *)json_data, strlen(json_data)+1);

            if(connection_data->output_stream_source==NULL)
            {
                connection_data->output_stream_source =
                    g_pollable_output_stream_create_source(
                    G_POLLABLE_OUTPUT_STREAM(connection_data->output_stream),
                    NULL);
                g_source_set_callback(connection_data->output_stream_source,
                    (GSourceFunc)
                    pcat_controller_unix_socket_output_watch_func,
                    connection_data, NULL);
                g_source_attach(connection_data->output_stream_source, NULL);
            }
        }
    }
}

static void pcat_controller_unix_socket_input_parse(
    PCatControllerData *ctrl_data,
    PCatControllerConnectionData *connection_data)
{
    gsize i;
    gsize used_size = 0;
    const gchar *start = (const gchar *)connection_data->input_buffer->data;
    struct json_tokener *tokener;
    struct json_object *root, *child;
    const gchar *command;
    PCatControllerCommandCallback callback;

    for(i=0;i<connection_data->input_buffer->len;i++)
    {
        if(connection_data->input_buffer->data[i]==0)
        {
            if(i > used_size)
            {
                tokener = json_tokener_new();
                root = json_tokener_parse_ex(tokener, start, i - used_size);
                json_tokener_free(tokener);

                if(root!=NULL)
                {
                    command = NULL;
                    if(json_object_object_get_ex(root, "command", &child))
                    {
                        command = json_object_get_string(child);
                    }
                    if(command!=NULL)
                    {
                        callback = g_hash_table_lookup(
                            ctrl_data->command_table, command);
                        if(callback!=NULL)
                        {
                            callback(ctrl_data, connection_data, command,
                                root);
                        }

                        g_debug("Controller got command %s.", command);
                    }

                    json_object_put(root);
                }
            }

            used_size = i + 1;
            start = (const gchar *)connection_data->input_buffer->data +
                i + 1;
        }
    }

    if(used_size > 0)
    {
        g_byte_array_remove_range(connection_data->input_buffer, 0, used_size);
    }
}

static gboolean pcat_controller_unix_socket_input_watch_func(
    GObject *stream, gpointer user_data)
{
    PCatControllerData *ctrl_data = &g_pcat_controller_data;
    PCatControllerConnectionData *connection_data =
        (PCatControllerConnectionData *)user_data;
    guint8 buffer[4096];
    gssize rsize;
    GError *error = NULL;
    gboolean ret = TRUE;

    while((rsize=g_pollable_input_stream_read_nonblocking(
        G_POLLABLE_INPUT_STREAM(stream), buffer, 4096, NULL, &error))>0)
    {
        if(connection_data->input_buffer->len > 2097152)
        {
            g_byte_array_remove_range(connection_data->input_buffer, 0,
                1048576);
        }
        g_byte_array_append(connection_data->input_buffer, buffer, rsize);

        pcat_controller_unix_socket_input_parse(ctrl_data, connection_data);
    }

    if(error!=NULL)
    {
        if(g_error_matches(error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
        {

        }
        else if(g_error_matches(error, G_IO_ERROR,
            G_IO_ERROR_CONNECTION_CLOSED))
        {
            ret = FALSE;

            g_message("A Unix socket connection closed.");
        }
        else
        {
            ret = FALSE;

            g_warning("A Unix socket connection broke with error %s!",
                error->message);
        }

        g_clear_error(&error);
    }
    else if(rsize==0)
    {
        ret = FALSE;

        g_message("A Unix socket connection closed.");
    }

    if(!ret)
    {
        g_hash_table_remove(ctrl_data->control_connection_table,
            connection_data->connection);
    }

    return ret;
}

static gboolean pcat_controller_unix_socket_incoming_func(
    GSocketService *service, GSocketConnection *connection,
    GObject *source_object, gpointer user_data)
{
    PCatControllerData *ctrl_data = (PCatControllerData *)user_data;
    PCatControllerConnectionData *connection_data;

    connection_data = g_new0(PCatControllerConnectionData, 1);
    connection_data->connection = g_object_ref(connection);
    connection_data->input_stream = g_io_stream_get_input_stream(
        G_IO_STREAM(connection_data->connection));
    connection_data->output_stream = g_io_stream_get_output_stream(
        G_IO_STREAM(connection_data->connection));
    connection_data->input_buffer = g_byte_array_new();
    connection_data->output_buffer = g_byte_array_new();

    connection_data->input_stream_source =
        g_pollable_input_stream_create_source(
        G_POLLABLE_INPUT_STREAM(connection_data->input_stream), NULL);
    g_source_set_callback(connection_data->input_stream_source,
        (GSourceFunc)pcat_controller_unix_socket_input_watch_func,
        connection_data, NULL);
    g_source_attach(connection_data->input_stream_source, NULL);

    g_hash_table_replace(ctrl_data->control_connection_table,
        connection_data->connection, connection_data);

    g_message("Controller client connected.");

    return TRUE;
}

static gboolean pcat_controller_unix_socket_connection_check_timeout_func(
    gpointer user_data)
{
    PCatControllerData *ctrl_data = (PCatControllerData *)user_data;
    PCatControllerConnectionData *connection_data;
    GHashTableIter iter;

    g_hash_table_iter_init(&iter, ctrl_data->control_connection_table);
    while(g_hash_table_iter_next(&iter, NULL, (gpointer *)&connection_data))
    {
        if(connection_data==NULL || connection_data->output_stream==NULL)
        {
            continue;
        }

        if(connection_data->output_stream_source==NULL &&
           connection_data->output_buffer->len > 0)
        {
            connection_data->output_stream_source =
                g_pollable_output_stream_create_source(
                G_POLLABLE_OUTPUT_STREAM(connection_data->output_stream),
                NULL);
            g_source_set_callback(connection_data->output_stream_source,
                (GSourceFunc)pcat_controller_unix_socket_output_watch_func,
                connection_data, NULL);
            g_source_attach(connection_data->output_stream_source, NULL);
        }
    }

    return TRUE;
}

static void pcat_controller_command_pmu_status_func(
    PCatControllerData *ctrl_data,
    PCatControllerConnectionData *connection_data,
    const gchar *command, struct json_object *root)
{
    struct json_object *rroot, *child;
    guint battery_voltage = 0, charger_voltage = 0, battery_percentage = 0;
    gint board_temp;
    gboolean on_battery = FALSE;

    rroot = json_object_new_object();

    pcat_pmu_manager_pmu_status_get(&battery_voltage, &charger_voltage,
        &on_battery, &battery_percentage);
    board_temp = pcat_pmu_manager_board_temp_get();

    child = json_object_new_string(command);
    json_object_object_add(rroot, "command", child);

    child = json_object_new_int(0);
    json_object_object_add(rroot, "code", child);

    child = json_object_new_int(battery_voltage);
    json_object_object_add(rroot, "battery-voltage", child);

    child = json_object_new_int(charger_voltage);
    json_object_object_add(rroot, "charger-voltage", child);

    child = json_object_new_int(on_battery ? 1 : 0);
    json_object_object_add(rroot, "on-battery", child);

    child = json_object_new_int(battery_percentage);
    json_object_object_add(rroot, "charge-percentage", child);

    child = json_object_new_int(board_temp);
    json_object_object_add(rroot, "board-temperature", child);

    pcat_controller_unix_socket_output_json_push(ctrl_data, connection_data,
        rroot);
    json_object_put(rroot);
}

static void pcat_controller_command_schedule_power_event_set_func(
    PCatControllerData *ctrl_data,
    PCatControllerConnectionData *connection_data,
    const gchar *command, struct json_object *root)
{
    struct json_object *rroot, *child, *array, *node;
    guint array_len;
    guint i;
    gint iv;
    PCatManagerPowerScheduleData *sdata;
    PCatManagerUserConfigData *uconfig_data;
    guint count_on = 0, count_off = 0;
    gboolean action = FALSE;
    gint y, m, d, h, min;
    GDateTime *dt1, *dt2;

    uconfig_data = pcat_main_user_config_data_get();

    if(uconfig_data->power_schedule_data!=NULL)
    {
        g_ptr_array_unref(uconfig_data->power_schedule_data);
        uconfig_data->power_schedule_data = NULL;
    }

    uconfig_data->power_schedule_data = g_ptr_array_new();
    uconfig_data->dirty = TRUE;

    if(json_object_object_get_ex(root, "event-list", &array))
    {
        array_len = json_object_array_length(array);

        if(array_len > 0)
        {
            for(i=0;i<array_len;i++)
            {
                node = json_object_array_get_idx(array, i);
                if(node==NULL)
                {
                    continue;
                }

                if(json_object_object_get_ex(node, "action", &child))
                {
                    action = (json_object_get_int(child)!=0);
                }
                if(action)
                {
                    count_on++;

                    if(count_on > 6)
                    {
                        continue;
                    }
                }
                else
                {
                    count_off++;

                    if(count_off > 6)
                    {
                        continue;
                    }
                }

                sdata = g_new0(PCatManagerPowerScheduleData, 1);
                sdata->action = action;

                if(json_object_object_get_ex(node, "enabled", &child))
                {
                    iv = json_object_get_int(child);
                    sdata->enabled = (iv!=0);
                    sdata->enable_bits = (iv!=0 ?
                        PCAT_MANAGER_POWER_SCHEDULE_ENABLE_MINUTE : 0);
                }
                if(json_object_object_get_ex(node, "enable-bits", &child))
                {
                    iv = json_object_get_int(child);
                    sdata->enable_bits |= (iv & 0xFF);
                }
                y = 2000;
                m = 1;
                d = 1;
                h = 0;
                min = 0;
                if(json_object_object_get_ex(node, "year", &child))
                {
                    y = json_object_get_int(child);
                }
                if(json_object_object_get_ex(node, "month", &child))
                {
                    m = json_object_get_int(child);
                }
                if(json_object_object_get_ex(node, "day", &child))
                {
                    d = json_object_get_int(child);
                }

                if(json_object_object_get_ex(node, "hour", &child))
                {
                    h = json_object_get_int(child);
                }
                if(json_object_object_get_ex(node, "minute", &child))
                {
                    min = json_object_get_int(child);
                }

                dt1 = g_date_time_new_local(y, m, d, h, min, 0);
                dt2 = NULL;
                if(dt1!=NULL)
                {
                    dt2 = g_date_time_to_utc(dt1);
                    g_date_time_unref(dt1);
                }
                if(dt2!=NULL)
                {
                    sdata->year = g_date_time_get_year(dt2);
                    sdata->month = g_date_time_get_month(dt2);
                    sdata->day = g_date_time_get_day_of_month(dt2);
                    sdata->hour = g_date_time_get_hour(dt2);
                    sdata->minute = g_date_time_get_minute(dt2);

                    g_date_time_unref(dt2);
                }
                else
                {
                    sdata->year = 2000;
                    sdata->month = 1;
                    sdata->day = 1;
                    sdata->hour = 0;
                    sdata->minute = 0;
                }

                if(json_object_object_get_ex(node, "dow-bits", &child))
                {
                    sdata->dow_bits = json_object_get_int(child) & 0xFF;
                }

                g_ptr_array_add(uconfig_data->power_schedule_data, sdata);
            }
        }
    }
    pcat_main_user_config_data_sync();

    rroot = json_object_new_object();

    child = json_object_new_string(command);
    json_object_object_add(rroot, "command", child);

    child = json_object_new_int(0);
    json_object_object_add(rroot, "code", child);

    pcat_controller_unix_socket_output_json_push(ctrl_data, connection_data,
        rroot);
    json_object_put(rroot);

    pcat_pmu_manager_schedule_time_update();
}

static void pcat_controller_command_schedule_power_event_get_func(
    PCatControllerData *ctrl_data,
    PCatControllerConnectionData *connection_data,
    const gchar *command, struct json_object *root)
{
    struct json_object *rroot, *child, *array, *node;
    guint i;
    PCatManagerPowerScheduleData *sdata;
    const PCatManagerUserConfigData *uconfig_data;
    GDateTime *dt1, *dt2;

    uconfig_data = pcat_main_user_config_data_get();

    rroot = json_object_new_object();

    child = json_object_new_string(command);
    json_object_object_add(rroot, "command", child);

    child = json_object_new_int(0);
    json_object_object_add(rroot, "code", child);

    array = json_object_new_array();

    if(uconfig_data->power_schedule_data!=NULL)
    {
        for(i=0;i<uconfig_data->power_schedule_data->len;i++)
        {
            sdata = g_ptr_array_index(uconfig_data->power_schedule_data, i);
            node = json_object_new_object();

            child = json_object_new_int(sdata->enabled ? 1 : 0);
            json_object_object_add(node, "enabled", child);

            child = json_object_new_int(sdata->enable_bits);
            json_object_object_add(node, "enable-bits", child);

            child = json_object_new_int(sdata->action ? 1 : 0);
            json_object_object_add(node, "action", child);

            dt1 = g_date_time_new_utc(sdata->year, sdata->month,
                sdata->day, sdata->hour, sdata->minute, 0);
            dt2 = NULL;
            if(dt1!=NULL)
            {
                dt2 = g_date_time_to_local(dt1);
                g_date_time_unref(dt1);
            }

            if(dt2!=NULL)
            {
                child = json_object_new_int(g_date_time_get_year(dt2));
                json_object_object_add(node, "year", child);

                child = json_object_new_int(g_date_time_get_month(dt2));
                json_object_object_add(node, "month", child);

                child = json_object_new_int(g_date_time_get_day_of_month(dt2));
                json_object_object_add(node, "day", child);

                child = json_object_new_int(g_date_time_get_hour(dt2));
                json_object_object_add(node, "hour", child);

                child = json_object_new_int(g_date_time_get_minute(dt2));
                json_object_object_add(node, "minute", child);

                g_date_time_unref(dt2);
            }
            else
            {
                child = json_object_new_int(2000);
                json_object_object_add(node, "year", child);

                child = json_object_new_int(1);
                json_object_object_add(node, "month", child);

                child = json_object_new_int(1);
                json_object_object_add(node, "day", child);

                child = json_object_new_int(0);
                json_object_object_add(node, "hour", child);

                child = json_object_new_int(0);
                json_object_object_add(node, "minute", child);
            }

            child = json_object_new_int(sdata->dow_bits);
            json_object_object_add(node, "dow-bits", child);

            json_object_array_add(array, node);
        }
    }

    json_object_object_add(rroot, "event-list", array);

    pcat_controller_unix_socket_output_json_push(ctrl_data, connection_data,
        rroot);
    json_object_put(rroot);
}

static void pcat_controller_command_modem_status_get_func(
    PCatControllerData *ctrl_data,
    PCatControllerConnectionData *connection_data,
    const gchar *command, struct json_object *root)
{
    struct json_object *rroot, *child;
    PCatModemManagerMode mode = PCAT_MODEM_MANAGER_MODE_NONE;
    PCatModemManagerSIMState sim_state = PCAT_MODEM_MANAGER_SIM_STATE_ABSENT;
    gint signal_strength = 0;
    gchar *isp_name = NULL;
    gchar *isp_plmn = NULL;
    gint code = 0;
    const gchar *mode_str = "none", *sim_state_str = "absent";
    gboolean rfkill_state = FALSE;
    gboolean iface_enabled;

    rroot = json_object_new_object();
    child = json_object_new_string(command);
    json_object_object_add(rroot, "command", child);

    if(!pcat_modem_manager_status_get(&mode, &sim_state, &rfkill_state,
        &signal_strength, &isp_name, &isp_plmn))
    {
        code = 1;
    }

    child = json_object_new_int(code);
    json_object_object_add(rroot, "code", child);

    switch(mode)
    {
        case PCAT_MODEM_MANAGER_MODE_2G:
        {
            mode_str = "2g";
            break;
        }
        case PCAT_MODEM_MANAGER_MODE_3G:
        {
            mode_str = "3g";
            break;
        }
        case PCAT_MODEM_MANAGER_MODE_LTE:
        {
            mode_str = "lte";
            break;
        }
        case PCAT_MODEM_MANAGER_MODE_5G:
        {
            mode_str = "5g";
            break;
        }
        default:
        {
            break;
        }
    }

    iface_enabled = pcat_modem_manager_iface_state_get();

    if(iface_enabled)
    {
        switch(sim_state)
        {
            case PCAT_MODEM_MANAGER_SIM_STATE_ABSENT:
            {
                sim_state_str = "absent";
                break;
            }
            case PCAT_MODEM_MANAGER_SIM_STATE_NOT_READY:
            {
                sim_state_str = "not-ready";
                break;
            }
            case PCAT_MODEM_MANAGER_SIM_STATE_READY:
            {
                sim_state_str = "ready";
                break;
            }
            case PCAT_MODEM_MANAGER_SIM_STATE_PIN:
            {
                sim_state_str = "need-pin";
                break;
            }
            case PCAT_MODEM_MANAGER_SIM_STATE_PUK:
            {
                sim_state_str = "need-puk";
                break;
            }
            case PCAT_MODEM_MANAGER_SIM_STATE_NETWORK_PERSONALIZATION:
            {
                sim_state_str = "personalized-network";
                break;
            }
            case PCAT_MODEM_MANAGER_SIM_STATE_BAD:
            {
                sim_state_str = "bad";
                break;
            }
            default:
            {
                break;
            }
        }
    }
    else
    {
        sim_state_str = "unknown";
        signal_strength = -1;
    }

    child = json_object_new_string(mode_str);
    json_object_object_add(rroot, "mode", child);

    child = json_object_new_int(iface_enabled ? 1 : 0);
    json_object_object_add(rroot, "interface-enabled", child);

    child = json_object_new_int(rfkill_state ? 1 : 0);
    json_object_object_add(rroot, "rfkill-state", child);

    child = json_object_new_string(sim_state_str);
    json_object_object_add(rroot, "sim-state", child);

    child = json_object_new_string(isp_name!=NULL ? isp_name : "");
    json_object_object_add(rroot, "isp-name", child);

    child = json_object_new_string(isp_plmn!=NULL ? isp_plmn : "");
    json_object_object_add(rroot, "isp-lpmn", child);
    
    child = json_object_new_int(signal_strength);
    json_object_object_add(rroot, "signal-strength", child);

    g_free(isp_name);
    g_free(isp_plmn);

    pcat_controller_unix_socket_output_json_push(ctrl_data, connection_data,
        rroot);
    json_object_put(rroot);
}

static void pcat_controller_command_network_route_mode_get_func(
    PCatControllerData *ctrl_data,
    PCatControllerConnectionData *connection_data,
    const gchar *command, struct json_object *root)
{
    struct json_object *rroot, *child;
    PCatManagerRouteMode mode;
    const gchar *mode_str = "none";

    rroot = json_object_new_object();

    mode = pcat_main_network_route_mode_get();

    switch(mode)
    {
        case PCAT_MANAGER_ROUTE_MODE_WIRED:
        {
            mode_str = "wired";
            break;
        }
        case PCAT_MANAGER_ROUTE_MODE_MOBILE:
        {
            mode_str = "mobile";
            break;
        }
        case PCAT_MANAGER_ROUTE_MODE_UNKNOWN:
        {
            mode_str = "unknown";
            break;
        }
        default:
        {
            break;
        }
    }

    child = json_object_new_string(command);
    json_object_object_add(rroot, "command", child);

    child = json_object_new_int(0);
    json_object_object_add(rroot, "code", child);

    child = json_object_new_string(mode_str);
    json_object_object_add(rroot, "mode", child);

    pcat_controller_unix_socket_output_json_push(ctrl_data, connection_data,
        rroot);
    json_object_put(rroot);
}

static void pcat_controller_command_charger_on_auto_start_set_func(
    PCatControllerData *ctrl_data,
    PCatControllerConnectionData *connection_data,
    const gchar *command, struct json_object *root)
{
    struct json_object *rroot, *child;
    PCatManagerUserConfigData *uconfig_data;

    uconfig_data = pcat_main_user_config_data_get();

    if(json_object_object_get_ex(root, "state", &child))
    {
        uconfig_data->charger_on_auto_start = (json_object_get_int(child)!=0);
        uconfig_data->dirty = TRUE;
    }

    if(json_object_object_get_ex(root, "timeout", &child))
    {
        uconfig_data->charger_on_auto_start_timeout =
            json_object_get_int(child);
        uconfig_data->dirty = TRUE;
    }

    rroot = json_object_new_object();

    child = json_object_new_string(command);
    json_object_object_add(rroot, "command", child);

    child = json_object_new_int(0);
    json_object_object_add(rroot, "code", child);

    pcat_controller_unix_socket_output_json_push(ctrl_data, connection_data,
        rroot);
    json_object_put(rroot);

    pcat_pmu_manager_charger_on_auto_start(
        uconfig_data->charger_on_auto_start);
    pcat_main_user_config_data_sync();
}

static void pcat_controller_command_charger_on_auto_start_get_func(
    PCatControllerData *ctrl_data,
    PCatControllerConnectionData *connection_data,
    const gchar *command, struct json_object *root)
{
    struct json_object *rroot, *child;
    const PCatManagerUserConfigData *uconfig_data;
    gint64 countdown;

    uconfig_data = pcat_main_user_config_data_get();

    rroot = json_object_new_object();

    child = json_object_new_string(command);
    json_object_object_add(rroot, "command", child);

    child = json_object_new_int(0);
    json_object_object_add(rroot, "code", child);

    child = json_object_new_int(uconfig_data->charger_on_auto_start ? 1 : 0);
    json_object_object_add(rroot, "state", child);

    child = json_object_new_int(uconfig_data->charger_on_auto_start_timeout);
    json_object_object_add(rroot, "timeout", child);

    countdown = (g_get_monotonic_time() -
        pcat_pmu_manager_charger_on_auto_start_last_timestamp_get()) /
        1000000L;
    countdown = uconfig_data->charger_on_auto_start_timeout - countdown;

    child = json_object_new_int(countdown);
    json_object_object_add(rroot, "countdown", child);

    pcat_controller_unix_socket_output_json_push(ctrl_data, connection_data,
        rroot);
    json_object_put(rroot);
}

static void pcat_controller_command_pmu_fw_version_get_func(
    PCatControllerData *ctrl_data,
    PCatControllerConnectionData *connection_data,
    const gchar *command, struct json_object *root)
{
    struct json_object *rroot, *child;
    const gchar *version_str;

    rroot = json_object_new_object();

    child = json_object_new_string(command);
    json_object_object_add(rroot, "command", child);

    child = json_object_new_int(0);
    json_object_object_add(rroot, "code", child);

    version_str = pcat_pmu_manager_pmu_fw_version_get();

    child = json_object_new_string(version_str!=NULL ? version_str : "");
    json_object_object_add(rroot, "version", child);

    pcat_controller_unix_socket_output_json_push(ctrl_data, connection_data,
        rroot);
    json_object_put(rroot);
}

static void pcat_controller_command_modem_rfkill_mode_set_func(
    PCatControllerData *ctrl_data,
    PCatControllerConnectionData *connection_data,
    const gchar *command, struct json_object *root)
{
    struct json_object *rroot, *child;
    gboolean state = FALSE;

    rroot = json_object_new_object();

    child = json_object_new_string(command);
    json_object_object_add(rroot, "command", child);

    child = json_object_new_int(0);
    json_object_object_add(rroot, "code", child);

    if(json_object_object_get_ex(root, "state", &child))
    {
        state = (json_object_get_int(child)!=0);
    }

    pcat_modem_manager_device_rfkill_mode_set(state);

    pcat_controller_unix_socket_output_json_push(ctrl_data, connection_data,
        rroot);
    json_object_put(rroot);
}

static void pcat_controller_command_modem_network_setup_func(
    PCatControllerData *ctrl_data,
    PCatControllerConnectionData *connection_data,
    const gchar *command, struct json_object *root)
{
    struct json_object *rroot, *child;
    const gchar *apn_str = NULL;
    const gchar *user_str = NULL;
    const gchar *password_str = NULL;
    const gchar *auth_str = NULL;
    PCatManagerUserConfigData *uconfig_data;

    rroot = json_object_new_object();

    child = json_object_new_string(command);
    json_object_object_add(rroot, "command", child);

    child = json_object_new_int(0);
    json_object_object_add(rroot, "code", child);

    uconfig_data = pcat_main_user_config_data_get();

    if(json_object_object_get_ex(root, "apn", &child))
    {
        apn_str = json_object_get_string(child);
        if(apn_str!=NULL && *apn_str=='\0')
        {
            apn_str = NULL;
        }

        g_free(uconfig_data->modem_dial_apn);
        uconfig_data->modem_dial_apn = g_strdup(apn_str);

        uconfig_data->dirty = TRUE;
    }

    if(json_object_object_get_ex(root, "user", &child))
    {
        user_str = json_object_get_string(child);
        if(user_str!=NULL && *user_str=='\0')
        {
            user_str = NULL;
        }

        g_free(uconfig_data->modem_dial_user);
        uconfig_data->modem_dial_user = g_strdup(user_str);

        uconfig_data->dirty = TRUE;
    }
    if(json_object_object_get_ex(root, "password", &child))
    {
        password_str = json_object_get_string(child);
        if(password_str!=NULL && *password_str=='\0')
        {
            password_str = NULL;
        }

        g_free(uconfig_data->modem_dial_password);
        uconfig_data->modem_dial_password = g_strdup(password_str);

        uconfig_data->dirty = TRUE;
    }
    if(json_object_object_get_ex(root, "auth", &child))
    {
        auth_str = json_object_get_string(child);
        if(auth_str!=NULL && *auth_str=='\0')
        {
            auth_str = NULL;
        }

        g_free(uconfig_data->modem_dial_auth);
        uconfig_data->modem_dial_auth = g_strdup(auth_str);

        uconfig_data->dirty = TRUE;
    }

    if(json_object_object_get_ex(root, "disable-connection-5g-fail-auto-reset",
        &child))
    {
        uconfig_data->modem_disable_5g_fail_auto_reset =
            (json_object_get_int(child)!=0);

        uconfig_data->dirty = TRUE;
    }
    if(json_object_object_get_ex(root, "modem-iface-auto-stop-if-wired",
        &child))
    {
        uconfig_data->modem_iface_auto_stop = (json_object_get_int(child)!=0);

        uconfig_data->dirty = TRUE;
    }

    pcat_main_user_config_data_sync();

    pcat_controller_unix_socket_output_json_push(ctrl_data, connection_data,
        rroot);
    json_object_put(rroot);
}

static void pcat_controller_command_modem_network_get_func(
    PCatControllerData *ctrl_data,
    PCatControllerConnectionData *connection_data,
    const gchar *command, struct json_object *root)
{
    struct json_object *rroot, *child;
    const PCatManagerUserConfigData *uconfig_data;
    PCatModemManagerDeviceType device_type;
    const gchar *device_type_str = "none";

    rroot = json_object_new_object();

    child = json_object_new_string(command);
    json_object_object_add(rroot, "command", child);

    child = json_object_new_int(0);
    json_object_object_add(rroot, "code", child);

    uconfig_data = pcat_main_user_config_data_get();

    device_type = pcat_modem_manager_device_type_get();
    switch(device_type)
    {
        case PCAT_MODEM_MANAGER_DEVICE_5G:
        {
            device_type_str = "5g";
            break;
        }
        case PCAT_MODEM_MANAGER_DEVICE_GENERAL:
        {
            device_type_str = "lte";
            break;
        }
        default:
        {
            break;
        }
    }

    child = json_object_new_string(device_type_str);
    json_object_object_add(rroot, "device-type", child);

    child = json_object_new_string(uconfig_data->modem_dial_apn!=NULL ?
        uconfig_data->modem_dial_apn : "");
    json_object_object_add(rroot, "apn", child);

    child = json_object_new_string(uconfig_data->modem_dial_user!=NULL ?
        uconfig_data->modem_dial_user : "");
    json_object_object_add(rroot, "user", child);

    child = json_object_new_string(uconfig_data->modem_dial_password!=NULL ?
        uconfig_data->modem_dial_password : "");
    json_object_object_add(rroot, "password", child);

    child = json_object_new_string(uconfig_data->modem_dial_auth!=NULL ?
        uconfig_data->modem_dial_auth : "");
    json_object_object_add(rroot, "auth", child);

    child = json_object_new_int(uconfig_data->modem_disable_5g_fail_auto_reset
        ? 1 : 0);
    json_object_object_add(rroot, "disable-connection-5g-fail-auto-reset",
        child);

    child = json_object_new_int(uconfig_data->modem_iface_auto_stop ? 1 : 0);
    json_object_object_add(rroot, "modem-iface-auto-stop-if-wired", child);

    pcat_controller_unix_socket_output_json_push(ctrl_data, connection_data,
        rroot);
    json_object_put(rroot);
}

static void pcat_controller_command_pmu_io_set_func(
    PCatControllerData *ctrl_data,
    PCatControllerConnectionData *connection_data,
    const gchar *command, struct json_object *root)
{
    struct json_object *rroot, *child;
    gint state;

    rroot = json_object_new_object();

    child = json_object_new_string(command);
    json_object_object_add(rroot, "command", child);

    child = json_object_new_int(0);
    json_object_object_add(rroot, "code", child);

    if(json_object_object_get_ex(root, "status-led-v2-enabled", &child))
    {
        state = json_object_get_int(child);
        pcat_pmu_manager_status_led_v2_state_set(state!=0);
    }

    if(json_object_object_get_ex(root, "beeper-enabled", &child))
    {
        state = json_object_get_int(child);
        pcat_pmu_manager_beeper_state_set(state!=0);
    }

    pcat_controller_unix_socket_output_json_push(ctrl_data, connection_data,
        rroot);
    json_object_put(rroot);
}

static void pcat_controller_command_pmu_io_get_func(
    PCatControllerData *ctrl_data,
    PCatControllerConnectionData *connection_data,
    const gchar *command, struct json_object *root)
{
    struct json_object *rroot, *child;
    gboolean state;

    rroot = json_object_new_object();

    child = json_object_new_string(command);
    json_object_object_add(rroot, "command", child);

    child = json_object_new_int(0);
    json_object_object_add(rroot, "code", child);

    state = pcat_pmu_manager_status_led_v2_state_get();
    child = json_object_new_int(state ? 1 : 0);
    json_object_object_add(rroot, "status-led-v2-enabled", child);

    state = pcat_pmu_manager_beeper_state_get();
    child = json_object_new_int(state ? 1 : 0);
    json_object_object_add(rroot, "beeper-enabled", child);

    pcat_controller_unix_socket_output_json_push(ctrl_data, connection_data,
        rroot);
    json_object_put(rroot);
}

static PCatControllerCommandData g_pcat_controller_command_list[] =
{
    {
        .command = "pmu-status",
        .callback = pcat_controller_command_pmu_status_func
    },
    {
        .command = "schedule-power-event-set",
        .callback = pcat_controller_command_schedule_power_event_set_func
    },
    {
        .command = "schedule-power-event-get",
        .callback = pcat_controller_command_schedule_power_event_get_func
    },
    {
        .command = "modem-status-get",
        .callback = pcat_controller_command_modem_status_get_func,
    },
    {
        .command = "network-route-mode-get",
        .callback = pcat_controller_command_network_route_mode_get_func,
    },
    {
        .command = "charger-on-auto-start-set",
        .callback = pcat_controller_command_charger_on_auto_start_set_func,
    },
    {
        .command = "charger-on-auto-start-get",
        .callback = pcat_controller_command_charger_on_auto_start_get_func,
    },
    {
        .command = "pmu-fw-version-get",
        .callback = pcat_controller_command_pmu_fw_version_get_func,
    },
    {
        .command = "modem-rfkill-mode-set",
        .callback = pcat_controller_command_modem_rfkill_mode_set_func,
    },
    {
        .command = "modem-network-setup",
        .callback = pcat_controller_command_modem_network_setup_func,
    },
    {
        .command = "modem-network-get",
        .callback = pcat_controller_command_modem_network_get_func,
    },
    {
        .command = "pmu-io-set",
        .callback = pcat_controller_command_pmu_io_set_func,
    },
    {
        .command = "pmu-io-get",
        .callback = pcat_controller_command_pmu_io_get_func,
    },
    { NULL, NULL }
};

static gboolean pcat_controller_unix_socket_open(
    PCatControllerData *ctrl_data)
{
    GSocketAddress *address;
    GSocketService *service;
    GError *error = NULL;

    if(ctrl_data->control_socket_service!=NULL)
    {
        return TRUE;
    }

    g_remove(PCAT_CONTROLLER_SOCKET_FILE);

    address = g_unix_socket_address_new(PCAT_CONTROLLER_SOCKET_FILE);
    if(address==NULL)
    {
        g_warning("Failed to create socket address for unix socket %s!",
            PCAT_CONTROLLER_SOCKET_FILE);

        return FALSE;
    }

    service = g_socket_service_new();
    if(service==NULL)
    {
        g_warning("Failed to create socket service for unix socket %s!",
            PCAT_CONTROLLER_SOCKET_FILE);
        g_object_unref(address);

        return FALSE;
    }

    if(!g_socket_listener_add_address(G_SOCKET_LISTENER(service),
        address, G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_DEFAULT,
        NULL, NULL, &error))
    {
        g_warning("Failed to listen to unix socket %s: %s",
            PCAT_CONTROLLER_SOCKET_FILE, error!=NULL ?
            error->message : "Unknown");

        g_clear_error(&error);
        g_object_unref(service);
        g_object_unref(address);

        return FALSE;
    }

    g_object_unref(address);

    ctrl_data->control_socket_service = service;
    ctrl_data->control_connection_table = g_hash_table_new_full(
        g_direct_hash, g_direct_equal, NULL, (GDestroyNotify)
        pcat_controller_connection_data_free);
    g_socket_service_start(ctrl_data->control_socket_service);
    g_signal_connect(service, "incoming",
        G_CALLBACK(pcat_controller_unix_socket_incoming_func), ctrl_data);

    ctrl_data->connection_check_timeout_id = g_timeout_add_seconds(
        1, pcat_controller_unix_socket_connection_check_timeout_func,
        ctrl_data);

    return TRUE;
}

static void pcat_controller_unix_socket_close(
    PCatControllerData *ctrl_data)
{
    if(ctrl_data->connection_check_timeout_id > 0)
    {
        g_source_remove(ctrl_data->connection_check_timeout_id);
        ctrl_data->connection_check_timeout_id = 0;
    }

    if(ctrl_data->control_connection_table!=NULL)
    {
        g_hash_table_unref(ctrl_data->control_connection_table);
        ctrl_data->control_connection_table = NULL;
    }

    if(ctrl_data->control_socket_service!=NULL)
    {
        g_object_unref(ctrl_data->control_socket_service);
        ctrl_data->control_socket_service = NULL;
    }

    g_remove(PCAT_CONTROLLER_SOCKET_FILE);
}

gboolean pcat_controller_init()
{
    guint i;

    if(g_pcat_controller_data.initialized)
    {
        return TRUE;
    }

    if(!pcat_controller_unix_socket_open(&g_pcat_controller_data))
    {
        g_warning("Failed to open controller socket!");

        return FALSE;
    }

    g_pcat_controller_data.command_table = g_hash_table_new_full(
        g_str_hash, g_str_equal, g_free, NULL);
    for(i=0;g_pcat_controller_command_list[i].command!=NULL;i++)
    {
        g_hash_table_replace(g_pcat_controller_data.command_table,
            g_strdup(g_pcat_controller_command_list[i].command),
            g_pcat_controller_command_list[i].callback);
    }

    g_pcat_controller_data.initialized = TRUE;

    return TRUE;
}

void pcat_controller_uninit()
{
    if(!g_pcat_controller_data.initialized)
    {
        return;
    }

    pcat_controller_unix_socket_close(&g_pcat_controller_data);

    if(g_pcat_controller_data.command_table!=NULL)
    {
        g_hash_table_unref(g_pcat_controller_data.command_table);
        g_pcat_controller_data.command_table = NULL;
    }

    g_pcat_controller_data.initialized = FALSE;
}

