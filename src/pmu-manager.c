#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/file.h>
#include <fcntl.h>

#include "pmu-manager.h"
#include "modem-manager.h"
#include "common.h"

#define PCAT_PMU_MANAGER_PM_DEV "/dev/pcat-pm-ctl"
#define PCAT_PMU_MANAGER_BATTERY_SYSFS_PATH "/sys/class/power_supply/battery"
#define PCAT_PMU_MANAGER_CHARGER_SYSFS_PATH "/sys/class/power_supply/charger"
#define PCAT_PMU_MANAGER_STATEFS_BATTERY_PATH "/run/state/namespaces/Battery"
#define PCAT_PMU_MANAGER_COMMAND_TIMEOUT 1000000L
#define PCAT_PMU_MANAGER_COMMAND_QUEUE_MAX 128

typedef enum
{
    PCAT_PMU_MANAGER_COMMAND_HEARTBEAT = 0x1,
    PCAT_PMU_MANAGER_COMMAND_HEARTBEAT_ACK = 0x2,
    PCAT_PMU_MANAGER_COMMAND_PMU_HW_VERSION_GET = 0x3,
    PCAT_PMU_MANAGER_COMMAND_PMU_HW_VERSION_GET_ACK = 0x4,
    PCAT_PMU_MANAGER_COMMAND_PMU_FW_VERSION_GET = 0x5,
    PCAT_PMU_MANAGER_COMMAND_PMU_FW_VERSION_GET_ACK = 0x6,
    PCAT_PMU_MANAGER_COMMAND_STATUS_REPORT = 0x7,
    PCAT_PMU_MANAGER_COMMAND_STATUS_REPORT_ACK = 0x8,
    PCAT_PMU_MANAGER_COMMAND_DATE_TIME_SYNC = 0x9,
    PCAT_PMU_MANAGER_COMMAND_DATE_TIME_SYNC_ACK = 0xA,
    PCAT_PMU_MANAGER_COMMAND_SCHEDULE_STARTUP_TIME_SET = 0xB,
    PCAT_PMU_MANAGER_COMMAND_SCHEDULE_STARTUP_TIME_SET_ACK = 0xC,
    PCAT_PMU_MANAGER_COMMAND_PMU_REQUEST_SHUTDOWN = 0xD,
    PCAT_PMU_MANAGER_COMMAND_PMU_REQUEST_SHUTDOWN_ACK = 0xE,
    PCAT_PMU_MANAGER_COMMAND_HOST_REQUEST_SHUTDOWN = 0xF,
    PCAT_PMU_MANAGER_COMMAND_HOST_REQUEST_SHUTDOWN_ACK = 0x10,
    PCAT_PMU_MANAGER_COMMAND_PMU_REQUEST_FACTORY_RESET = 0x11,
    PCAT_PMU_MANAGER_COMMAND_PMU_REQUEST_FACTORY_RESET_ACK = 0x12,
    PCAT_PMU_MANAGER_COMMAND_WATCHDOG_TIMEOUT_SET = 0x13,
    PCAT_PMU_MANAGER_COMMAND_WATCHDOG_TIMEOUT_SET_ACK = 0x14,
    PCAT_PMU_MANAGER_COMMAND_CHARGER_ON_AUTO_START = 0x15,
    PCAT_PMU_MANAGER_COMMAND_CHARGER_ON_AUTO_START_ACK = 0x16,
    PCAT_PMU_MANAGER_COMMAND_VOLTAGE_THRESHOLD_SET = 0x17,
    PCAT_PMU_MANAGER_COMMAND_VOLTAGE_THRESHOLD_SET_ACK = 0x18,
    PCAT_PMU_MANAGER_COMMAND_NET_STATUS_LED_SETUP = 0x19,
    PCAT_PMU_MANAGER_COMMAND_NET_STATUS_LED_SETUP_ACK = 0x1A,
    PCAT_PMU_MANAGER_COMMAND_POWER_ON_EVENT_GET = 0x1B,
    PCAT_PMU_MANAGER_COMMAND_POWER_ON_EVENT_GET_ACK = 0x1C,
    PCAT_PMU_MANAGER_COMMAND_STATUS_LED_BEEPER_V2_SET = 0x9B,
    PCAT_PMU_MANAGER_COMMAND_STATUS_LED_BEEPER_V2_SET_ACK = 0x9C,
}PCatPMUManagerCommandType;

typedef struct _PCatPMUManagerCommandData
{
    GByteArray *buffer;
    gsize written_size;
    guint16 command;
    gboolean need_ack;
    guint retry_count;
    guint16 frame_num;
    gint64 timestamp;
    gboolean firstrun;
}PCatPMUManagerCommandData;

typedef struct _PCatPMUManagerData
{
    gboolean initialized;

    guint check_timeout_id;

    int dev_fd;
    GIOChannel *dev_channel;
    guint dev_read_source;
    guint dev_write_source;
    GByteArray *dev_read_buffer;
    gchar *board_hwmon_device_path;

    PCatPMUManagerCommandData *dev_write_current_command_data;
    GQueue *dev_write_command_queue;

    gboolean shutdown_request;
    gboolean shutdown_planned;

    guint last_battery_voltage;
    guint last_charger_voltage;
    gboolean last_on_battery_state;
    guint last_battery_percentage;

    gchar *pmu_fw_version;
    gint64 charger_on_auto_start_last_timestamp;
    gint64 pmu_time_set_timestamp;

    guint power_on_event;
    guint modem_power_usage;
    gint board_temp;

    guint battery_discharge_table_normal[11];
    guint battery_discharge_table_5g[11];
    guint battery_charge_table[11];

    gboolean status_led_v2_state;
    gboolean beeper_state;
}PCatPMUManagerData;

static PCatPMUManagerData g_pcat_pmu_manager_data = {0};

static guint g_pat_pmu_manager_battery_discharge_table_normal[11] =
{
    4200, 4060, 3980, 3920, 3870, 3820, 3790, 3770, 3740, 3680, 3450
};

static guint g_pat_pmu_manager_battery_discharge_table_5g[11] =
{
    4200, 4060, 3980, 3920, 3870, 3820, 3790, 3770, 3740, 3680, 3600
};

static guint g_pat_pmu_manager_battery_charge_table[11] =
{
    4200, 4150, 4100, 4050, 4000, 3950, 3900, 3850, 3800, 3750, 3700
};

static gboolean pcat_pmu_pm_dev_open(PCatPMUManagerData *pmu_data);
static void pcat_pmu_pm_dev_close(PCatPMUManagerData *pmu_data);

static void pcat_pmu_manager_command_data_free(
    PCatPMUManagerCommandData *data)
{
    if(data==NULL)
    {
        return;
    }

    if(data->buffer!=NULL)
    {
        g_byte_array_unref(data->buffer);
    }

    g_free(data);
}

static inline guint16 pcat_pmu_compute_crc16(const guint8 *data,
    gsize len)
{
    guint16 crc = 0xFFFF;
    gsize i;
    guint j;

    for(i=0;i<len;i++)
    {
        crc ^= data[i];
        for(j=0;j<8;j++)
        {
            if(crc & 1)
            {
                crc = (crc >> 1) ^ 0xA001;
            }
            else
            {
                crc >>= 1;
            }
        }
    }

    return crc;
}

static void pcat_pmu_poweroff_request(PCatPMUManagerData *pmu_data)
{
    GError *error = NULL;

    if(pmu_data->shutdown_request)
    {
        return;
    }

    if(g_spawn_command_line_async("poweroff", &error))
    {
        pmu_data->shutdown_request = TRUE;

        g_message("Request poweroff.");
    }
    else
    {
        g_warning("Failed to poweroff: %s!",
            error!=NULL ? error->message : "Unknown");
    }
}

static gboolean pcat_pmu_pm_dev_write_watch_func(GIOChannel *source,
    GIOCondition condition, gpointer user_data)
{
    PCatPMUManagerData *pmu_data = (PCatPMUManagerData *)user_data;
    gssize wsize = 0;
    guint remaining_size;
    gboolean ret = FALSE;
    gint64 now;
    GByteArray *buffer;

    now = g_get_monotonic_time();

    do
    {
        if(pmu_data->dev_write_current_command_data==NULL)
        {
            pmu_data->dev_write_current_command_data =
                g_queue_pop_head(pmu_data->dev_write_command_queue);
        }
        if(pmu_data->dev_write_current_command_data==NULL)
        {
            break;
        }
        if(!pmu_data->dev_write_current_command_data->firstrun &&
            pmu_data->dev_write_current_command_data->written_size==0)
        {
            if(now <= pmu_data->dev_write_current_command_data->timestamp +
                PCAT_PMU_MANAGER_COMMAND_TIMEOUT)
            {
                break;
            }
            else if(
                pmu_data->dev_write_current_command_data->retry_count==0)
            {
                pcat_pmu_manager_command_data_free(
                    pmu_data->dev_write_current_command_data);
                pmu_data->dev_write_current_command_data = NULL;

                continue;
            }
        }

        buffer = pmu_data->dev_write_current_command_data->buffer;

        if(buffer->len <=
           pmu_data->dev_write_current_command_data->written_size)
        {
            if(pmu_data->dev_write_current_command_data->need_ack)
            {
                break;
            }
            else
            {
                pcat_pmu_manager_command_data_free(
                    pmu_data->dev_write_current_command_data);
                pmu_data->dev_write_current_command_data = NULL;

                continue;
            }
        }

        remaining_size = buffer->len -
            pmu_data->dev_write_current_command_data->written_size;

        wsize = write(pmu_data->dev_fd,
            buffer->data +
            pmu_data->dev_write_current_command_data->written_size,
            remaining_size > 4096 ? 4096 : remaining_size);

        if(wsize > 0)
        {
            pmu_data->dev_write_current_command_data->written_size += wsize;
            pmu_data->dev_write_current_command_data->timestamp = now;
            pmu_data->dev_write_current_command_data->firstrun = FALSE;
        }
        else
        {
            break;
        }
    }
    while(1);

    if(pmu_data->dev_write_current_command_data!=NULL &&
       pmu_data->dev_write_current_command_data->written_size >=
       pmu_data->dev_write_current_command_data->buffer->len)
    {
        if(pmu_data->dev_write_current_command_data->need_ack &&
           pmu_data->dev_write_current_command_data->retry_count > 0)
        {
            pmu_data->dev_write_current_command_data->retry_count--;
            pmu_data->dev_write_current_command_data->written_size = 0;
        }
        else
        {
            pcat_pmu_manager_command_data_free(
                pmu_data->dev_write_current_command_data);
            pmu_data->dev_write_current_command_data = NULL;
        }
    }

    if(wsize < 0)
    {
        if(errno==EAGAIN)
        {
            ret = TRUE;
        }
        else
        {
            g_warning("PM device write error: %s", strerror(errno));

            pcat_pmu_pm_dev_close(pmu_data);
        }
    }

    if(!ret)
    {
        pmu_data->dev_write_source = 0;
    }

    return ret;
}

static void pcat_pmu_pm_dev_write_data_request(
    PCatPMUManagerData *pmu_data, guint16 command,
    const guint8 *extra_data, guint16 extra_data_len, gboolean need_ack)
{
    GByteArray *ba;
    guint16 sv;
    guint16 dp_size;
    PCatPMUManagerCommandData *new_data, *old_data;

    ba = g_byte_array_new();

    g_byte_array_append(ba, (const guint8 *)"\xA5\x01\x81", 3);
    sv = GUINT16_TO_LE(0);
    g_byte_array_append(ba, (const guint8 *)&sv, 2);

    if(extra_data!=NULL && extra_data_len > 0 && extra_data_len <= 65532)
    {
        sv = extra_data_len + 3;
        sv = GUINT16_TO_LE(sv);
        g_byte_array_append(ba, (const guint8 *)&sv, 2);

        sv = command;
        sv = GUINT16_TO_LE(sv);
        g_byte_array_append(ba, (const guint8 *)&sv, 2);

        g_byte_array_append(ba, extra_data, extra_data_len);

        dp_size = extra_data_len + 3;
    }
    else
    {
        sv = 3;
        sv = GUINT16_TO_LE(sv);

        g_byte_array_append(ba, (const guint8 *)&sv, 2);

        sv = command;
        sv = GUINT16_TO_LE(sv);
        g_byte_array_append(ba, (const guint8 *)&sv, 2);

        dp_size = 3;
    }

    g_byte_array_append(ba,
        need_ack ? (const guint8 *)"\x01" : (const guint8 *)"\x00", 1);

    sv = pcat_pmu_compute_crc16(ba->data + 1, dp_size + 6);
    sv = GUINT16_TO_LE(sv);
    g_byte_array_append(ba, (const guint8 *)&sv, 2);

    g_byte_array_append(ba, (const guint8 *)"\x5A", 1);

    while(g_queue_get_length(pmu_data->dev_write_command_queue) >
       PCAT_PMU_MANAGER_COMMAND_QUEUE_MAX)
    {
        old_data = g_queue_pop_head(pmu_data->dev_write_command_queue);
        pcat_pmu_manager_command_data_free(old_data);
    }

    new_data = g_new0(PCatPMUManagerCommandData, 1);
    new_data->buffer = ba;
    new_data->timestamp = g_get_monotonic_time();
    new_data->need_ack = need_ack;
    new_data->retry_count = need_ack ? 3 : 1;
    new_data->command = command;
    new_data->firstrun = TRUE;

    g_queue_push_tail(pmu_data->dev_write_command_queue, new_data);

    if(pmu_data->dev_write_current_command_data==NULL)
    {
        pmu_data->dev_write_current_command_data = g_queue_pop_head(
            pmu_data->dev_write_command_queue);
    }

    if(pmu_data->dev_write_source==0)
    {
        pmu_data->dev_write_source = g_io_add_watch(
            pmu_data->dev_channel, G_IO_OUT,
            pcat_pmu_pm_dev_write_watch_func, pmu_data);
    }
}

static void pcat_pmu_manager_schedule_time_update_internal(
    PCatPMUManagerData *pmu_data)
{
    guint i;
    const PCatManagerUserConfigData *uconfig_data;
    const PCatManagerPowerScheduleData *sdata;
    GByteArray *startup_setup_buffer;
    guint8 v;

    uconfig_data = pcat_main_user_config_data_get();
    if(uconfig_data->power_schedule_data!=NULL)
    {
        startup_setup_buffer = g_byte_array_new();

        for(i=0;i<uconfig_data->power_schedule_data->len;i++)
        {
            sdata = g_ptr_array_index(uconfig_data->power_schedule_data, i);
            if(!sdata->enabled || !sdata->action)
            {
                continue;
            }

            v = sdata->year & 0xFF;
            g_byte_array_append(startup_setup_buffer, &v, 1);
            v = (sdata->year >> 8) & 0xFF;
            g_byte_array_append(startup_setup_buffer, &v, 1);

            v = sdata->month;
            g_byte_array_append(startup_setup_buffer, &v, 1);

            v = sdata->day;
            g_byte_array_append(startup_setup_buffer, &v, 1);

            v = sdata->hour;
            g_byte_array_append(startup_setup_buffer, &v, 1);

            v = sdata->minute;
            g_byte_array_append(startup_setup_buffer, &v, 1);

            v = sdata->dow_bits;
            g_byte_array_append(startup_setup_buffer, &v, 1);

            v = sdata->enable_bits;
            g_byte_array_append(startup_setup_buffer, &v, 1);

            if(startup_setup_buffer->len >= 48)
            {
                break;
            }
        }

        if(startup_setup_buffer->len > 0)
        {
            pcat_pmu_pm_dev_write_data_request(pmu_data,
                PCAT_PMU_MANAGER_COMMAND_SCHEDULE_STARTUP_TIME_SET,
                startup_setup_buffer->data, startup_setup_buffer->len, TRUE);

            g_message("Updated PMU schedule startup data.");
        }
        else
        {
            pcat_pmu_pm_dev_write_data_request(pmu_data,
                PCAT_PMU_MANAGER_COMMAND_SCHEDULE_STARTUP_TIME_SET,
                NULL, 0, TRUE);

            g_message("Cleared PMU schedule startup data.");
        }

        g_byte_array_unref(startup_setup_buffer);
    }
    else
    {
        pcat_pmu_pm_dev_write_data_request(pmu_data,
            PCAT_PMU_MANAGER_COMMAND_SCHEDULE_STARTUP_TIME_SET, NULL, 0, TRUE);

        g_message("Cleared PMU schedule startup data.");
    }
}

static void pcat_pmu_manager_charger_on_auto_start_internal(
    PCatPMUManagerData *pmu_data, gboolean state)
{
    guint8 v = state ? 1 : 0;

    pcat_pmu_pm_dev_write_data_request(pmu_data,
        PCAT_PMU_MANAGER_COMMAND_CHARGER_ON_AUTO_START, &v, 1, TRUE);
}

static void pcat_pmu_manager_pmu_fw_version_get_internal(
    PCatPMUManagerData *pmu_data)
{
    pcat_pmu_pm_dev_write_data_request(pmu_data,
        PCAT_PMU_MANAGER_COMMAND_PMU_FW_VERSION_GET, NULL, 0, TRUE);
}

static void pcat_pmu_manager_power_on_event_get_internal(
    PCatPMUManagerData *pmu_data)
{
    pcat_pmu_pm_dev_write_data_request(pmu_data,
        PCAT_PMU_MANAGER_COMMAND_POWER_ON_EVENT_GET, NULL, 0, TRUE);
}

static void pcat_pmu_manager_net_status_led_setup_internal(
    PCatPMUManagerData *pmu_data, guint on_time, guint down_time,
    guint repeat)
{
    guint8 buffer[6];
    guint16 v;

    v = GUINT16_TO_LE(on_time);
    memcpy(buffer, &v, 2);

    v = GUINT16_TO_LE(down_time);
    memcpy(buffer + 2, &v, 2);

    v = GUINT16_TO_LE(repeat);
    memcpy(buffer + 4, &v, 2);

    pcat_pmu_pm_dev_write_data_request(pmu_data,
        PCAT_PMU_MANAGER_COMMAND_NET_STATUS_LED_SETUP, buffer, 6, TRUE);
}

static void pcat_pmu_manager_voltage_threshold_set_interval(
    PCatPMUManagerData *pmu_data, guint led_vh, guint led_vm,
    guint led_vl, guint startup_voltage, guint charger_voltage,
    guint shutdown_voltage, guint led_work_vl, guint charger_fast_voltage)
{
    guint8 buffer[18];
    const PCatManagerMainConfigData *main_config_data;
    guint battery_full_threshold;

    main_config_data = pcat_main_config_data_get();

    if(led_vh==0)
    {
        led_vh = main_config_data->pm_led_high_voltage;
    }
    if(led_vm==0)
    {
        led_vm = main_config_data->pm_led_medium_voltage;
    }
    if(led_vl==0)
    {
        led_vl = main_config_data->pm_led_low_voltage;;
    }
    if(startup_voltage==0)
    {
        startup_voltage = main_config_data->pm_startup_voltage;
    }
    if(charger_voltage==0)
    {
        charger_voltage = main_config_data->pm_charger_limit_voltage;
    }
    if(shutdown_voltage==0)
    {
        shutdown_voltage = main_config_data->pm_auto_shutdown_voltage_general;
    }
    if(led_work_vl==0)
    {
        led_work_vl = main_config_data->pm_led_work_low_voltage;
    }
    if(charger_fast_voltage==0)
    {
        charger_fast_voltage = main_config_data->pm_charger_fast_voltage;
    }

    battery_full_threshold = main_config_data->pm_battery_full_threshold;

    buffer[0] = led_vh & 0xFF;
    buffer[1] = (led_vh >> 8) & 0xFF;
    buffer[2] = led_vm & 0xFF;
    buffer[3] = (led_vm >> 8) & 0xFF;
    buffer[4] = led_vl & 0xFF;
    buffer[5] = (led_vl >> 8) & 0xFF;
    buffer[6] = startup_voltage & 0xFF;
    buffer[7] = (startup_voltage >> 8) & 0xFF;
    buffer[8] = charger_voltage & 0xFF;
    buffer[9] = (charger_voltage >> 8) & 0xFF;
    buffer[10] = shutdown_voltage & 0xFF;
    buffer[11] = (shutdown_voltage >> 8) & 0xFF;
    buffer[12] = led_work_vl & 0xFF;
    buffer[13] = (led_work_vl >> 8) & 0xFF;
    buffer[14] = charger_fast_voltage & 0xFF;
    buffer[15] = (charger_fast_voltage >> 8) & 0xFF;

    buffer[16] = battery_full_threshold & 0xFF;
    buffer[17] = (battery_full_threshold >> 8) & 0xFF;

    pcat_pmu_pm_dev_write_data_request(pmu_data,
        PCAT_PMU_MANAGER_COMMAND_VOLTAGE_THRESHOLD_SET, buffer, 18, TRUE);
}

static void pcat_pmu_manager_status_led_beeper_v2_set_interval(
    PCatPMUManagerData *pmu_data, gboolean led_enabled,
    gboolean beeper_enabled)
{
    guint8 state;

    state = led_enabled ? 1 : 0;
    state |= beeper_enabled ? 2 : 0;

    pcat_pmu_pm_dev_write_data_request(pmu_data,
        PCAT_PMU_MANAGER_COMMAND_STATUS_LED_BEEPER_V2_SET, &state, 1, TRUE);
}

static void pcat_pmu_manager_status_led_beeper_v2_get_interval(
    PCatPMUManagerData *pmu_data)
{
    guint8 state = 0xFF;

    pcat_pmu_pm_dev_write_data_request(pmu_data,
        PCAT_PMU_MANAGER_COMMAND_STATUS_LED_BEEPER_V2_SET, &state, 1, TRUE);
}

static void pcat_pmu_pm_status_get(PCatPMUManagerData *pmu_data)
{
    guint battery_voltage = 0, charger_voltage = 0;
    FILE *fp;
    gchar *fname;
    guint battery_percentage = 100;
    gboolean on_battery = TRUE;
    guint charger_online;
    gint board_temp = 0;
    const PCatManagerMainConfigData *config_data;
    guint charge_detection_threshold = 4200;

    config_data = pcat_main_config_data_get();
    if(config_data->pm_battery_charge_detection_threshold > 0)
    {
        charge_detection_threshold =
            config_data->pm_battery_charge_detection_threshold;
    }

    fname = g_build_filename(PCAT_PMU_MANAGER_BATTERY_SYSFS_PATH,
        "voltage_now", NULL);
    fp = fopen(fname, "r");
    g_free(fname);
    if(fp!=NULL)
    {
        fscanf(fp, "%u", &battery_voltage);
        battery_voltage /= 1000;
        fclose(fp);
    }

    fname = g_build_filename(PCAT_PMU_MANAGER_BATTERY_SYSFS_PATH,
        "capacity", NULL);
    fp = fopen(fname, "r");
    g_free(fname);
    if(fp!=NULL)
    {
        fscanf(fp, "%u", &battery_percentage);
        fclose(fp);
    }

    fname = g_build_filename(PCAT_PMU_MANAGER_CHARGER_SYSFS_PATH,
        "voltage_now", NULL);
    fp = fopen(fname, "r");
    g_free(fname);
    if(fp!=NULL)
    {
        fscanf(fp, "%u", &charger_voltage);
        charger_voltage /= 1000;
        fclose(fp);
    }

    fname = g_build_filename(PCAT_PMU_MANAGER_CHARGER_SYSFS_PATH,
        "online", NULL);
    fp = fopen(fname, "r");
    g_free(fname);
    if(fp!=NULL)
    {
        fscanf(fp, "%u", &charger_online);
        on_battery = !charger_online;
        fclose(fp);
    }

    if(pmu_data->board_hwmon_device_path!=NULL)
    {
        fp = fopen(pmu_data->board_hwmon_device_path, "r");
        if(fp!=NULL)
        {
            fscanf(fp, "%d", &board_temp);
            fclose(fp);
        }
    }

    on_battery = (charger_voltage < charge_detection_threshold);

    pmu_data->last_on_battery_state = on_battery;

    pmu_data->last_battery_voltage = battery_voltage;

    pmu_data->last_charger_voltage = charger_voltage;
    pmu_data->board_temp = board_temp / 1000;

    pmu_data->last_battery_percentage = battery_percentage * 100;

    fp = fopen(PCAT_PMU_MANAGER_STATEFS_BATTERY_PATH"/ChargePercentage", "w");
    if(fp!=NULL)
    {
        fprintf(fp, "%lf\n", (double)battery_percentage);
        fclose(fp);
    }

    fp = fopen(PCAT_PMU_MANAGER_STATEFS_BATTERY_PATH"/Voltage", "w");
    if(fp!=NULL)
    {
        fprintf(fp, "%u\n", battery_voltage * 1000);
        fclose(fp);
    }

    fp = fopen(PCAT_PMU_MANAGER_STATEFS_BATTERY_PATH"/OnBattery", "w");
    if(fp!=NULL)
    {
        fprintf(fp, "%u\n", on_battery ? 1 : 0);
        fclose(fp);
    }
}

static void pcat_pmu_pm_dev_read_data_parse(PCatPMUManagerData *pmu_data)
{
    guint i;
    gsize used_size = 0, remaining_size;
    GByteArray *buffer = pmu_data->dev_read_buffer;
    guint16 expect_len, extra_data_len;
    const guint8 *p, *extra_data;
    guint16 checksum, rchecksum;
    guint16 command;
    guint8 src, dst;
    gboolean need_ack;

    if(buffer->len < 13)
    {
        return;
    }

    for(i=0;i<buffer->len;i++)
    {
        if(buffer->data[i]==0xA5)
        {
            p = buffer->data + i;
            remaining_size = buffer->len - i;
            used_size = i;

            if(remaining_size < 13)
            {
                break;
            }

            expect_len = p[5] + ((guint16)p[6] << 8);
            if(expect_len < 3 || expect_len > 65532)
            {
                used_size = i;
                continue;
            }
            if(expect_len + 10 > remaining_size)
            {
                if(used_size > 0)
                {
                    g_byte_array_remove_range(
                        pmu_data->dev_read_buffer, 0, used_size);
                }

                return;
            }

            if(p[9+expect_len]!=0x5A)
            {
                used_size = i;
                continue;
            }

            checksum = p[7+expect_len] + ((guint16)p[8+expect_len] << 8);
            rchecksum = pcat_pmu_compute_crc16(p+1, 6+expect_len);

            if(checksum!=rchecksum)
            {
                g_warning("PM device got incorrect checksum %X, "
                    "should be %X!", checksum ,rchecksum);

                i += 9 + expect_len;
                used_size = i + 1;
                continue;
            }

            src = p[1];
            dst = p[2];

            command = p[7] + ((guint16)p[8] << 8);
            extra_data_len = expect_len - 3;
            if(expect_len > 3)
            {
                extra_data = p + 9;
            }
            else
            {
                extra_data = NULL;
            }
            need_ack = (p[6 + expect_len]!=0);

            g_debug("Got command %X from %X to %X.", command, src, dst);

            if(pmu_data->dev_write_current_command_data!=NULL)
            {
                if(pmu_data->dev_write_current_command_data->command + 1==
                    command)
                {
                    pcat_pmu_manager_command_data_free(
                        pmu_data->dev_write_current_command_data);
                    pmu_data->dev_write_current_command_data = NULL;
                }
            }

            if(dst==0x1 || dst==0x80 || dst==0xFF)
            {
                switch(command)
                {
                    case PCAT_PMU_MANAGER_COMMAND_PMU_REQUEST_SHUTDOWN:
                    {
                        pcat_pmu_poweroff_request(pmu_data);

                        if(need_ack)
                        {
                            pcat_pmu_pm_dev_write_data_request(pmu_data,
                                command+1, NULL, 0, FALSE);
                        }

                        break;
                    }
                    case PCAT_PMU_MANAGER_COMMAND_PMU_REQUEST_FACTORY_RESET:
                    {
                        guint8 state = 0;

                        g_spawn_command_line_async(
                            "pcat-factory-reset.sh", NULL);

                        if(need_ack)
                        {
                            pcat_pmu_pm_dev_write_data_request(pmu_data,
                                command+1, &state, 1, FALSE);
                        }

                        break;
                    }
                    case PCAT_PMU_MANAGER_COMMAND_PMU_FW_VERSION_GET_ACK:
                    {
                        if(extra_data_len < 14)
                        {
                            break;
                        }

                        if(pmu_data->pmu_fw_version!=NULL)
                        {
                            g_free(pmu_data->pmu_fw_version);
                        }
                        pmu_data->pmu_fw_version =
                            g_strndup((const gchar *)extra_data,
                            extra_data_len);

                        g_message("PMU FW Version: %s",
                            pmu_data->pmu_fw_version);

                        break;
                    }
                    case PCAT_PMU_MANAGER_COMMAND_POWER_ON_EVENT_GET_ACK:
                    {
                        if(extra_data_len < 1)
                        {
                            break;
                        }

                        pmu_data->power_on_event = extra_data[0];

                        break;
                    }
                    case PCAT_PMU_MANAGER_COMMAND_STATUS_LED_BEEPER_V2_SET_ACK:
                    {
                        if(extra_data_len < 1)
                        {
                            break;
                        }

                        if(extra_data[0] <= 3)
                        {
                            pmu_data->status_led_v2_state = extra_data[0] & 1;
                            pmu_data->beeper_state = (extra_data[0] >> 1) & 1;
                        }

                        g_message("PMU IO operation status: %X",
                            extra_data[0]);

                        break;
                    }
                    default:
                    {
                        break;
                    }
                }
            }

            i += 9 + expect_len;
            used_size = i + 1;
        }
        else
        {
            used_size = i;
        }
    }

    if(used_size > 0)
    {
        g_byte_array_remove_range(pmu_data->dev_read_buffer, 0, used_size);
    }
}

static gboolean pcat_pmu_pm_dev_read_watch_func(GIOChannel *source,
    GIOCondition condition, gpointer user_data)
{
    PCatPMUManagerData *pmu_data = (PCatPMUManagerData *)user_data;
    gssize rsize;
    guint8 buffer[4096];

    while((rsize=read(pmu_data->dev_fd, buffer, 4096))>0)
    {
        g_byte_array_append(pmu_data->dev_read_buffer, buffer, rsize);
        if(pmu_data->dev_read_buffer->len > 131072)
        {
            g_byte_array_remove_range(pmu_data->dev_read_buffer, 0,
                pmu_data->dev_read_buffer->len - 65536);
        }

        pcat_pmu_pm_dev_read_data_parse(pmu_data);
    }

    if(rsize < 0)
    {
        if(errno!=EAGAIN)
        {
            g_warning("Read PM device with error %s!", strerror(errno));

            pcat_pmu_pm_dev_close(pmu_data);
        }
    }

    return TRUE;
}

static gboolean pcat_pmu_pm_dev_open(PCatPMUManagerData *pmu_data)
{
    int fd;
    GIOChannel *channel;

    fd = open(PCAT_PMU_MANAGER_PM_DEV, O_RDWR | O_NDELAY);
    if(fd < 0)
    {
        g_warning("Failed to open PM device %s", strerror(errno));

        return FALSE;
    }

    if(flock(fd, LOCK_EX)!=0)
    {
        g_warning("Failed to lock PM device %s, maybe "
            "another process using this device!", strerror(errno));

        return FALSE;
    }

    channel = g_io_channel_unix_new(fd);
    if(channel==NULL)
    {
        g_warning("Cannot open channel for PM device!");
        close(fd);

        return FALSE;
    }
    g_io_channel_set_flags(channel, G_IO_FLAG_NONBLOCK, NULL);

    if(pmu_data->dev_write_source > 0)
    {
        g_source_remove(pmu_data->dev_write_source);
        pmu_data->dev_write_source = 0;
    }

    if(pmu_data->dev_read_source > 0)
    {
        g_source_remove(pmu_data->dev_read_source);
        pmu_data->dev_read_source = 0;
    }
    if(pmu_data->dev_channel!=NULL)
    {
        g_io_channel_unref(pmu_data->dev_channel);
    }
    if(pmu_data->dev_fd > 0)
    {
        close(pmu_data->dev_fd);
        pmu_data->dev_fd = -1;
    }

    pmu_data->dev_fd = fd;
    pmu_data->dev_channel = channel;

    pmu_data->dev_read_source = g_io_add_watch(channel,
        G_IO_IN, pcat_pmu_pm_dev_read_watch_func, pmu_data);

    g_message("Open PM device successfully.");

    return TRUE;
}

static void pcat_pmu_pm_dev_close(PCatPMUManagerData *pmu_data)
{
    if(pmu_data->dev_write_source > 0)
    {
        g_source_remove(pmu_data->dev_write_source);
        pmu_data->dev_write_source = 0;
    }

    if(pmu_data->dev_read_source > 0)
    {
        g_source_remove(pmu_data->dev_read_source);
        pmu_data->dev_read_source = 0;
    }

    if(pmu_data->dev_channel!=NULL)
    {
        g_io_channel_unref(pmu_data->dev_channel);
        pmu_data->dev_channel = NULL;
    }

    if(pmu_data->dev_fd > 0)
    {
        flock(pmu_data->dev_fd, LOCK_UN);
        close(pmu_data->dev_fd);
        pmu_data->dev_fd = -1;
    }
}

static gboolean pcat_pmu_manager_check_timeout_func(gpointer user_data)
{
    PCatPMUManagerData *pmu_data = (PCatPMUManagerData *)user_data;
    const PCatManagerMainConfigData *config_data;
    const PCatManagerUserConfigData *uconfig_data;
    const PCatManagerPowerScheduleData *sdata;
    guint i;
    GDateTime *dt;
    gboolean need_action = FALSE;
    guint dow;
    gint64 now;
    guint modem_power_usage;
    guint shutdown_voltage = 0;
    guint charge_detection_threshold = 4200;

    pcat_pmu_pm_status_get(pmu_data);

    config_data = pcat_main_config_data_get();

    if(config_data->pm_battery_charge_detection_threshold > 0)
    {
        charge_detection_threshold =
            config_data->pm_battery_charge_detection_threshold;
    }

    now = g_get_monotonic_time();
    if(pmu_data->last_charger_voltage >= charge_detection_threshold)
    {
        pmu_data->charger_on_auto_start_last_timestamp = now;
    }

    if(!pmu_data->shutdown_request)
    {
        uconfig_data = pcat_main_user_config_data_get();
        if(uconfig_data->charger_on_auto_start)
        {
            if((pmu_data->power_on_event==3 || pmu_data->power_on_event==4) &&
               now > pmu_data->charger_on_auto_start_last_timestamp +
               (gint64)uconfig_data->charger_on_auto_start_timeout * 1000000L)
            {
                pcat_pmu_poweroff_request(pmu_data);
                pmu_data->shutdown_planned = TRUE;
            }
        }
        else if(uconfig_data->power_schedule_data!=NULL &&
            !pmu_data->shutdown_planned)
        {
            dt = g_date_time_new_now_utc();

            for(i=0;i<uconfig_data->power_schedule_data->len;i++)
            {
                sdata = g_ptr_array_index(
                    uconfig_data->power_schedule_data, i);

                if(!sdata->enabled || sdata->action)
                {
                    continue;
                }

                if(!(sdata->enable_bits &
                    PCAT_MANAGER_POWER_SCHEDULE_ENABLE_MINUTE))
                {
                    continue;
                }

                if(sdata->enable_bits &
                    PCAT_MANAGER_POWER_SCHEDULE_ENABLE_YEAR)
                {
                    if(g_date_time_get_year(dt)==sdata->year &&
                       g_date_time_get_month(dt)==sdata->month &&
                       g_date_time_get_day_of_month(dt)==sdata->day &&
                       g_date_time_get_hour(dt)==sdata->hour &&
                       g_date_time_get_minute(dt)==sdata->minute)
                    {
                        need_action = TRUE;
                    }
                }
                else if(sdata->enable_bits &
                    PCAT_MANAGER_POWER_SCHEDULE_ENABLE_MONTH)
                {
                    if(g_date_time_get_month(dt)==sdata->month &&
                       g_date_time_get_day_of_month(dt)==sdata->day &&
                       g_date_time_get_hour(dt)==sdata->hour &&
                       g_date_time_get_minute(dt)==sdata->minute)
                    {
                        need_action = TRUE;
                    }
                }
                else if(sdata->enable_bits &
                    PCAT_MANAGER_POWER_SCHEDULE_ENABLE_DAY)
                {
                    if(g_date_time_get_day_of_month(dt)==sdata->day &&
                       g_date_time_get_hour(dt)==sdata->hour &&
                       g_date_time_get_minute(dt)==sdata->minute)
                    {
                        need_action = TRUE;
                    }
                }
                else if(sdata->enable_bits &
                    PCAT_MANAGER_POWER_SCHEDULE_ENABLE_DOW)
                {
                    dow = g_date_time_get_day_of_week(dt) % 7;

                    if(((sdata->dow_bits >> dow) & 1) &&
                       g_date_time_get_hour(dt)==sdata->hour &&
                       g_date_time_get_minute(dt)==sdata->minute)
                    {
                        need_action = TRUE;

                    }
                }
                else if(sdata->enable_bits &
                    PCAT_MANAGER_POWER_SCHEDULE_ENABLE_HOUR)
                {
                    if(g_date_time_get_hour(dt)==sdata->hour &&
                       g_date_time_get_minute(dt)==sdata->minute)
                    {
                        need_action = TRUE;
                    }
                }
                else
                {
                    if(g_date_time_get_minute(dt)==sdata->minute)
                    {
                        need_action = TRUE;
                    }
                }

                if(need_action)
                {
                    pcat_pmu_poweroff_request(pmu_data);
                    pmu_data->shutdown_planned = TRUE;
                }
            }

            g_date_time_unref(dt);
        }
    }

    modem_power_usage = pcat_modem_manager_device_power_usage_get();

    if(pmu_data->modem_power_usage!=modem_power_usage)
    {
        switch(modem_power_usage)
        {
            case 2:
            {
                shutdown_voltage = config_data->pm_auto_shutdown_voltage_5g;
                break;
            }
            case 1:
            {
                shutdown_voltage = config_data->pm_auto_shutdown_voltage_lte;
                break;
            }
            default:
            {
                shutdown_voltage =
                    config_data->pm_auto_shutdown_voltage_general;
                break;
            }
        }

        pmu_data->modem_power_usage = modem_power_usage;
        pcat_pmu_manager_voltage_threshold_set_interval(pmu_data,
            0, 0, 0, 0, 0, shutdown_voltage, 0, 0);

        g_message("Detected modem power usage level %u, "
            "set shutdown voltage to %u.", modem_power_usage,
            shutdown_voltage);
    }

    if(pmu_data->dev_write_source==0 &&
       pmu_data->dev_write_current_command_data==NULL &&
       !g_queue_is_empty(pmu_data->dev_write_command_queue))
    {
        pmu_data->dev_write_source = g_io_add_watch(
            pmu_data->dev_channel, G_IO_OUT,
            pcat_pmu_pm_dev_write_watch_func, pmu_data);
    }

    if(pmu_data->dev_write_source==0 &&
       pmu_data->dev_write_current_command_data!=NULL &&
        (pmu_data->dev_write_current_command_data->firstrun ||
        now > pmu_data->dev_write_current_command_data->timestamp +
        PCAT_PMU_MANAGER_COMMAND_TIMEOUT))
    {
        pmu_data->dev_write_source = g_io_add_watch(
            pmu_data->dev_channel, G_IO_OUT,
            pcat_pmu_pm_dev_write_watch_func, pmu_data);
    }

    return TRUE;
}

gboolean pcat_pmu_manager_init()
{
    const PCatManagerMainConfigData *config_data;
    const PCatManagerUserConfigData *uconfig_data;
    guint i;
    gboolean valid;
    guint tmp;
    GDir *hwmon_dir;
    const gchar *hwmon_dname;
    gchar *hwmon_name_file;
    gchar hwmon_name[64] = {0};
    FILE *hwmon_name_fp;

    if(g_pcat_pmu_manager_data.initialized)
    {
        return TRUE;
    }

    g_pcat_pmu_manager_data.shutdown_request = FALSE;
    g_pcat_pmu_manager_data.charger_on_auto_start_last_timestamp =
        g_get_monotonic_time();
    g_pcat_pmu_manager_data.power_on_event = 0;

    g_mkdir_with_parents(PCAT_PMU_MANAGER_STATEFS_BATTERY_PATH, 0755);

    g_pcat_pmu_manager_data.dev_read_buffer = g_byte_array_new();
    g_pcat_pmu_manager_data.dev_write_command_queue = g_queue_new();
    g_pcat_pmu_manager_data.dev_write_current_command_data = NULL;
    g_pcat_pmu_manager_data.status_led_v2_state = TRUE;
    g_pcat_pmu_manager_data.beeper_state = TRUE;


    if(!pcat_pmu_pm_dev_open(&g_pcat_pmu_manager_data))
    {
        g_warning("Failed to open PMU PM device! Try it later....");
    }

    for(i=0;i<11;i++)
    {
        g_pcat_pmu_manager_data.battery_discharge_table_normal[i] =
            g_pat_pmu_manager_battery_discharge_table_normal[i];
        g_pcat_pmu_manager_data.battery_discharge_table_5g[i] =
            g_pat_pmu_manager_battery_discharge_table_5g[i];
        g_pcat_pmu_manager_data.battery_charge_table[i] =
            g_pat_pmu_manager_battery_charge_table[i];
    }

    config_data = pcat_main_config_data_get();

    valid = TRUE;
    tmp = config_data->pm_battery_discharge_table_normal[0];
    for(i=1;i<11;i++)
    {
        if(tmp <= config_data->pm_battery_discharge_table_normal[i])
        {
            valid = FALSE;
            break;
        }
        tmp = config_data->pm_battery_discharge_table_normal[i];
    }
    if(valid)
    {
        for(i=0;i<11;i++)
        {
            g_pcat_pmu_manager_data.battery_discharge_table_normal[i] =
                config_data->pm_battery_discharge_table_normal[i];
        }
    }

    valid = TRUE;
    tmp = config_data->pm_battery_discharge_table_5g[0];
    for(i=1;i<11;i++)
    {
        if(tmp <= config_data->pm_battery_discharge_table_5g[i])
        {
            valid = FALSE;
            break;
        }
        tmp = config_data->pm_battery_discharge_table_5g[i];
    }
    if(valid)
    {
        for(i=0;i<11;i++)
        {
            g_pcat_pmu_manager_data.battery_discharge_table_5g[i] =
                config_data->pm_battery_discharge_table_5g[i];
        }
    }

    valid = TRUE;
    tmp = config_data->pm_battery_charge_table[0];
    for(i=1;i<11;i++)
    {
        if(tmp <= config_data->pm_battery_charge_table[i])
        {
            valid = FALSE;
            break;
        }
        tmp = config_data->pm_battery_charge_table[i];
    }
    if(valid)
    {
        for(i=0;i<11;i++)
        {
            g_pcat_pmu_manager_data.battery_charge_table[i] =
                config_data->pm_battery_charge_table[i];
        }
    }

    hwmon_dir = g_dir_open("/sys/class/hwmon", 0, NULL);
    if(hwmon_dir!=NULL)
    {
        while((hwmon_dname=g_dir_read_name(hwmon_dir))!=NULL)
        {
            hwmon_name_file = g_build_filename("/sys/class/hwmon",
                hwmon_dname, "name", NULL);
            hwmon_name_fp = fopen(hwmon_name_file, "r");
            g_free(hwmon_name_file);

            if(hwmon_name_fp!=NULL)
            {
                fread(hwmon_name, 63, 1, hwmon_name_fp);

                if(g_str_has_prefix(hwmon_name, "pcat_pm_hwmon_temp_mb"))
                {
                    g_pcat_pmu_manager_data.board_hwmon_device_path =
                        g_build_filename("/sys/class/hwmon", hwmon_dname,
                        "temp1_input", NULL);
                }

                fclose(hwmon_name_fp);
            }

            if(g_pcat_pmu_manager_data.board_hwmon_device_path!=NULL)
            {
                break;
            }
        }

        g_dir_close(hwmon_dir);
    }

    g_pcat_pmu_manager_data.check_timeout_id = g_timeout_add_seconds(1,
        pcat_pmu_manager_check_timeout_func, &g_pcat_pmu_manager_data);

    g_pcat_pmu_manager_data.initialized = TRUE;

    pcat_pmu_manager_schedule_time_update_internal(&g_pcat_pmu_manager_data);

    uconfig_data = pcat_main_user_config_data_get();

    pcat_pmu_manager_charger_on_auto_start_internal(&g_pcat_pmu_manager_data,
        uconfig_data->charger_on_auto_start);

    pcat_pmu_manager_voltage_threshold_set_interval(&g_pcat_pmu_manager_data,
        0, 0, 0, 0, 0, config_data->pm_auto_shutdown_voltage_general, 0, 0);

    pcat_pmu_manager_pmu_fw_version_get_internal(&g_pcat_pmu_manager_data);

    pcat_pmu_manager_power_on_event_get_internal(&g_pcat_pmu_manager_data);

    pcat_pmu_manager_status_led_beeper_v2_get_interval(
        &g_pcat_pmu_manager_data);

    return TRUE;
}

void pcat_pmu_manager_uninit()
{
    if(!g_pcat_pmu_manager_data.initialized)
    {
        return;
    }

    if(g_pcat_pmu_manager_data.check_timeout_id > 0)
    {
        g_source_remove(g_pcat_pmu_manager_data.check_timeout_id);
        g_pcat_pmu_manager_data.check_timeout_id = 0;
    }

    pcat_pmu_pm_dev_close(&g_pcat_pmu_manager_data);

    if(g_pcat_pmu_manager_data.dev_write_current_command_data!=NULL)
    {
        pcat_pmu_manager_command_data_free(
            g_pcat_pmu_manager_data.dev_write_current_command_data);
        g_pcat_pmu_manager_data.dev_write_current_command_data = NULL;
    }
    if(g_pcat_pmu_manager_data.dev_write_command_queue!=NULL)
    {
        g_queue_free_full(g_pcat_pmu_manager_data.dev_write_command_queue,
            (GDestroyNotify)pcat_pmu_manager_command_data_free);
        g_pcat_pmu_manager_data.dev_write_command_queue = NULL;
    }

    if(g_pcat_pmu_manager_data.dev_read_buffer!=NULL)
    {
        g_byte_array_unref(g_pcat_pmu_manager_data.dev_read_buffer);
        g_pcat_pmu_manager_data.dev_read_buffer = NULL;
    }

    if(g_pcat_pmu_manager_data.pmu_fw_version!=NULL)
    {
        g_free(g_pcat_pmu_manager_data.pmu_fw_version);
        g_pcat_pmu_manager_data.pmu_fw_version = NULL;
    }

    if(g_pcat_pmu_manager_data.board_hwmon_device_path!=NULL)
    {
        g_free(g_pcat_pmu_manager_data.board_hwmon_device_path);
        g_pcat_pmu_manager_data.board_hwmon_device_path = NULL;
    }

    g_pcat_pmu_manager_data.initialized = FALSE;
}

gboolean pcat_pmu_manager_pmu_status_get(guint *battery_voltage,
    guint *charger_voltage, gboolean *on_battery, guint *battery_percentage)
{
    if(!g_pcat_pmu_manager_data.initialized)
    {
        return FALSE;
    }

    if(battery_voltage!=NULL)
    {
        *battery_voltage = g_pcat_pmu_manager_data.last_battery_voltage;
    }
    if(charger_voltage!=NULL)
    {
        *charger_voltage = g_pcat_pmu_manager_data.last_charger_voltage;
    }
    if(on_battery!=NULL)
    {
        *on_battery = g_pcat_pmu_manager_data.last_on_battery_state;
    }
    if(battery_percentage!=NULL)
    {
        *battery_percentage = g_pcat_pmu_manager_data.last_battery_percentage;
    }

    return TRUE;
}

void pcat_pmu_manager_schedule_time_update()
{
    if(!g_pcat_pmu_manager_data.initialized)
    {
        return;
    }

    pcat_pmu_manager_schedule_time_update_internal(&g_pcat_pmu_manager_data);
}

void pcat_pmu_manager_charger_on_auto_start(gboolean state)
{
    if(!g_pcat_pmu_manager_data.initialized)
    {
        return;
    }

    pcat_pmu_manager_charger_on_auto_start_internal(&g_pcat_pmu_manager_data,
        state);
}

void pcat_pmu_manager_net_status_led_setup(guint on_time, guint off_time,
    guint repeat)
{
    if(!g_pcat_pmu_manager_data.initialized)
    {
        return;
    }

    pcat_pmu_manager_net_status_led_setup_internal(&g_pcat_pmu_manager_data,
        on_time, off_time, repeat);
}

const gchar *pcat_pmu_manager_pmu_fw_version_get()
{
    return g_pcat_pmu_manager_data.pmu_fw_version;
}

gint64 pcat_pmu_manager_charger_on_auto_start_last_timestamp_get()
{
    return g_pcat_pmu_manager_data.charger_on_auto_start_last_timestamp;
}

void pcat_pmu_manager_voltage_threshold_set(guint led_vh, guint led_vm,
    guint led_vl, guint startup_voltage, guint charger_voltage,
    guint shutdown_voltage, guint led_work_vl, guint charger_fast_voltage)
{
    if(!g_pcat_pmu_manager_data.initialized)
    {
        return;
    }

    pcat_pmu_manager_voltage_threshold_set_interval(&g_pcat_pmu_manager_data,
        led_vh, led_vm, led_vl, startup_voltage, charger_voltage,
        shutdown_voltage, led_work_vl, charger_fast_voltage);
}

gint pcat_pmu_manager_board_temp_get()
{
    return g_pcat_pmu_manager_data.board_temp;
}

void pcat_pmu_manager_status_led_v2_state_set(gboolean state)
{
    g_pcat_pmu_manager_data.status_led_v2_state = state;

    pcat_pmu_manager_status_led_beeper_v2_set_interval(
        &g_pcat_pmu_manager_data, g_pcat_pmu_manager_data.status_led_v2_state,
        g_pcat_pmu_manager_data.beeper_state);
}

gboolean pcat_pmu_manager_status_led_v2_state_get()
{
    return g_pcat_pmu_manager_data.status_led_v2_state;
}

void pcat_pmu_manager_beeper_state_set(gboolean state)
{
    g_pcat_pmu_manager_data.beeper_state = state;

    pcat_pmu_manager_status_led_beeper_v2_set_interval(
        &g_pcat_pmu_manager_data, g_pcat_pmu_manager_data.status_led_v2_state,
        g_pcat_pmu_manager_data.beeper_state);
}

gboolean pcat_pmu_manager_beeper_state_get()
{
    return g_pcat_pmu_manager_data.beeper_state;
}

