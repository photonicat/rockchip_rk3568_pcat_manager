#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>

#include "pmu-manager.h"
#include "modem-manager.h"
#include "common.h"

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

    int serial_fd;
    GIOChannel *serial_channel;
    guint serial_read_source;
    guint serial_write_source;
    GByteArray *serial_read_buffer;

    PCatPMUManagerCommandData *serial_write_current_command_data;
    GQueue *serial_write_command_queue;
    guint16 serial_write_frame_num;

    gboolean shutdown_request;
    gboolean reboot_request;
    gboolean shutdown_planned;
    gboolean shutdown_process_completed;
    gboolean reboot_process_completed;

    guint last_battery_voltage;
    guint last_charger_voltage;
    gboolean last_on_battery_state;
    guint last_battery_percentage;

    gchar *pmu_fw_version;
    gint64 charger_on_auto_start_last_timestamp;
    gboolean system_time_set_flag;

    guint power_on_event;
    PCatModemManagerDeviceType modem_device_type;
}PCatPMUManagerData;

static PCatPMUManagerData g_pcat_pmu_manager_data = {0};

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

static inline guint16 pcat_pmu_serial_compute_crc16(const guint8 *data,
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

static gboolean pcat_pmu_serial_write_watch_func(GIOChannel *source,
    GIOCondition condition, gpointer user_data)
{
    PCatPMUManagerData *pmu_data = (PCatPMUManagerData *)user_data;
    gssize wsize;
    guint remaining_size;
    gboolean ret = FALSE;
    gint64 now;
    GByteArray *buffer;

    now = g_get_monotonic_time();

    do
    {
        if(pmu_data->serial_write_current_command_data==NULL)
        {
            pmu_data->serial_write_current_command_data =
                g_queue_pop_head(pmu_data->serial_write_command_queue);
        }
        if(pmu_data->serial_write_current_command_data==NULL)
        {
            break;
        }
        if(!pmu_data->serial_write_current_command_data->firstrun &&
            pmu_data->serial_write_current_command_data->written_size==0)
        {
            if(now <= pmu_data->serial_write_current_command_data->timestamp +
                PCAT_PMU_MANAGER_COMMAND_TIMEOUT)
            {
                break;
            }
            else if(
                pmu_data->serial_write_current_command_data->retry_count==0)
            {
                pcat_pmu_manager_command_data_free(
                    pmu_data->serial_write_current_command_data);
                pmu_data->serial_write_current_command_data = NULL;

                continue;
            }
        }

        buffer = pmu_data->serial_write_current_command_data->buffer;

        if(buffer->len <=
           pmu_data->serial_write_current_command_data->written_size)
        {
            if(pmu_data->serial_write_current_command_data->need_ack)
            {
                break;
            }
            else
            {
                pcat_pmu_manager_command_data_free(
                    pmu_data->serial_write_current_command_data);
                pmu_data->serial_write_current_command_data = NULL;

                continue;
            }
        }

        remaining_size = buffer->len -
            pmu_data->serial_write_current_command_data->written_size;

        wsize = write(pmu_data->serial_fd,
            buffer->data +
            pmu_data->serial_write_current_command_data->written_size,
            remaining_size > 4096 ? 4096 : remaining_size);

        if(wsize > 0)
        {
            pmu_data->serial_write_current_command_data->written_size += wsize;
            pmu_data->serial_write_current_command_data->timestamp = now;
            pmu_data->serial_write_current_command_data->firstrun = FALSE;
        }
        else
        {
            break;
        }
    }
    while(1);

    if(pmu_data->serial_write_current_command_data!=NULL &&
       pmu_data->serial_write_current_command_data->written_size >=
       pmu_data->serial_write_current_command_data->buffer->len)
    {
        if(pmu_data->serial_write_current_command_data->need_ack &&
           pmu_data->serial_write_current_command_data->retry_count > 0)
        {
            pmu_data->serial_write_current_command_data->retry_count--;
            pmu_data->serial_write_current_command_data->written_size = 0;
        }
        else
        {
            pcat_pmu_manager_command_data_free(
                pmu_data->serial_write_current_command_data);
            pmu_data->serial_write_current_command_data = NULL;
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
            g_warning("Serial port write error: %s", strerror(errno));
        }
    }

    if(!ret)
    {
        pmu_data->serial_write_source = 0;
    }

    return ret;
}

static void pcat_pmu_serial_write_data_request(
    PCatPMUManagerData *pmu_data, guint16 command, gboolean frame_num_set,
    guint16 frame_num, const guint8 *extra_data, guint16 extra_data_len,
    gboolean need_ack)
{
    GByteArray *ba;
    guint16 sv;
    guint16 dp_size;
    PCatPMUManagerCommandData *new_data, *old_data;

    ba = g_byte_array_new();

    g_byte_array_append(ba, (const guint8 *)"\xA5\x01\x81", 3);
    if(frame_num_set)
    {
        sv = frame_num;
        sv = GUINT16_TO_LE(sv);
        g_byte_array_append(ba, (const guint8 *)&sv, 2);
    }
    else
    {
        frame_num = pmu_data->serial_write_frame_num;
        sv = pmu_data->serial_write_frame_num;
        sv = GUINT16_TO_LE(sv);
        g_byte_array_append(ba, (const guint8 *)&sv, 2);
        pmu_data->serial_write_frame_num++;
    }

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

    sv = pcat_pmu_serial_compute_crc16(ba->data + 1, dp_size + 6);
    sv = GUINT16_TO_LE(sv);
    g_byte_array_append(ba, (const guint8 *)&sv, 2);

    g_byte_array_append(ba, (const guint8 *)"\x5A", 1);

    while(g_queue_get_length(pmu_data->serial_write_command_queue) >
       PCAT_PMU_MANAGER_COMMAND_QUEUE_MAX)
    {
        old_data = g_queue_pop_head(pmu_data->serial_write_command_queue);
        pcat_pmu_manager_command_data_free(old_data);
    }

    new_data = g_new0(PCatPMUManagerCommandData, 1);
    new_data->buffer = ba;
    new_data->timestamp = g_get_monotonic_time();
    new_data->need_ack = need_ack;
    new_data->retry_count = need_ack ? 3 : 1;
    new_data->frame_num = frame_num;
    new_data->command = command;
    new_data->firstrun = TRUE;

    g_queue_push_tail(pmu_data->serial_write_command_queue, new_data);

    if(pmu_data->serial_write_current_command_data==NULL)
    {
        pmu_data->serial_write_current_command_data = g_queue_pop_head(
            pmu_data->serial_write_command_queue);
    }

    if(pmu_data->serial_write_source==0)
    {
        pmu_data->serial_write_source = g_io_add_watch(
            pmu_data->serial_channel, G_IO_OUT,
            pcat_pmu_serial_write_watch_func, pmu_data);
    }
}

static void pcat_pmu_manager_date_time_sync(PCatPMUManagerData *pmu_data)
{
    guint8 data[7];
    GDateTime *dt;
    gint y, m, d, h, min, sec;

    dt = g_date_time_new_now_utc();
    g_date_time_get_ymd(dt, &y, &m, &d);
    h = g_date_time_get_hour(dt);
    min = g_date_time_get_minute(dt);
    sec = g_date_time_get_second(dt);

    data[0] = y & 0xFF;
    data[1] = (y >> 8) & 0xFF;
    data[2] = m;
    data[3] = d;
    data[4] = h;
    data[5] = min;
    data[6] = sec;

    g_date_time_unref(dt);

    pcat_pmu_serial_write_data_request(pmu_data,
        PCAT_PMU_MANAGER_COMMAND_DATE_TIME_SYNC, FALSE, 0,
        data, 7, TRUE);
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
            pcat_pmu_serial_write_data_request(pmu_data,
                PCAT_PMU_MANAGER_COMMAND_SCHEDULE_STARTUP_TIME_SET, FALSE, 0,
                startup_setup_buffer->data, startup_setup_buffer->len, TRUE);

            g_message("Updated PMU schedule startup data.");
        }

        g_byte_array_unref(startup_setup_buffer);
    }
}

static void pcat_pmu_manager_charger_on_auto_start_internal(
    PCatPMUManagerData *pmu_data, gboolean state)
{
    guint8 v = state ? 1 : 0;

    pcat_pmu_serial_write_data_request(pmu_data,
        PCAT_PMU_MANAGER_COMMAND_CHARGER_ON_AUTO_START, FALSE, 0,
        &v, 1, TRUE);
}

static void pcat_pmu_manager_pmu_fw_version_get_internal(
    PCatPMUManagerData *pmu_data)
{
    pcat_pmu_serial_write_data_request(pmu_data,
        PCAT_PMU_MANAGER_COMMAND_PMU_FW_VERSION_GET, FALSE, 0,
        NULL, 0, TRUE);
}

static void pcat_pmu_manager_power_on_event_get_internal(
    PCatPMUManagerData *pmu_data)
{
    pcat_pmu_serial_write_data_request(pmu_data,
        PCAT_PMU_MANAGER_COMMAND_POWER_ON_EVENT_GET, FALSE, 0,
        NULL, 0, TRUE);
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

    pcat_pmu_serial_write_data_request(pmu_data,
        PCAT_PMU_MANAGER_COMMAND_NET_STATUS_LED_SETUP, FALSE, 0,
        buffer, 6, TRUE);
}

static void pcat_pmu_manager_voltage_threshold_set_interval(
    PCatPMUManagerData *pmu_data, guint led_vh, guint led_vm,
    guint led_vl, guint startup_voltage, guint charger_voltage,
    guint shutdown_voltage, guint led_work_vl, guint charger_fast_voltage)
{
    guint8 buffer[16];

    if(led_vh==0)
    {
        led_vh = 3850;
    }
    if(led_vm==0)
    {
        led_vm = 3700;
    }
    if(led_vl==0)
    {
        led_vl = 3600;
    }
    if(startup_voltage==0)
    {
        startup_voltage = 3400;
    }
    if(charger_voltage==0)
    {
        charger_voltage = 4500;
    }
    if(shutdown_voltage==0)
    {
        shutdown_voltage = 3450;
    }
    if(led_work_vl==0)
    {
        led_work_vl = 3600;
    }
    if(charger_fast_voltage==0)
    {
        charger_fast_voltage = 4700;
    }

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

    pcat_pmu_serial_write_data_request(pmu_data,
        PCAT_PMU_MANAGER_COMMAND_VOLTAGE_THRESHOLD_SET, FALSE, 0,
        buffer, 16, TRUE);
}

static void pcat_pmu_serial_status_data_parse(PCatPMUManagerData *pmu_data,
    const guint8 *data, guint len)
{
    guint16 battery_voltage, charger_voltage;
    guint16 gpio_input, gpio_output;
    gint y, m, d, h, min, s;
    GDateTime *pmu_dt, *host_dt;
    gint64 pmu_unix_time, host_unix_time;
    FILE *fp;
    gdouble battery_percentage;
    gboolean on_battery;
    struct timeval tv;

    if(len < 16)
    {
        return;
    }

    battery_voltage = data[0] + ((guint16)data[1] << 8);
    charger_voltage = data[2] + ((guint16)data[3] << 8);
    gpio_input = data[4] + ((guint16)data[5] << 8);
    gpio_output = data[6] + ((guint16)data[7] << 8);
    y = data[8] + ((guint16)data[9] << 8);
    m = data[10];
    d = data[11];
    h = data[12];
    min = data[13];
    s = data[14];

    if(pmu_data->system_time_set_flag)
    {
        pmu_dt = g_date_time_new_utc(y, m, d, h, min, (gdouble)s);
        if(pmu_dt!=NULL)
        {
            pmu_unix_time = g_date_time_to_unix(pmu_dt);
            g_date_time_unref(pmu_dt);
        }
        else
        {
            pmu_unix_time = 0;
        }

        host_dt = g_date_time_new_now_utc();
        host_unix_time = g_date_time_to_unix(host_dt);
        g_date_time_unref(host_dt);

        if(pmu_unix_time - host_unix_time > 60 ||
            host_unix_time - pmu_unix_time > 60)
        {
            g_message("PMU time out of sync, send time sync command.");

            pcat_pmu_manager_date_time_sync(pmu_data);
        }
    }
    else
    {
        pmu_dt = g_date_time_new_utc(y, m, d, h, min, (gdouble)s);
        if(pmu_dt!=NULL)
        {
            pmu_unix_time = g_date_time_to_unix(pmu_dt);
            g_date_time_unref(pmu_dt);

            tv.tv_sec = pmu_unix_time;
            settimeofday(&tv, NULL);

            g_message("Read system time from PMU: %d-%d-%d %02d:%02d:%02d",
                y, m, d, h, min, s);
        }
        else
        {
            g_warning("Invalid system time from PMU: %d-%d-%d %02d:%02d:%02d",
                y, m, d, h, min, s);
        }

        pmu_data->system_time_set_flag = TRUE;
    }

    g_debug("PMU report battery voltage %u mV, charger voltage %u mV, "
        "GPIO input state %X, output state %X.", battery_voltage,
        charger_voltage, gpio_input, gpio_output);

    on_battery = (charger_voltage < 4200);

    if(!on_battery)
    {
        if(battery_voltage >= 4200)
        {
            battery_percentage = 100.0f;
        }
        else if(battery_voltage >= 3700)
        {
            battery_percentage = ((gdouble)battery_voltage - 3700) * 100 / 500;
        }
        else
        {
            battery_percentage = 0.0f;
        }
    }
    else
    {
        if(battery_voltage >= 4200)
        {
            battery_percentage = 100.0f;
        }
        else if(battery_voltage >= 4060)
        {
            battery_percentage = 90.0f +
                ((gdouble)battery_voltage - 4060) * 10 / 140;
        }
        else if(battery_voltage >= 3980)
        {
            battery_percentage = 80.0f +
                ((gdouble)battery_voltage - 3980) * 10 / 80;
        }
        else if(battery_voltage >= 3920)
        {
            battery_percentage = 70.0f +
                ((gdouble)battery_voltage - 3920) * 10 / 60;
        }
        else if(battery_voltage >= 3870)
        {
            battery_percentage = 60.0f +
                ((gdouble)battery_voltage - 3870) * 10 / 50;
        }
        else if(battery_voltage >= 3820)
        {
            battery_percentage = 50.0f +
                ((gdouble)battery_voltage - 3820) * 10 / 50;
        }
        else if(battery_voltage >= 3790)
        {
            battery_percentage = 40.0f +
                ((gdouble)battery_voltage - 3790) * 10 / 30;
        }
        else if(battery_voltage >= 3770)
        {
            battery_percentage = 30.0f +
                ((gdouble)battery_voltage - 3770) * 10 / 20;
        }
        else if(battery_voltage >= 3740)
        {
            battery_percentage = 20.0f +
                ((gdouble)battery_voltage - 3740) * 10 / 30;
        }
        else if(battery_voltage >= 3680)
        {
            battery_percentage = 10.0f +
                ((gdouble)battery_voltage - 3680) * 10 / 60;
        }
        else if(battery_voltage >= 3450)
        {
            battery_percentage = ((gdouble)battery_voltage - 3450) * 10 / 230;
        }
        else
        {
            battery_percentage = 0.0f;
        }
    }

    pmu_data->last_battery_voltage = battery_voltage;
    pmu_data->last_charger_voltage = charger_voltage;
    pmu_data->last_on_battery_state = on_battery;
    pmu_data->last_battery_percentage = battery_percentage * 100;

    fp = fopen(PCAT_PMU_MANAGER_STATEFS_BATTERY_PATH"/ChargePercentage", "w");
    if(fp!=NULL)
    {
        fprintf(fp, "%lf\n", battery_percentage);
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

static void pcat_pmu_serial_read_data_parse(PCatPMUManagerData *pmu_data)
{
    guint i;
    gsize used_size = 0, remaining_size;
    GByteArray *buffer = pmu_data->serial_read_buffer;
    guint16 expect_len, extra_data_len;
    const guint8 *p, *extra_data;
    guint16 checksum, rchecksum;
    guint16 command;
    guint8 src, dst;
    gboolean need_ack;
    guint16 frame_num;

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
                        pmu_data->serial_read_buffer, 0, used_size);
                }

                return;
            }

            if(p[9+expect_len]!=0x5A)
            {
                used_size = i;
                continue;
            }

            checksum = p[7+expect_len] + ((guint16)p[8+expect_len] << 8);
            rchecksum = pcat_pmu_serial_compute_crc16(p+1, 6+expect_len);

            if(checksum!=rchecksum)
            {
                g_warning("Serial port got incorrect checksum %X, "
                    "should be %X!", checksum ,rchecksum);

                i += 9 + expect_len;
                used_size = i + 1;
                continue;
            }

            src = p[1];
            dst = p[2];
            frame_num = p[3] + ((guint16)p[4] << 8);

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

            if(pmu_data->serial_write_current_command_data!=NULL)
            {
                if(pmu_data->serial_write_current_command_data->command + 1==
                    command &&
                    pmu_data->serial_write_current_command_data->frame_num==
                    frame_num)
                {
                    pcat_pmu_manager_command_data_free(
                        pmu_data->serial_write_current_command_data);
                    pmu_data->serial_write_current_command_data = NULL;
                }
            }

            if(dst==0x1 || dst==0x80 || dst==0xFF)
            {
                switch(command)
                {
                    case PCAT_PMU_MANAGER_COMMAND_STATUS_REPORT:
                    {
                        if(extra_data_len < 16)
                        {
                            break;
                        }

                        pcat_pmu_serial_status_data_parse(pmu_data,
                            extra_data, extra_data_len);

                        if(need_ack)
                        {
                            pcat_pmu_serial_write_data_request(pmu_data,
                                command+1, TRUE, frame_num, NULL, 0, FALSE);
                        }

                        break;
                    }
                    case PCAT_PMU_MANAGER_COMMAND_PMU_REQUEST_SHUTDOWN:
                    {
                        pcat_main_request_shutdown(FALSE);

                        if(need_ack)
                        {
                            pcat_pmu_serial_write_data_request(pmu_data,
                                command+1, TRUE, frame_num, NULL, 0, FALSE);
                        }

                        break;
                    }
                    case PCAT_PMU_MANAGER_COMMAND_HOST_REQUEST_SHUTDOWN_ACK:
                    {
                        if(pmu_data->shutdown_request)
                        {
                            pmu_data->shutdown_process_completed = TRUE;
                        }

                        break;
                    }
                    case PCAT_PMU_MANAGER_COMMAND_WATCHDOG_TIMEOUT_SET_ACK:
                    {
                        if(pmu_data->reboot_request)
                        {
                            pmu_data->reboot_process_completed = TRUE;
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
                            pcat_pmu_serial_write_data_request(pmu_data,
                                command+1, TRUE, frame_num, &state, 1, FALSE);
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
        g_byte_array_remove_range(pmu_data->serial_read_buffer, 0, used_size);
    }
}

static gboolean pcat_pmu_serial_read_watch_func(GIOChannel *source,
    GIOCondition condition, gpointer user_data)
{
    PCatPMUManagerData *pmu_data = (PCatPMUManagerData *)user_data;
    gssize rsize;
    guint8 buffer[4096];

    while((rsize=read(pmu_data->serial_fd, buffer, 4096))>0)
    {
        g_byte_array_append(pmu_data->serial_read_buffer, buffer, rsize);
        if(pmu_data->serial_read_buffer->len > 131072)
        {
            g_byte_array_remove_range(pmu_data->serial_read_buffer, 0,
                pmu_data->serial_read_buffer->len - 65536);
        }

        pcat_pmu_serial_read_data_parse(pmu_data);
    }

    return TRUE;
}

static gboolean pcat_pmu_serial_open(PCatPMUManagerData *pmu_data)
{
    PCatManagerMainConfigData *main_config_data;
    int fd;
    GIOChannel *channel;
    struct termios options;
    int rspeed = B115200;

    main_config_data = pcat_main_config_data_get();

    fd = open(main_config_data->pm_serial_device,
        O_RDWR | O_NOCTTY | O_NDELAY);
    if(fd < 0)
    {
        g_warning("Failed to open serial port %s: %s",
            main_config_data->pm_serial_device, strerror(errno));

        return FALSE;
    }

    switch(main_config_data->pm_serial_baud)
    {
        case 4800:
        {
            rspeed = B4800;
            break;
        }
        case 9600:
        {
            rspeed = B9600;
            break;
        }
        case 19200:
        {
            rspeed = B19200;
            break;
        }
        case 38400:
        {
            rspeed = B38400;
            break;
        }
        case 57600:
        {
            rspeed = B57600;
            break;
        }
        case 115200:
        {
            rspeed = B115200;
            break;
        }
        default:
        {
            g_warning("Invalid serial speed, set to default speed at %u.",
                115200);
            break;
        }
    }

    tcgetattr(fd, &options);
    cfmakeraw(&options);
    cfsetispeed(&options, rspeed);
    cfsetospeed(&options, rspeed);
    options.c_cflag &= ~CSIZE;
    options.c_cflag &= ~PARENB;
    options.c_cflag &= ~PARODD;
    options.c_cflag &= ~CSTOPB;
    options.c_cflag &= ~CRTSCTS;
    options.c_cflag |= CS8;
    options.c_cflag |= (CLOCAL | CREAD);
    options.c_iflag &= ~(IGNBRK | BRKINT | ICRNL |
        INLCR | PARMRK | INPCK | ISTRIP | IXON | IXOFF | IXANY);
    options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG | IEXTEN);
    options.c_oflag &= ~OPOST;
    options.c_cc[VMIN] = 1;
    options.c_cc[VTIME] = 0;
    tcflush(fd, TCIOFLUSH);
    tcsetattr(fd, TCSANOW, &options);

    channel = g_io_channel_unix_new(fd);
    if(channel==NULL)
    {
        g_warning("Cannot open channel for serial port %s!",
            main_config_data->pm_serial_device);
        close(fd);

        return FALSE;
    }
    g_io_channel_set_flags(channel, G_IO_FLAG_NONBLOCK, NULL);

    pmu_data->serial_fd = fd;
    pmu_data->serial_channel = channel;
    pmu_data->serial_write_current_command_data = NULL;
    pmu_data->serial_read_buffer = g_byte_array_new();
    pmu_data->serial_write_command_queue = g_queue_new();

    pmu_data->serial_read_source = g_io_add_watch(channel,
        G_IO_IN, pcat_pmu_serial_read_watch_func, pmu_data);

    g_message("Open PMU serial port %s successfully.",
        main_config_data->pm_serial_device);

    return TRUE;
}

static void pcat_pmu_serial_close(PCatPMUManagerData *pmu_data)
{
    if(pmu_data->serial_write_source > 0)
    {
        g_source_remove(pmu_data->serial_write_source);
        pmu_data->serial_write_source = 0;
    }

    if(pmu_data->serial_read_source > 0)
    {
        g_source_remove(pmu_data->serial_read_source);
        pmu_data->serial_read_source = 0;
    }

    if(pmu_data->serial_channel!=NULL)
    {
        g_io_channel_unref(pmu_data->serial_channel);
        pmu_data->serial_channel = NULL;
    }

    if(pmu_data->serial_fd > 0)
    {
        close(pmu_data->serial_fd);
        pmu_data->serial_fd = -1;
    }

    if(pmu_data->serial_write_current_command_data!=NULL)
    {
        pcat_pmu_manager_command_data_free(
            pmu_data->serial_write_current_command_data);
        pmu_data->serial_write_current_command_data = NULL;
    }
    if(pmu_data->serial_write_command_queue!=NULL)
    {
        g_queue_free_full(pmu_data->serial_write_command_queue,
            (GDestroyNotify)pcat_pmu_manager_command_data_free);
        pmu_data->serial_write_command_queue = NULL;
    }

    if(pmu_data->serial_read_buffer!=NULL)
    {
        g_byte_array_unref(pmu_data->serial_read_buffer);
        pmu_data->serial_read_buffer = NULL;
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
    PCatModemManagerDeviceType modem_device_type;
    guint shutdown_voltage = 0;

    if(pmu_data->serial_channel==NULL)
    {
        return TRUE;
    }

    now = g_get_monotonic_time();
    if(pmu_data->last_charger_voltage >= 4200)
    {
        pmu_data->charger_on_auto_start_last_timestamp = now;
    }

    if(!pmu_data->reboot_request && !pmu_data->shutdown_request)
    {
        pcat_pmu_serial_write_data_request(pmu_data,
            PCAT_PMU_MANAGER_COMMAND_HEARTBEAT, FALSE, 0, NULL, 0, FALSE);

        uconfig_data = pcat_main_user_config_data_get();
        if(uconfig_data->charger_on_auto_start)
        {
            if((pmu_data->power_on_event==3 || pmu_data->power_on_event==4) &&
               now > pmu_data->charger_on_auto_start_last_timestamp +
               (gint64)uconfig_data->charger_on_auto_start_timeout * 1000000L)
            {
                pcat_main_request_shutdown(TRUE);
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
                    pcat_main_request_shutdown(TRUE);
                    pmu_data->shutdown_planned = TRUE;
                }
            }

            g_date_time_unref(dt);
        }
    }

    config_data = pcat_main_config_data_get();

    modem_device_type = pcat_modem_manager_device_type_get();
    if(pmu_data->modem_device_type!=modem_device_type)
    {
        switch(modem_device_type)
        {
            case PCAT_MODEM_MANAGER_DEVICE_5G:
            {
                shutdown_voltage = config_data->pm_auto_shutdown_voltage_5g;
                break;
            }
            case PCAT_MODEM_MANAGER_DEVICE_GENERAL:
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

        pmu_data->modem_device_type = modem_device_type;
        pcat_pmu_manager_voltage_threshold_set_interval(pmu_data,
            0, 0, 0, 0, 0, shutdown_voltage, 0, 0);

        g_message("Detected modem type %u, set shutdown voltage to %u.",
            modem_device_type, shutdown_voltage);
    }

    if(pmu_data->serial_write_source==0 &&
       pmu_data->serial_write_current_command_data==NULL &&
       !g_queue_is_empty(pmu_data->serial_write_command_queue))
    {
        pmu_data->serial_write_source = g_io_add_watch(
            pmu_data->serial_channel, G_IO_OUT,
            pcat_pmu_serial_write_watch_func, pmu_data);
    }

    if(pmu_data->serial_write_source==0 &&
       pmu_data->serial_write_current_command_data!=NULL &&
        (pmu_data->serial_write_current_command_data->firstrun ||
        now > pmu_data->serial_write_current_command_data->timestamp +
        PCAT_PMU_MANAGER_COMMAND_TIMEOUT))
    {
        pmu_data->serial_write_source = g_io_add_watch(
            pmu_data->serial_channel, G_IO_OUT,
            pcat_pmu_serial_write_watch_func, pmu_data);
    }

    return TRUE;
}

gboolean pcat_pmu_manager_init()
{
    const PCatManagerMainConfigData *config_data;
    const PCatManagerUserConfigData *uconfig_data;

    if(g_pcat_pmu_manager_data.initialized)
    {
        return TRUE;
    }

    g_pcat_pmu_manager_data.shutdown_request = FALSE;
    g_pcat_pmu_manager_data.reboot_request = FALSE;
    g_pcat_pmu_manager_data.shutdown_process_completed = FALSE;
    g_pcat_pmu_manager_data.reboot_process_completed = FALSE;
    g_pcat_pmu_manager_data.charger_on_auto_start_last_timestamp =
        g_get_monotonic_time();
    g_pcat_pmu_manager_data.system_time_set_flag = FALSE;
    g_pcat_pmu_manager_data.power_on_event = 0;

    g_mkdir_with_parents(PCAT_PMU_MANAGER_STATEFS_BATTERY_PATH, 0755);

    if(!pcat_pmu_serial_open(&g_pcat_pmu_manager_data))
    {
        return FALSE;
    }

    g_pcat_pmu_manager_data.check_timeout_id = g_timeout_add_seconds(1,
        pcat_pmu_manager_check_timeout_func, &g_pcat_pmu_manager_data);

    g_pcat_pmu_manager_data.initialized = TRUE;

    pcat_pmu_manager_schedule_time_update_internal(&g_pcat_pmu_manager_data);
    pcat_pmu_manager_date_time_sync(&g_pcat_pmu_manager_data);

    config_data = pcat_main_config_data_get();
    uconfig_data = pcat_main_user_config_data_get();

    pcat_pmu_manager_charger_on_auto_start_internal(&g_pcat_pmu_manager_data,
        uconfig_data->charger_on_auto_start);

    pcat_pmu_manager_voltage_threshold_set_interval(&g_pcat_pmu_manager_data,
        0, 0, 0, 0, 0, config_data->pm_auto_shutdown_voltage_general, 0, 0);

    pcat_pmu_manager_pmu_fw_version_get_internal(&g_pcat_pmu_manager_data);

    pcat_pmu_manager_power_on_event_get_internal(&g_pcat_pmu_manager_data);

    pcat_pmu_manager_watchdog_timeout_set(5);

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

    pcat_pmu_serial_close(&g_pcat_pmu_manager_data);

    if(g_pcat_pmu_manager_data.pmu_fw_version!=NULL)
    {
        g_free(g_pcat_pmu_manager_data.pmu_fw_version);
        g_pcat_pmu_manager_data.pmu_fw_version = NULL;
    }

    g_pcat_pmu_manager_data.initialized = FALSE;
}

void pcat_pmu_manager_shutdown_request()
{
    pcat_pmu_serial_write_data_request(&g_pcat_pmu_manager_data,
        PCAT_PMU_MANAGER_COMMAND_HOST_REQUEST_SHUTDOWN,
        FALSE, 0, NULL, 0, TRUE);
    g_pcat_pmu_manager_data.shutdown_request = TRUE;
}

void pcat_pmu_manager_reboot_request()
{
    pcat_pmu_manager_watchdog_timeout_set(60);
    g_pcat_pmu_manager_data.reboot_request = TRUE;
}

gboolean pcat_pmu_manager_shutdown_completed()
{
    return g_pcat_pmu_manager_data.shutdown_process_completed;
}

gboolean pcat_pmu_manager_reboot_completed()
{
    return g_pcat_pmu_manager_data.reboot_process_completed;
}

void pcat_pmu_manager_watchdog_timeout_set(guint timeout)
{
    guint8 timeouts[3] = {60, 60, timeout};

    if(!g_pcat_pmu_manager_data.initialized)
    {
        return;
    }

    if(g_pcat_pmu_manager_data.serial_channel==NULL ||
        g_pcat_pmu_manager_data.serial_write_command_queue==NULL)
    {
        return;
    }

    pcat_pmu_serial_write_data_request(&g_pcat_pmu_manager_data,
        PCAT_PMU_MANAGER_COMMAND_WATCHDOG_TIMEOUT_SET, FALSE, 0,
        timeouts, 3, TRUE);
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

void pcat_pmu_manager_net_status_led_setup(guint on_time, guint down_time,
    guint repeat)
{
    if(!g_pcat_pmu_manager_data.initialized)
    {
        return;
    }

    pcat_pmu_manager_net_status_led_setup_internal(&g_pcat_pmu_manager_data,
        on_time, down_time, repeat);
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

