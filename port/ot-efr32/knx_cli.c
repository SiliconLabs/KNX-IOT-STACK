/*******************************************************************************
 * # License
 * <b>Copyright 2024 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * License: MSLA
 *
 * The licensor of this software is Silicon Laboratories Inc.
 *
 * Your use of this software is governed by the terms of Silicon Labs Master
 * Software License Agreement (MSLA) available at
 *
 * https://www.silabs.com/about-us/legal/master-software-license-agreement
 *
 * This software is distributed to you in Source Code format and is governed by
 * the sections of the MSLA applicable to Source Code.
 *
 * By installing, copying or otherwise using this software, you agree to the
 * terms of the MSLA.
 *
 ******************************************************************************/

#include "oc_config.h"
#include "oc_core_res.h"
#include "api/oc_knx_dev.h"
#include "api/oc_knx_fp.h"
#include "api/oc_main.h"

#include "openthread/cli.h"

#include "sl_ot_custom_cli.h"

#define OC_ARRAY_LENGTH(aArray) (sizeof(aArray) / sizeof(aArray[0]))

#ifndef ARG_UNUSED
#define ARG_UNUSED(arg) (void)arg
#endif

#define KNX_STORAGE_HOSTNAME "dev_knx_hostname"
#define KNX_STORAGE_PM "dev_knx_pm"
#define KNX_STORAGE_PORT "dev_knx_port"

#define MAX_GA_PER_ENTRY 8

/*
 * KNX CLI dev subcommand processing.
 *
 * Usage: knx dev <dev subcommand args ...>
 *
 * See oc_knx_dev_commands[] for list of supported subcommands.
 */
static otError oc_knx_dev_sn(void *context, uint8_t argc, char *argv[])
{
    ARG_UNUSED(context);
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);

    oc_device_info_t *device = oc_core_get_device_info(0);

    otCliOutputFormat("%s\r\n", oc_string(device->serialnumber));

    return OT_ERROR_NONE;
}

static otError oc_knx_dev_hwv(void *context, uint8_t argc, char *argv[])
{
    ARG_UNUSED(context);
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);

    oc_device_info_t *device = oc_core_get_device_info(0);

    otCliOutputFormat("%d.%d.%d\r\n", device->hwv.major, device->hwv.minor, device->hwv.patch);

    return OT_ERROR_NONE;
}

static otError oc_knx_dev_hwt(void *context, uint8_t argc, char *argv[])
{
    ARG_UNUSED(context);
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);

    oc_device_info_t *device = oc_core_get_device_info(0);

    otCliOutputFormat("%s\r\n", oc_string(device->hwt));

    return OT_ERROR_NONE;
}

static otError oc_knx_dev_model(void *context, uint8_t argc, char *argv[])
{
    ARG_UNUSED(context);
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);

    oc_device_info_t *device = oc_core_get_device_info(0);

    otCliOutputFormat("%s\r\n", oc_string(device->model));

    return OT_ERROR_NONE;
}

static otError oc_knx_dev_sa(void *context, uint8_t argc, char *argv[])
{
    ARG_UNUSED(context);
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);

    oc_device_info_t *device = oc_core_get_device_info(0);

    otCliOutputFormat("%u\r\n", (uint8_t)((device->ia) >> 8));

    return OT_ERROR_NONE;
}

static otError oc_knx_dev_da(void *context, uint8_t argc, char *argv[])
{
    ARG_UNUSED(context);
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);

    oc_device_info_t *device = oc_core_get_device_info(0);

    otCliOutputFormat("%u\r\n", device->ia);

    return OT_ERROR_NONE;
}

static otError oc_knx_dev_hname(void *context, uint8_t argc, char *argv[])
{
    ARG_UNUSED(context);

    oc_device_info_t *device   = oc_core_get_device_info(0);
    oc_hostname_t    *hname_cb = oc_get_hostname_cb();

    if (argc < 1)
    {
        otCliOutputFormat("%s\r\n", oc_string(device->hostname));
        return OT_ERROR_NONE;
    }

    oc_core_set_device_hostname(0, argv[0]);
    oc_storage_write(KNX_STORAGE_HOSTNAME, (uint8_t *)oc_string(device->hostname), oc_string_len(device->hostname));

    if (hname_cb && hname_cb->cb)
    {
        hname_cb->cb(0, device->hostname, hname_cb->data);
    }

    return OT_ERROR_NONE;
}

static otError oc_knx_dev_fid(void *context, uint8_t argc, char *argv[])
{
    ARG_UNUSED(context);

    uint64_t          fid;
    oc_device_info_t *device = oc_core_get_device_info(0);

    if (argc < 1)
    {
        otCliOutputFormat("%llu\r\n", device->fid);
        return OT_ERROR_NONE;
    }

    fid = atoll(argv[0]);

    oc_core_set_device_fid(0, fid);
    oc_storage_write(KNX_STORAGE_FID, (uint8_t *)&fid, sizeof(fid));

    return OT_ERROR_NONE;
}

static otError oc_knx_dev_iid(void *context, uint8_t argc, char *argv[])
{
    ARG_UNUSED(context);

    uint64_t          iid;
    oc_device_info_t *device = oc_core_get_device_info(0);

    if (argc < 1)
    {
        otCliOutputFormat("%lu\r\n", device->iid);
        return OT_ERROR_NONE;
    }

    iid = atoll(argv[0]);

    oc_core_set_device_iid(0, iid);
    oc_storage_write(KNX_STORAGE_IID, (uint8_t *)&iid, sizeof(iid));

    return OT_ERROR_NONE;
}

static otError oc_knx_dev_lsm(void *context, uint8_t argc, char *argv[])
{
    ARG_UNUSED(context);

    oc_device_info_t *device = oc_core_get_device_info(0);

    if (argc > 0)
    {
        return OT_ERROR_INVALID_ARGS;
    }

    otCliOutputFormat("device state: %s\r\n", oc_core_get_lsm_state_as_string(device->lsm_s));

    return OT_ERROR_NONE;
}

static otError oc_knx_dev_ia(void *context, uint8_t argc, char *argv[])
{
    ARG_UNUSED(context);

    uint32_t          ia;
    oc_device_info_t *device = oc_core_get_device_info(0);

    if (argc < 1)
    {
        otCliOutputFormat("%u\r\n", device->ia);
        return OT_ERROR_NONE;
    }

    ia = atoi(argv[0]);

    oc_core_set_device_ia(0, ia);
    oc_storage_write(KNX_STORAGE_IA, (uint8_t *)&ia, sizeof(ia));

    return OT_ERROR_NONE;
}

static otError oc_knx_dev_port(void *context, uint8_t argc, char *argv[])
{
    ARG_UNUSED(context);

    uint32_t          port;
    oc_device_info_t *device = oc_core_get_device_info(0);

    if (argc < 1)
    {
        otCliOutputFormat("%u\r\n", device->port);
        return OT_ERROR_NONE;
    }

    device->port = atoi(argv[0]);
    oc_storage_write(KNX_STORAGE_PORT, (uint8_t *)&port, sizeof(port));

    return OT_ERROR_NONE;
}

static otCliCommand oc_knx_dev_commands[] = {
    {"sn", oc_knx_dev_sn},
    {"hwv", oc_knx_dev_hwv},
    {"hwt", oc_knx_dev_hwt},
    {"model", oc_knx_dev_model},
    {"sa", oc_knx_dev_sa},
    {"da", oc_knx_dev_da},
    {"hname", oc_knx_dev_hname},
    {"fid", oc_knx_dev_fid},
    {"iid", oc_knx_dev_iid},
    {"ia", oc_knx_dev_ia},
    {"port", oc_knx_dev_port},
    {"lsm", oc_knx_dev_lsm},
};

/*
 * KNX CLI got subcommand processing.
 *
 * Usage: knx got <got subcommand args ...>
 *
 * See oc_knx_got_commands[] for list of supported subcommands.
 */

static void format_group_addresses(char *buf, uint32_t *ga, int ga_len)
{
    size_t bufIndex = 0;

    buf[bufIndex++] = '[';
    for (size_t i = 0; i < ga_len - 1; ++i)
    {
        bufIndex += sprintf(&buf[bufIndex], "%u,", ga[i]);
    }
    sprintf(&buf[bufIndex], "%u]", ga[ga_len - 1]);
}

static int parse_group_addresses(const char *buf, uint32_t *ga, int max)
{
    int      ga_len      = 0;
    uint32_t temp        = 0;
    size_t   bufIndex    = 0;
    bool     after_comma = false;

    if (buf[bufIndex++] != '[')
    {
        return 0;
    }

    while (buf[bufIndex] && buf[bufIndex] != ']')
    {
        if (buf[bufIndex] >= '0' && buf[bufIndex] <= '9')
        {
            temp        = (temp * 10) + buf[bufIndex] - '0';
            after_comma = false;
        }
        else if (buf[bufIndex] == ',')
        {
            ga[ga_len] = temp;
            temp       = 0;
            ga_len += 1;
            after_comma = true;

            if (ga_len == max)
            {
                return ga_len;
            }
        }
        else if (buf[bufIndex] == ' ' && after_comma)
        {
            // Intentionally empty
        }
        else
        {
            return 0;
        }

        bufIndex++;
    }

    if (buf[bufIndex] == ']' && ga_len < max)
    {
        ga[ga_len] = temp;
        ga_len += 1;
    }

    return ga_len;
}

static otError add_or_edit_got_entry(void *context, bool add_only, uint8_t argc, char *argv[])
{
    ARG_UNUSED(context);

    oc_group_object_table_t entry;
    int                     index = 0;
    uint32_t                temp_ga[MAX_GA_PER_ENTRY];
    int                     id;
    int                     ga_len;

    if (argc < 4)
    {
        return OT_ERROR_INVALID_ARGS;
    }

    id    = atoi(argv[0]);
    index = find_empty_slot_in_group_object_table(id);

    if (add_only && oc_core_find_group_object_table_number_group_entries(index))
    {
        otCliOutputFormat("entry id already in use, set a different one or use the 'knx got edit' command\r\n");
        return OT_ERROR_INVALID_ARGS;
    }

    entry.id = id;
    oc_new_string(&entry.href, argv[1], strlen(argv[1]));
    entry.cflags = atoi(argv[2]);

    ga_len = parse_group_addresses(argv[3], temp_ga, MAX_GA_PER_ENTRY);

    if (ga_len == 0)
    {
        otCliOutputFormat("failed to parse group addresses\r\n");
        return OT_ERROR_INVALID_ARGS;
    }

    entry.ga_len = ga_len;
    entry.ga     = temp_ga;

    oc_core_set_group_object_table(index, entry);
    oc_dump_group_object_table_entry(index);
    oc_register_group_multicasts();

    oc_free_string(&entry.href);

    return OT_ERROR_NONE;
}

static otError oc_knx_got_edit(void *context, uint8_t argc, char *argv[])
{
    return add_or_edit_got_entry(context, /* add_only: */ false, argc, argv);
}

static otError oc_knx_got_add(void *context, uint8_t argc, char *argv[])
{
    return add_or_edit_got_entry(context, /* add_only: */ true, argc, argv);
}

static otError oc_knx_got_remove(void *context, uint8_t argc, char *argv[])
{
    int id;
    int index;

    if (argc < 1)
    {
        return OT_ERROR_INVALID_ARGS;
    }

    id    = atoi(argv[0]);
    index = find_empty_slot_in_group_object_table(id);

    if (index < 0)
    {
        otCliOutputFormat("entry with id: %u not found\r\n", id);
        return OT_ERROR_INVALID_ARGS;
    }

    oc_delete_group_object_table_entry(index);

    return OT_ERROR_NONE;
}

static otError oc_knx_got_print(void *context, uint8_t argc, char *argv[])
{
    oc_group_object_table_t *entry_ptr;
    char                     ga_buf[64];
    bool                     got_any = false;

    for (int i = 0; i < oc_core_get_group_object_table_total_size(); ++i)
    {
        entry_ptr = oc_core_get_group_object_table_entry(i);
        if (entry_ptr->ga_len > 0)
        {
            memset(ga_buf, 0, sizeof(ga_buf));
            format_group_addresses(ga_buf, entry_ptr->ga, entry_ptr->ga_len);

            otCliOutputFormat("[%2u]: %d %s %u %s\r\n",
                              i,
                              entry_ptr->id,
                              oc_string(entry_ptr->href),
                              entry_ptr->cflags,
                              ga_buf);
            got_any = true;
        }
    }

    if (!got_any)
    {
        otCliOutputFormat("no entries found\r\n");
    }

    return OT_ERROR_NONE;
}

static otCliCommand oc_knx_got_commands[] = {
    {"add", oc_knx_got_add},
    {"edit", oc_knx_got_edit},
    {"remove", oc_knx_got_remove},
    {"print", oc_knx_got_print},
};

/*
 * KNX CLI subcommand processing.
 *
 * Usage: knx help [subcommand]
 * Usage: knx dev <dev subcommand args ...>
 * Usage: knx got <got subcommand args ...>
 *
 * See oc_knx_commands[] for list of supported subcommands.
 */
static otError oc_knx_help_command(void *context, uint8_t argc, char *argv[]);

static otError oc_knx_dev_command(void *context, uint8_t argc, char *argv[])
{
    return processCommand(context, argc, argv, OC_ARRAY_LENGTH(oc_knx_dev_commands), oc_knx_dev_commands);
}

static otError oc_knx_got_command(void *context, uint8_t argc, char *argv[])
{
    return processCommand(context, argc, argv, OC_ARRAY_LENGTH(oc_knx_got_commands), oc_knx_got_commands);
}

static otError oc_knx_test_command(void *context, uint8_t argc, char *argv[])
{
#ifdef OC_USE_MULTICAST_SCOPE_2
    oc_do_s_mode_with_scope_no_check(2, "/p/o_1_1", "w");
#endif
    oc_do_s_mode_with_scope_no_check(5, "/p/o_1_1", "w");
    return OT_ERROR_NONE;
}
extern void    app_knx_init(void);
static otError oc_knx_init_command(void *context, uint8_t argc, char *argv[])
{
    otCliOutputFormat("Initializing KNX IOT Server\n");
    app_knx_init();
    return OT_ERROR_NONE;
}

static otCliCommand oc_knx_commands[] = {
    {"help", &oc_knx_help_command},
    {"dev", &oc_knx_dev_command},
    {"got", &oc_knx_got_command},
    {"test", &oc_knx_test_command},
    {"init", &oc_knx_init_command},
};

static otError oc_knx_help_command(void *context, uint8_t argc, char *argv[])
{
    ARG_UNUSED(context);
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);

    if (argc > 0 && strcmp(argv[0], "dev") == 0)
    {
        otCliOutputFormat("available knx dev subcommands:\r\n");
        printCommands(oc_knx_dev_commands, OC_ARRAY_LENGTH(oc_knx_dev_commands));
        otCliOutputFormat("command usage: knx dev <subcommand>\r\n");
    }
    else if (argc > 0 && strcmp(argv[0], "got") == 0)
    {
        if (argc > 1 && (strcmp(argv[1], "add") == 0 || strcmp(argv[1], "edit") == 0))
        {
            otCliOutputFormat("usage: knx got %s <id> <path> <cflags> [<ga>]\r\n", argv[1]);
            otCliOutputFormat("  <id>     - entry identifier\r\n");
            otCliOutputFormat("  <path>   - path\r\n");
            otCliOutputFormat("  <cflags> - flags\r\n");
            otCliOutputFormat("  <ga>     - comma-separated group addresses list , e.g [1,4,12]\r\n");
        }
        else if (argc > 1 && strcmp(argv[1], "remove") == 0)
        {
            otCliOutputFormat("usage: knx got remove <id> <path> <cflags> [<ga>]\r\n");
            otCliOutputFormat("  <id> - entry identifier\r\n");
        }
        else if (argc > 1 && strcmp(argv[1], "print") == 0)
        {
            otCliOutputFormat("print all the entries in the following format:\r\n");
            otCliOutputFormat("  <entry index>: <id> <path> <cflags> <group addresses>\r\n");
        }
        else
        {
            otCliOutputFormat("available knx got subcommands:\r\n");
            printCommands(oc_knx_got_commands, OC_ARRAY_LENGTH(oc_knx_got_commands));
            otCliOutputFormat("command usage: knx dev <subcommand>\r\n");
        }
    }
    else
    {
        otCliOutputFormat("available knx subcommands:\r\n");
        printCommands(oc_knx_commands, OC_ARRAY_LENGTH(oc_knx_commands));
        otCliOutputFormat("command usage: knx [help] <subcommand>\r\n");
    }

    return OT_ERROR_NONE;
}

/*
 * Top level KNX CLI command processing.
 *
 * Usage: knx <subcommand>
 *
 * See oc_knx_commands[] for list of supported subcommands.
 */
static otError oc_knx_command(void *context, uint8_t argc, char *argv[])
{
    otError error = processCommand(context, argc, argv, OC_ARRAY_LENGTH(oc_knx_commands), oc_knx_commands);

    if (error == OT_ERROR_INVALID_COMMAND)
    {
        (void)oc_knx_help_command(context, argc, argv);
    }

    return error;
}

/*
 * Top level KNX CLI registration
 */
otCliCommand sl_ot_custom_commands[] = {
    {"knx", oc_knx_command},
};

const uint8_t sl_ot_custom_commands_count = OC_ARRAY_LENGTH(sl_ot_custom_commands);

void otCliVendorSetUserCommands(void)
{
    otCliSetUserCommands(sl_ot_custom_commands, sl_ot_custom_commands_count, NULL);
}
