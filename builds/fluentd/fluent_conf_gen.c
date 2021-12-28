#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLUENT_CONF_FILE_NAME "fluent.conf"
#define FLUENT_ZEEK_LOGS_TAG_PREFIX "zeek."
#define FLUENT_POS_FILES_PATH "/var/log/fluent/tmp"

#define ZEEK_LOGS_PATH "/zeek-spool"
#define ZEEK_LOGS_PREFIX "json_streaming_"
#define ZEEK_LOGS_SUFFIX "*.log"

#define RABBITMQ_HOST "rabbitmq"
#define RABBITMQ_USER "admin"
#define RABBITMQ_PASS "pleasechangeme"
#define RABBITMQ_VHOST "/"
#define RABBITMQ_EXCHANGE "amq.direct"
#define RABBITMQ_EXCHANGE_TYPE "direct"

static const char *zeek_log_files[] = { "conn", "notice", "dns"};

void main(void)
{
    FILE* f = fopen(FLUENT_CONF_FILE_NAME, "w");
    if (f == NULL) {
        fprintf(stdout, "ERROR: could not open file %s: %s\n", FLUENT_CONF_FILE_NAME, strerror(errno));
        exit(1);
    }

    const size_t zeek_log_files_count = sizeof(zeek_log_files) / sizeof(zeek_log_files[0]);
    for (size_t i = 0; i < zeek_log_files_count; ++i) {
        const char* zeek_log_file = zeek_log_files[i];
        fprintf(f, "<source>\n");
        fprintf(f, "\t@type tail\n");
        fprintf(f, "\t@id zeek_json_%s\n", zeek_log_file);
        fprintf(f, "\ttag zeek.%s\n", zeek_log_file);
        fprintf(f, "\tpath %s/%s%s%s\n", ZEEK_LOGS_PATH, ZEEK_LOGS_PREFIX, zeek_log_file, ZEEK_LOGS_SUFFIX);
        fprintf(f, "\tpos_file %s/zeek_%s%s.pos\n", FLUENT_POS_FILES_PATH, ZEEK_LOGS_PREFIX, zeek_log_file);
        fprintf(f, "\tfollow_inodes true\n");
        fprintf(f, "\refresh_interval 10\n");
        fprintf(f, "\t<parse>\n");
        fprintf(f, "\t\t@type json\n");
        fprintf(f, "\t</parse>\n");
        fprintf(f, "</source>\n\n");
    }

    fprintf(f, "<match %s*>\n", FLUENT_ZEEK_LOGS_TAG_PREFIX);
    fprintf(f, "\t@type rabbitmq\n");
    fprintf(f, "\thost %s\n", RABBITMQ_HOST);
    fprintf(f, "\tuser %s\n", RABBITMQ_USER);
    fprintf(f, "\tpass %s\n", RABBITMQ_PASS);
    fprintf(f, "\tvhost %s\n", RABBITMQ_VHOST);
    fprintf(f, "\tformat json\n");
    fprintf(f, "\texchange %s\n", RABBITMQ_EXCHANGE);
    fprintf(f, "\texchange_type %s\n", RABBITMQ_EXCHANGE_TYPE);
    fprintf(f, "\texchange_durable false\n");
    fprintf(f, "\t<format>\n");
    fprintf(f, "\t\t@type json\n");
    fprintf(f, "\t</format>\n");
    fprintf(f, "</match>");


    fclose(f);
    fprintf(stdout, "INFO: Generated %s\n", FLUENT_CONF_FILE_NAME);
}
