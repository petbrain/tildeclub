// for vasprintf:
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char log_filename[] = "/home/petbrain/public_html/tw.amw/test/visitors.amw";
//char log_filename[] = "visitors.amw";

extern char **environ;

char error_begin[] = "Status: 500\nContent-Type: application/json\n\n{\"status\": \"error\", \"description\": \"";
char error_end[] = "\"}\n";

void print_error(char* fmt, ...)
{
    fputs(error_begin, stdout);
    char* msg;
    va_list ap;
    va_start(ap);
    int msg_len = vasprintf(&msg, fmt, ap);
    va_end(ap);
    if (msg_len == -1) {
        fputs("Out of memory", stdout);
    } else {
        // escape double quotes and newlines for JSON output
        unsigned escaped_msg_len = msg_len;
        for(int i = 0; i < msg_len; i++) {
            char c = msg[i];
            if (c == '"' || c == '\n') {
                escaped_msg_len++;
            }
        }
        char escaped_msg[escaped_msg_len + 1];
        for(int i = 0, o = 0; i < msg_len; i++) {
            char c = msg[i];
            if (c == '"') {
                escaped_msg[o++] = '\\';
                escaped_msg[o++] = c;
            } else if (c == '\n') {
                escaped_msg[o++] = '\\';
                escaped_msg[o++] = 'n';
            } else {
                escaped_msg[o++] = c;
            }
        }
        escaped_msg[escaped_msg_len] = 0;
        fputs(escaped_msg, stdout);
        free(msg);
    }
    fputs(error_end, stdout);
}

int main(int argc, char* argv[])
{
    FILE* log = fopen(log_filename, "a");
    if (!log) {
        print_error("Cannot open %s", log_filename);
        return 0;
    }
    time_t t = time(NULL);
    struct tm* tm = gmtime(&t);
    if (tm == NULL) {
        print_error("localtime: %s", strerror(errno));
        return 0;
    }

    fprintf(log, "\n  - ts::isodate: %04d-%02d-%02dT%02d:%02d:%02dZ\n",
            tm->tm_year + 1900,
            tm->tm_mon + 1,
            tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
    fprintf(log, "    data:\n      type: log\n      content:\n");

    for (char** env = environ;;) {
        char* var = *env++;
        if (var == nullptr) {
            break;
        }
        char* delimiter = strchr(var, '=');
        char* value;
        unsigned key_len = 0;
        if (delimiter == nullptr) {
            value = "";
        } else {
            key_len = delimiter - var;
            value = delimiter + 1;
        }
        char key[key_len + 1];
        if (key_len) {
            strncpy(key, var, key_len);
        }
        key[key_len] = 0;
        fprintf(log, "        %s: %s\n", key, value);
    }
    fclose(log);

    puts("Status: 200\nContent-Type: application/json\n\n{\"status\": \"ok\"}\n");
    return 0;
}
