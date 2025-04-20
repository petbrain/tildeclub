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

char log_filename[] = "/home/petbrain/public_html/tw.myaw/test/visitors.myaw";
//char log_filename[] = "visitors.myaw";

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
        // escape double quotes, backslashes, and newlines for JSON output
        for(int i = 0; i < msg_len; i++) {
            char c = msg[i];
            if (c == '"') {
                putchar('\\');
                putchar(c);
            } else if (c == '\\') {
                putchar('\\');
                putchar('\\');
            } else if (c == '\n') {
                putchar('\\');
                putchar('n');
            } else {
                putchar(c);
            }
        }
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
        fputs("        ", log);  // indent
        // print NAME=VALUE as NAME: VALUE
        for (;;) {
            char c = *var++;
            if (c == 0) {
                break;
            }
            if (c == '=') {
                fputc(':', log);
                fputc(' ', log);
            } else {
                fputc(c, log);
            }
        }
        fputc('\n', log);
    }
    fclose(log);

    puts("Status: 200\nContent-Type: application/json\n\n{\"status\": \"ok\"}\n");
    return 0;
}
