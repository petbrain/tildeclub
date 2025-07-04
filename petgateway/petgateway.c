/*
 * The main purpose of this app is to spot all PetWay flaws.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <myaw.h>
#include <pw.h>
#include <pw_parse.h>
#include <pw_to_json.h>

#define MAX_REQUEST_LENGTH  (1024 * 1024 * 1024)  // 1M

#define CONTENT_DIR "/home/petbrain/content"

typedef struct {
    char* name;
    [[nodiscard]] bool (*func)(PwValuePtr args, PwValuePtr env, PwValuePtr result);
    /*
     * `args` is arguments passed to the client-side `pgw_call` function.
     *
     * Method should return a map containing:
     *  - `status`: integer value
     *  - `headers`: map containing response headers
     *  - `content`: optional content
     *
     * On error it returns a status.
     */
} Method;


/****************************************************************
 * Log visitor
 */

char log_filename[] = "/home/petbrain/public_html/tw.myaw/test/visitors.myaw";
//char log_filename[] = "visitors.myaw";

typedef struct {
    char* env_var_name;
    char* log_param_name;
} CgiNameMap;

CgiNameMap cgi_params_map[] = {
    {"HTTP_COOKIE",     "cookie"},
    {"HTTP_REFERER",    "referrer"},
    {"HTTP_USER_AGENT", "user_agent"},
    {"REMOTE_ADDR",     "address"},
    {"REQUEST_SCHEME",  "scheme"},
    {"SERVER_NAME",     "server"},
    {"SERVER_PROTOCOL", "proto" }
};

[[nodiscard]] bool log_visitor(PwValuePtr args, PwValuePtr env, PwValuePtr result)
/*
 * Write entry to tw.myaw
 */
{
    if (!pw_map_va(result,
        PwCharPtr("status"),  PwUnsigned(200),
        PwCharPtr("headers"), pwva_map(PwCharPtr("Content-Type"), PwCharPtr("application/json")),
        PwCharPtr("content"), pwva_map(PwCharPtr("status"), PwCharPtr("ok"))
    )) {
        return false;
    }

    // XXX need file lock here

    PwValue log_file = PW_NULL;
    if (!pw_file_open(log_filename, O_CREAT | O_WRONLY, 0644, &log_file)) {
        return false;
    }

    off_t pos;
    if (!pw_file_seek(&log_file, 0, SEEK_END, &pos)) {
        return false;
    }

    if (pos == 0) {
        // empty file, write header
        static char header[] = "channel:\n" \
                               "  file_id: 0\n" \
                               "  about: Visitors log\n" \
                               "\n" \
                               "items:\n";

        if (!pw_write_exact(&log_file, header, sizeof(header) - 1)) {
            return false;
        }
    }

    // XXX PetWay needs decent date/time module

    time_t t = time(NULL);
    struct tm* tm = gmtime(&t);
    if (tm == NULL) {
        pw_set_status(PwErrno(errno));
        return false;
    }

    char buf[256];
    int n = snprintf(buf, sizeof(buf),
                     "\n" \
                     "  - ts::isodate: %04d-%02d-%02dT%02d:%02d:%02dZ\n" \
                     "    data:\n" \
                     "      type: log\n" \
                     "      content:\n",
                     tm->tm_year + 1900,
                     tm->tm_mon + 1,
                     tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
    if (n < 0) {
        pw_set_status(PwStatus(PW_ERROR));
        return false;
    }
    if (!pw_write_exact(&log_file, buf, n)) {
        return false;
    }

    for (unsigned i = 0; i < PW_LENGTH(cgi_params_map); i++) {{
        PwValue value = PW_NULL;
        if (!pw_map_get(env, cgi_params_map[i].env_var_name, &value)) {
            continue;
        }
        char* param_name = cgi_params_map[i].log_param_name;
        if (!pw_write_exact(&log_file, "        ", 8)) {
            return false;
        }
        if (!pw_write_exact(&log_file, param_name, strlen(param_name))) {
            return false;
        }
        if (!pw_write_exact(&log_file, ": ", 2)) {
            return false;
        }
        PW_CSTRING_LOCAL(val, &value);
        if (!pw_write_exact(&log_file, val, sizeof(val) - 1)) {
            return false;
        }
        if (!pw_write_exact(&log_file, "\n", 1)) {
            return false;
        }
    }}

    return true;
}

/****************************************************************
 * Get content: return HTML for endpoint
 */

[[nodiscard]] bool get_content(PwValuePtr args, PwValuePtr env, PwValuePtr result)
{
    if (!log_visitor(args, env, result)) {
        // ignore error
    }

    if (!pw_map_va(result,
        PwCharPtr("status"),  PwUnsigned(200),
        PwCharPtr("headers"), pwva_map(PwCharPtr("Content-Type"), PwCharPtr("application/json")),
        PwCharPtr("content"), pwva_map(PwCharPtr("status"), PwCharPtr("ok"))
    )) {
        return false;
    }

    PwValue content_filename = PW_NULL;
    PwValue referrer = PW_NULL;
    if (!pw_map_get(env, "HTTP_REFERER", &referrer)) {
        if (!pw_create_string("404", &content_filename)) {
            return false;
        }
    } else {
        // XXX strip base path instead of getting flat basename
        if (!pw_basename(&referrer, &content_filename)) {
            return false;
        }
        if (pw_strlen(&content_filename) == 0) {
            if (!pw_create_string("000", &content_filename)) {
                return false;
            }
        }
    }
    if (!pw_string_append(&content_filename, ".myaw")) {
        return false;
    }
    PwValue full_path = PW_NULL;
    if (!pw_path(&full_path, pwva(_pw_create_string_ascii, CONTENT_DIR), pw_clone(&content_filename))) {
        return false;
    }

    PwValue page = PW_NULL;
    PwValue title = PW_NULL;
    PwValue html = PW_NULL;
    PwValue file = PW_NULL;

    if (!pw_file_open(&full_path, O_RDONLY, 0, &file)) {
        return false;
    }
    if (!mw_parse(&file, &page)) {
        return false;
    }
    if (!pw_get(&title, &page, "title")) {
        title = PwString(0, {});
    }
    if (!pw_get(&html, &page, "article", "html")) {
        return false;
    }
    if (!pw_set(&html, result, "content", "html")) {
        return false;
    }
    if (!pw_set(&title, result, "content", "title")) {
        return false;
    }
    return true;
}

/****************************************************************
 * Get access log
 */

[[nodiscard]] bool get_access_log(PwValuePtr args, PwValuePtr env, PwValuePtr result)
/*
 * grep my entries from access log
 */
{
    if (!pw_map_va(result,
        PwCharPtr("status"),  PwUnsigned(200),
        PwCharPtr("headers"), pwva_map(PwCharPtr("Content-Type"), PwCharPtr("application/json")),
        PwCharPtr("content"), pwva_map(PwCharPtr("status"), PwCharPtr("ok"))
    )) {
        return false;
    }
    int log_fd = open("/var/log/nginx/access.log", O_RDONLY);
    if (log_fd == -1) {
        pw_set_status(PwErrno(errno));
        return false;
    }
    int my_fd = open("/home/petbrain/public_html/tw.myaw/test/nginx-access.log", O_CREAT | O_WRONLY, 0644);
    if (my_fd == -1) {
        close(log_fd);
        pw_set_status(PwErrno(errno));
        return false;
    }

    // get records in reverse order, time limit is 30s

    // XXX it takes less than 30 seconds for full month log, rewrite this mess in a straightforward way.

    // XXX maybe save position for subsequent extraction, maybe extract daily

    off_t pos = lseek(log_fd, -0, SEEK_END);
    if (pos == -1) {
        close(my_fd);
        close(log_fd);
        pw_set_status(PwErrno(errno));
        return false;
    }
    time_t start_time = time(NULL);
    char buf[1024];
    char prev_tail[1024];
    unsigned prev_tail_len = 0;
    char tail[1024];
    unsigned tail_len = 0;
    pos &= ~1023L;
    while (pos && (time(NULL) < (start_time + 30))) {
        pos -= sizeof(buf);
        if (lseek(log_fd, pos, SEEK_SET) == -1) {
            close(my_fd);
            close(log_fd);
            pw_set_status(PwErrno(errno));
            return false;
        }
        ssize_t bytes_read = read(log_fd, buf, sizeof(buf));
        if (bytes_read != sizeof(buf)) {
            close(my_fd);
            close(log_fd);
            pw_set_status(PwErrno(errno));
            return false;
        }
        char* lf = memchr(buf, '\n', sizeof(buf));
        if (!lf) {
            // line too long, restart
            tail_len = 0;
            continue;
        }
        lf++;
        if (tail_len) {
            memcpy(prev_tail, tail, tail_len);
        }
        prev_tail_len = tail_len;
        tail_len = lf - buf;
        if (tail_len) {
            memcpy(tail, buf, tail_len);
        }
        unsigned offset = tail_len;
        while (offset < sizeof(buf)) {
            char strbuf[2048];
            unsigned rem = sizeof(buf) - offset;
            lf = memchr(buf + offset, '\n', rem);
            if (!lf) {
                memcpy(strbuf, buf + offset, rem);
                if (prev_tail_len) {
                    memcpy(strbuf + rem, prev_tail, prev_tail_len);
                }
                strbuf[rem + prev_tail_len] = 0;
                if (strstr(strbuf, "GET /~petbrain/")) {
                    write(my_fd, strbuf, rem + prev_tail_len);
                }
                break;
            }
            lf++;
            unsigned len = (lf - buf) - offset;
            memcpy(strbuf, buf + offset, len);
            strbuf[len] = 0;
            if (strstr(strbuf, "GET /~petbrain/")) {
                write(my_fd, strbuf, len);
            }
            offset += len;
        }
    }
    close(my_fd);
    close(log_fd);

    return true;
}

/****************************************************************
 * Main functions
 */

// methods of pwgateway
Method methods[] = {
    { "log-visitor",    log_visitor },
    { "get-content",    get_content },
    { "get-access-log", get_access_log }
};

[[nodiscard]] bool pw_main()
{
    PwValue env = PW_NULL;
    if (!pw_read_environment(&env)) {
        return false;
    }

    // validate Content-Type

    PwValue content_type = PW_NULL;
    if (!pw_map_get(&env, "CONTENT_TYPE", &content_type)) {
        return false;
    }
    if (!pw_equal(&content_type, "application/json")) {
        pw_set_status(PwStatus(PW_ERROR), "Bad content type of request");
        return false;
    }

    // get Content-Length

    PwValue content_length_str = PW_NULL;
    if (!pw_map_get(&env, "CONTENT_LENGTH", &content_length_str)) {
        pw_set_status(PwStatus(PW_ERROR), "Missing Content-Length");
        return false;
    }

    PwValue clen = PW_NULL;
    if (!pw_parse_number(&content_length_str, &clen)) {
        pw_set_status(PwStatus(PW_ERROR), "Bad content length of request");
        return false;
    }
    unsigned content_length;
    if (pw_is_signed(&clen) && 0 < clen.signed_value && clen.signed_value <= MAX_REQUEST_LENGTH) {
        content_length = clen.unsigned_value;
    } else if(pw_is_unsigned(&clen) && 0 < clen.unsigned_value && clen.unsigned_value <= MAX_REQUEST_LENGTH) {
        content_length = clen.signed_value;
    } else {
        pw_set_status(PwStatus(PW_ERROR), "Bad content length of request");
        return false;
    }

    // read stdin into string

    // XXX PetWay file needs concept of encoding, maybe

    char8_t* input_data = allocate(content_length + 1, false);
    if (!input_data) {
        pw_set_status(PwStatus(PW_ERROR_OOM));
        return false;
    }
    unsigned bytes_read = 0;
    while (bytes_read < content_length) {
        ssize_t n = read(0, input_data + bytes_read, content_length - bytes_read);
        if (n == 0) {
            release((void**) &input_data, content_length + 1);
            pw_set_status(PwStatus(PW_ERROR), "Premature end of input");
            return false;
        }
        if (n > 0) {
            bytes_read += n;
        }
    }
    input_data[content_length] = 0;

    PwValue input = PW_NULL;
    bool ret = pw_create_string_io(input_data, &input);
    release((void**) &input_data, content_length + 1);
    if (!ret) {
        return false;
    }

    // parse input JSON

    PwValue args = PW_NULL;
    if (!mw_parse_json(&input, &args)) {
        return false;
    }
    if (!pw_is_map(&args)) {
        pw_set_status(PwStatus(PW_ERROR), "Bad arguments");
        return false;
    }

    // args["0"] is method

    PwValue method = PW_NULL;
    if (!pw_map_get(&args, "0", &method)) {
        pw_set_status(PwStatus(PW_ERROR), "Missing method argument");
        return false;
    }

    // call method

    PwValue result = PW_NULL;
    for (unsigned i = 0; i < PW_LENGTH(methods); i++) {
        if (pw_equal(&method, methods[i].name)) {
            if (!methods[i].func(&args, &env, &result)) {
                return false;
            }
            break;
        }
    }
    if (pw_is_null(&result)) {
        pw_set_status(PwStatus(PW_ERROR), "Unknown method");
        return false;
    }

    PwValue status = PW_NULL;
    if (!pw_map_get(&result, "status", &status)) {
        return false;
    }
    if (!pw_is_int(&status)) {
        pw_set_status(PwStatus(PW_ERROR), "Internal error: bad response status");
        return false;
    }

    PwValue headers = PW_NULL;
    PwValue content = PW_NULL;
    if (!pw_map_get(&result, "headers", &headers)) {
        return false;
    }
    if (!pw_map_get(&result, "content", &content)) {
        // content is optional
    }

    // print response

    PwBufferedFileCtorArgs ctor_args = {
        .read_bufsize = 0,
        .write_bufsize = sys_page_size
    };
    PwValue output = PW_NULL;
    if (!pw_create2(PwTypeId_BufferedFile, &ctor_args, &output)) {
        return false;
    }
    if (!pw_file_set_fd(&output, 1 /* stdout fd */, false)) {
        return false;
    }

    // XXX PetWay still lacks string formatting and streaming
    char status_buf[48];
    int n = snprintf(status_buf, sizeof(status_buf), "Status: %u\n", (unsigned) status.unsigned_value);
    if (n < 0) {
        pw_set_status(PwStatus(PW_ERROR));
    }
    if (!pw_write_exact(&output, status_buf, n)) {
        return false;
    }

    // no error handling since we started writing output
    // well, we could write something to stderr, but why?

    for (unsigned i = 0, n = pw_map_length(&headers); i < n; i++) {{
        PwValue key = PwNull();
        PwValue value = PwNull();
        if (pw_map_item(&headers, i, &key, &value)) {
            {
                PW_CSTRING_LOCAL(k, &key);
                if (!pw_write_exact(&output, k, sizeof(k) - 1)) {
                }
            }
            if (!pw_write_exact(&output, ": ", 2)) {
            }
            {
                PW_CSTRING_LOCAL(v, &value);
                if (!pw_write_exact(&output, v, sizeof(v) - 1)) {
                }
            }
            if (!pw_write_exact(&output, "\n", 1)) {
            }
        }
    }}
    if (!pw_write_exact(&output, "\n", 1)) {
    }
    if (!pw_to_json_file(&content, 0, &output)) {
    }
    return true;
}

void critical_error(PwValuePtr status)
/*
 * Output critical error described by `status` to stdout
 * using very basic functions.
 */
{
    static char error_begin[] = "Status: 500\nContent-Type: application/json\n\n{\"status\": \"error\", \"description\": \"";
    static char error_end[] = "\"}\n";

    fputs(error_begin, stdout);

    PwValue desc = PW_NULL;
    if (!pw_to_string(status, &desc)) {
        fputs("Out of memory", stdout);
        fputs(error_end, stdout);
        return;
    }
    // escape double quotes, backslashes, and newlines
    PW_CSTRING_LOCAL(desc_cstr, &desc);
    for(char* p = desc_cstr;;) {
        char c = *p++;
        if (c == 0) {
            break;
        }
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
    fputs(error_end, stdout);
}

int main(int argc, char* argv[])
/*
 * Main function initializes allocator, parses environment,
 * calls `pw_main`, and prints critical error if it happens.
 */
{
    init_allocator(&pet_allocator);
    if (!pw_main()) {
        critical_error(&current_task->status);
    }
    return 0;
}
