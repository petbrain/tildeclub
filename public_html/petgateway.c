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

typedef struct {
    char* name;
    PwResult (*func)(PwValuePtr args, PwValuePtr env);
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

PwResult log_visitor(PwValuePtr args, PwValuePtr env)
/*
 * Write entry to tw.myaw
 */
{
    PwValue result = PwMap(
        PwCharPtr("status"),  PwUnsigned(200),
        PwCharPtr("headers"), PwMap(PwCharPtr("Content-Type"), PwCharPtr("application/json")),
        PwCharPtr("content"), PwMap(PwCharPtr("status"), PwCharPtr("ok"))
    );
    pw_return_if_error(&result);

    // XXX need file lock here

    PwValue log_file = pw_file_open(log_filename, O_CREAT | O_WRONLY, 0644);
    pw_return_if_error(&log_file);

    PwValue pos = pw_file_seek(&log_file, 0, SEEK_END);
    pw_return_if_error(&log_file);

    if (pos.unsigned_value == 0) {
        // empty file, write header
        static char header[] = "channel:\n" \
                               "  file_id: 0\n" \
                               "  about: Visitors log\n" \
                               "\n" \
                               "items:\n";

        pw_expect_ok( pw_write_exact(&log_file, header, sizeof(header) - 1) );
    }

    // XXX PetWay needs decent date/time module

    time_t t = time(NULL);
    struct tm* tm = gmtime(&t);
    if (tm == NULL) {
        return PwErrno(errno);
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
        return PwError(PW_ERROR);
    }
    pw_expect_ok( pw_write_exact(&log_file, buf, n) );

    for (unsigned i = 0; i < PW_LENGTH(cgi_params_map); i++) {{
        PwValue value = pw_map_get(env, cgi_params_map[i].env_var_name);
        if (pw_error(&value)) {
            continue;
        }
        char* param_name = cgi_params_map[i].log_param_name;
        pw_expect_ok( pw_write_exact(&log_file, "        ", 8) );
        pw_expect_ok( pw_write_exact(&log_file, param_name, strlen(param_name)) );
        pw_expect_ok( pw_write_exact(&log_file, ": ", 2) );
        PW_CSTRING_LOCAL(val, &value);
        pw_expect_ok( pw_write_exact(&log_file, val, sizeof(val) - 1) );
        pw_expect_ok( pw_write_exact(&log_file, "\n", 1) );
    }}

    return pw_move(&result);
}

/****************************************************************
 * Get content: return HTML for endpoint
 */

PwResult get_content(PwValuePtr args, PwValuePtr env)
{
    PwValue result = log_visitor(args, env);
    pw_destroy(&result);

    result = PwMap(
        PwCharPtr("status"),  PwUnsigned(200),
        PwCharPtr("headers"), PwMap(PwCharPtr("Content-Type"), PwCharPtr("application/json")),
        PwCharPtr("content"), PwMap(PwCharPtr("status"), PwCharPtr("ok"))
    );
    pw_return_if_error(&result);

    PwValue content_filename = PwNull();
    PwValue referrer = pw_map_get(env, "HTTP_REFERER");
    if (pw_error(&referrer)) {
        content_filename = pw_create_string("404");
        pw_return_if_error(&content_filename);
    } else {
        // XXX strip base path instead of getting flat basename
        content_filename = pw_basename(&referrer);
        pw_return_if_error(&content_filename);
        if (pw_strlen(&content_filename) == 0) {
            pw_destroy(&content_filename);
            content_filename = pw_create_string("000");
            pw_return_if_error(&content_filename);
        }
    }
    pw_expect_true( pw_string_append(&content_filename, ".myaw") );
    PwValue content_dir = pw_create_string("/home/petbrain/content");
    pw_return_if_error(&content_dir);

    PwValue full_path = pw_path(&content_dir, &content_filename);
    pw_return_if_error(&full_path);

    PwValue title = PwNull();
    PwValue html = PwNull();

    PwValue file = pw_file_open(&full_path, O_RDONLY, 0);
    if (pw_error(&file)) {
        goto snafu;
    } else {
        PwValue page = mw_parse(&file);
        if (pw_error(&page)) {
            goto snafu;
        }
        title = pw_get(&page, "title");
        if (pw_error(&title)) {
            title = PwString();
        }
        html = pw_get(&page, "article", "html");
        if (pw_error(&html)) {
            goto snafu;
        }
    }
    goto done;

snafu:
    pw_destroy(&html);
    html = pw_create_string("<h1>Oops</h1><p>SNAFU</p>");

done:
    pw_expect_ok( pw_set(&html, &result, "content", "html") );
    pw_expect_ok( pw_set(&title, &result, "content", "title") );

    return pw_move(&result);
}

/****************************************************************
 * Get access log
 */

PwResult get_access_log(PwValuePtr args, PwValuePtr env)
/*
 * grep my entries from access log
 */
{
    PwValue result = PwMap(
        PwCharPtr("status"),  PwUnsigned(200),
        PwCharPtr("headers"), PwMap(PwCharPtr("Content-Type"), PwCharPtr("application/json")),
        PwCharPtr("content"), PwMap(PwCharPtr("status"), PwCharPtr("ok"))
    );
    pw_return_if_error(&result);

    int log_fd = open("/var/log/nginx/access.log", O_RDONLY);
    if (log_fd == -1) {
        return PwErrno(errno);
    }
    int my_fd = open("/home/petbrain/public_html/tw.myaw/test/nginx-access.log", O_CREAT | O_WRONLY, 0644);
    if (my_fd == -1) {
        close(log_fd);
        return PwErrno(errno);
    }

    // get records in reverse order, time limit is 30s

    // XXX it takes less than 30 seconds for full month log, rewrite this mess in a straightforward way.

    // XXX maybe save position for subsequent extraction, maybe extract daily

    off_t pos = lseek(log_fd, -0, SEEK_END);
    if (pos == -1) {
        close(my_fd);
        close(log_fd);
        return PwErrno(errno);
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
            return PwErrno(errno);
        }
        ssize_t bytes_read = read(log_fd, buf, sizeof(buf));
        if (bytes_read != sizeof(buf)) {
            close(my_fd);
            close(log_fd);
            return PwErrno(errno);
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

    return pw_move(&result);
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

PwResult pw_main()
/*
 * PetWay pw_main returns PwResult which is checked
 * by the caller, main() function.
 */
{
    PwValue env = pw_read_environment();
    pw_return_if_error(&env);

    // validate Content-Type

    PwValue content_type = pw_map_get(&env, "CONTENT_TYPE");
    pw_return_if_error(&content_type, "Missing Content-Type");
    if (!pw_equal(&content_type, "application/json")) {
        return pw_status(PW_ERROR, "Bad content type of request");
    }

    // get Content-Length

    PwValue content_length_str = pw_map_get(&env, "CONTENT_LENGTH");
    pw_return_if_error(&content_length_str, "Missing Content-Length");

    PwValue clen = pw_parse_number(&content_length_str);
    pw_return_if_error(&clen, "Bad content length of request");
    unsigned content_length;
    if (pw_is_signed(&clen) && 0 < clen.signed_value && clen.signed_value <= MAX_REQUEST_LENGTH) {
        content_length = clen.unsigned_value;
    } else if(pw_is_unsigned(&clen) && 0 < clen.unsigned_value && clen.unsigned_value <= MAX_REQUEST_LENGTH) {
        content_length = clen.signed_value;
    } else {
        return pw_status(PW_ERROR, "Bad content length of request");
    }

    // read stdin into string

    // XXX PetWay file needs concept of encoding, maybe

    char8_t* input_data = allocate(content_length + 1, false);
    if (!input_data) {
        return PwOOM();
    }
    unsigned bytes_read = 0;
    while (bytes_read < content_length) {
        ssize_t n = read(0, input_data + bytes_read, content_length - bytes_read);
        if (n == 0) {
            release((void**) &input_data, content_length + 1);
            return pw_status(PW_ERROR, "Premature end of input");
        }
        if (n > 0) {
            bytes_read += n;
        }
    }
    input_data[content_length] = 0;

    PwValue input = pw_create_string_io(input_data);
    release((void**) &input_data, content_length + 1);
    pw_return_if_error(&input);

    // parse input JSON

    PwValue args = mw_parse_json(&input);
    pw_return_if_error(&args);
    if (!pw_is_map(&args)) {
        return pw_status(PW_ERROR, "Bad arguments");
    }

    // args[0] is method

    PwValue method = pw_map_get(&args, "0");
    if (pw_error(&method)) {
        // it comes from javascript, give number a try
        pw_destroy(&method);
        method = pw_map_get(&args, 0);
        if (pw_error(&method)) {
            return pw_status(PW_ERROR, "Missing method argument");
        }
    }

    // call method

    PwValue result = PwNull();
    for (unsigned i = 0; i < PW_LENGTH(methods); i++) {
        if (pw_equal(&method, methods[i].name)) {
            result = methods[i].func(&args, &env);
            break;
        }
    }
    if (pw_is_null(&result)) {
        return pw_status(PW_ERROR, "Unknown method");
    }
    pw_return_if_error(&result);

    PwValue status = pw_map_get(&result, "status");
    pw_return_if_error(&status);
    if (!pw_is_int(&status)) {
        return pw_status(PW_ERROR, "Internal error: bad response status");
    }

    PwValue headers = pw_map_get(&result, "headers");
    pw_return_if_error(&headers);

    PwValue content = pw_map_get(&result, "content"); // content is optional

    // print response

    PwBufferedFileCtorArgs ctor_args = {
        .read_bufsize = 0,
        .write_bufsize = sys_page_size
    };
    PwValue output = pw_create2(PwTypeId_BufferedFile, &ctor_args);
    pw_return_if_error(&output);

    pw_expect_ok( pw_interface(output.type_id, File)->set_fd(&output, 1 /* stdout fd */, false) );

    // XXX PetWay still lacks string formatting and streaming
    char status_buf[48];
    int n = snprintf(status_buf, sizeof(status_buf), "Status: %u\n", (unsigned) status.unsigned_value);
    if (n < 0) {
        return PwError(PW_ERROR);
    }
    pw_write_exact(&output, status_buf, n);

    // no error handling since we started writing output
    // well, we could write something to stderr, but why?

    for (unsigned i = 0, n = pw_map_length(&headers); i < n; i++) {{
        PwValue key = PwNull();
        PwValue value = PwNull();
        if (pw_map_item(&headers, i, &key, &value)) {
            {
                PW_CSTRING_LOCAL(k, &key);
                pw_write_exact(&output, k, sizeof(k) - 1);
            }
            pw_expect_ok( pw_write_exact(&output, ": ", 2) );
            {
                PW_CSTRING_LOCAL(v, &value);
                pw_write_exact(&output, v, sizeof(v) - 1);
            }
            pw_write_exact(&output, "\n", 1);
        }
    }}
    pw_write_exact(&output, "\n", 1);
    pw_to_json_file(&content, 0, &output);
    return PwOK();
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

    PwValue desc = pw_typeof(status)->to_string(status);
    if (!pw_is_string(&desc)) {
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
    PwValue status = pw_main();
    if (pw_error(&status)) {
        critical_error(&status);
    }
    return 0;
}
