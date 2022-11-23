#include <curl/curl.h>
#include <jansson.h>
#include <jwt.h>
#include <sds/sds.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>

#define AUTH_ERROR "authorization_pending"
#define CODE_PROMPT "Please use this one-time passcode (OTP) to sign in to your account: "
#define CONFIG_FILE "/etc/pam_aad.conf"
#define DEBUG false
#define HOST "https://login.microsoftonline.com/"
#define RESOURCE "https://graph.microsoft.com/"
#define SUBJECT "Your one-time passcode for signing in via Azure Active Directory"
#define TTW 5                   /* time to wait in seconds */
#define USER_AGENT "azure_authenticator_pam/1.0"
#define USER_PROMPT "\n\nEnter the code at "

#ifndef _AAD_EXPORT
#define STATIC static
#else
#define STATIC
#endif

struct message {
    size_t lines_read;
    char *data[];
};

struct response {
    char *data;
    size_t size;
};

struct ret_data {
    char *u_code, *d_code, *verify_uri, *token;
};

STATIC size_t read_callback(void *ptr, size_t size, size_t nmemb,
                            void *userp)
{
    struct message *msg = (struct message *) userp;
    char *data;

    if ((size == 0) || (nmemb == 0) || ((size * nmemb) < 1)) {
        return 0;
    }
    data = msg->data[msg->lines_read];

    if (data) {
        size_t len = strlen(data);
        memcpy(ptr, data, len);
        msg->lines_read++;
        return len;
    }

    return 0;
}

STATIC size_t response_callback(void *contents, size_t size, size_t nmemb,
                                void *userp)
{
    size_t realsize = size * nmemb;
    struct response *resp = (struct response *) userp;
    char *ptr = realloc(resp->data, resp->size + realsize + 1);
    if (ptr == NULL) {
        // Out of memory
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    resp->data = ptr;
    memcpy(&(resp->data[resp->size]), contents, realsize);
    resp->size += realsize;
    resp->data[resp->size] = 0;

    return realsize;
}

STATIC char *get_date(void)
{
    char *date;
    int len = 56;
    struct tm *tm_info;
    time_t timer;

    date = (char *) malloc(len * sizeof(char));
    time(&timer);
    tm_info = localtime(&timer);
    /* RFC 822 POSIX time stamp */
    strftime(date, len, "Date: %a, %d %b %Y %H:%M:%S %z\r\n", tm_info);
    return date;
}

STATIC char *get_message_id(void)
{
    char domainname[64], hostname[64], msg_id[37], *message_id;
    int len = 192, ret;
    size_t i;
    uuid_t uuid;

    message_id = (char *) malloc(len * sizeof(char));
    uuid_generate(uuid);

    for (i = 0; i < sizeof(uuid); i++) {
        if (i == 0) {
            snprintf(msg_id, sizeof(msg_id) - strlen(msg_id), "%02x",
                     uuid[i]);
        } else if (i == 3 || i == 5 || i == 7 || i == 9) {
            snprintf(msg_id + strlen(msg_id),
                     sizeof(msg_id) - strlen(msg_id) + 1, "%02x-",
                     uuid[i]);
        } else {
            snprintf(msg_id + strlen(msg_id),
                     sizeof(msg_id) - strlen(msg_id), "%02x", uuid[i]);
        }
    }

    /* FIXME: Check for errors */
    ret = getdomainname(domainname, sizeof(domainname));

    /* FIXME: Check for errors */
    ret = gethostname(hostname, sizeof(hostname));

    (void) ret;

    snprintf(message_id, len, "Message-ID: <%s@%s.%s>\r\n", msg_id,
             hostname, domainname);

    return message_id;
}

STATIC int curl_log(CURL *handle, curl_infotype type, char *data, size_t size,
        void *userptr) {
    pam_handle_t *pamh = (pam_handle_t *)userptr;
    char *text;
    (void)handle;

    if (type != CURLINFO_TEXT)
        return 0;

    text = malloc(6 /* curl:  */ + size + 1 /* nul */);
    if (text == NULL) {
        pam_syslog(pamh, LOG_CRIT, "error allocating memory in curl debug function");
        return CURLE_OK;
    }

    strcpy(text, "curl: ");
    memcpy(text + 6, data, size);
    text[6 + size] = '\0';

    pam_syslog(pamh, LOG_DEBUG, text);
    free(text);
    return CURLE_OK;
}

STATIC json_t *curl(pam_handle_t *pamh, const char *endpoint, const char *post_body,
                    struct curl_slist * headers, bool debug)
{
    CURL *curl;
    CURLcode res;
    json_t *data = NULL;
    json_error_t error;

    struct response resp;

    resp.data = malloc(1);
    resp.size = 0;

    curl = curl_easy_init();
    if (curl == NULL) {
        pam_syslog(pamh, LOG_CRIT, "error initialising curl for oauth2 request");
        return NULL;
    }

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &resp);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
    if (headers)
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    if (debug) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, curl_log);
        curl_easy_setopt(curl, CURLOPT_DEBUGDATA, pamh);
    }

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        pam_syslog(pamh, LOG_CRIT, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
    } else {
        data = json_loads(resp.data, 0, &error);

        if (!data) {
            pam_syslog(pamh, LOG_CRIT, "json_loads() failed: %s\n", error.text);
        }
    }

    curl_easy_cleanup(curl);
    free(resp.data);

    return data;
}

STATIC int auth_bearer_request(pam_handle_t *pamh, struct ret_data *data, const
        char *client_id, const char *tenant, const char *device_code,
        bool debug)
{
    json_t *json_data;
    int ret = EXIT_FAILURE;

    sds endpoint = sdsnew(HOST);
    endpoint = sdscat(endpoint, tenant);
    endpoint = sdscat(endpoint, "/oauth2/v2.0/token");

    sds post_body = sdsnew("device_code=");
    post_body = sdscat(post_body, device_code);
    post_body = sdscat(post_body, "&client_id=");
    post_body = sdscat(post_body, client_id);
    post_body = sdscat(post_body, "&grant_type=urn:ietf:params:oauth:grant-type:device_code");

    for (;;) {
        nanosleep((const struct timespec[]) { {
                                               TTW, 0 }
                  }, NULL);
        json_data = curl(pamh, endpoint, post_body, NULL, debug);
        if (json_data == NULL) {
            pam_syslog(pamh, LOG_CRIT, "no data returned from token endpoint");
            goto out;
        }

        if (json_object_get(json_data, "access_token")) {
            data->token =
                strdup(json_string_value(json_object_get
                                  (json_data, "access_token")));
            json_decref(json_data);

            if (data->token == NULL) {
                pam_syslog(pamh, LOG_CRIT, "error allocating memory when retrieving access token");
                break;
            }

            ret = EXIT_SUCCESS;
            break;
        } else if (json_object_get(json_data, "error")) {
            const char *error =
                json_string_value(json_object_get(json_data, "error"));
            if (strcmp(error, AUTH_ERROR) != 0) {
            const char *desc =
                json_string_value(json_object_get(json_data, "error_description"));
                pam_syslog(pamh, LOG_CRIT, "error retrieving access token: %s %s", error, desc);
                json_decref(json_data);
                break;
            }
        } else {
            pam_syslog(pamh, LOG_CRIT, "invalid json when retrieving access token");
            json_decref(json_data);
            break;
        }

        json_decref(json_data);
    }

out:
    sdsfree(endpoint);
    sdsfree(post_body);
    return ret;
}

STATIC int oauth_request(pam_handle_t *pamh, struct ret_data *data, const char *client_id,
        const char *tenant, bool debug)
{
    json_t *json_data;
    int ret = EXIT_FAILURE;

    sds endpoint = sdsnew(HOST);
    endpoint = sdscat(endpoint, tenant);
    endpoint = sdscat(endpoint, "/oauth2/v2.0/devicecode");

    sds post_body = sdsnew("client_id=");
    post_body = sdscat(post_body, client_id);
    post_body = sdscat(post_body, "&scope=profile%20openid");

    json_data = curl(pamh, endpoint, post_body, NULL, debug);
    if (json_data == NULL) {
        pam_syslog(pamh, LOG_CRIT, "no data returned from devicecode endpoint");
        goto out;
    }

    if (json_object_get(json_data, "device_code")
        && json_object_get(json_data, "user_code")
        && json_object_get(json_data, "verification_uri")) {
        data->d_code =
            strdup(json_string_value(json_object_get(json_data, "device_code")));
        data->u_code =
            strdup(json_string_value(json_object_get(json_data, "user_code")));
        data->verify_uri =
            strdup(json_string_value(json_object_get(json_data, "verification_uri")));

        if (data->d_code && data->u_code && data->verify_uri) {
            ret = EXIT_SUCCESS;
        } else {
            pam_syslog(pamh, LOG_CRIT,
                    "error allocating memory retrieving device, user code or verification URL");
        }
    } else {
        pam_syslog(pamh, LOG_CRIT,
                "device_code, user_code or verification URL is missing from json response");
    }

    json_decref(json_data);
out:
    sdsfree(endpoint);
    sdsfree(post_body);
    return ret;
}

STATIC int verify_user(pam_handle_t *pamh, const char *token, const char *username, bool debug)
{
    int ret = EXIT_FAILURE;
    jwt_t *jwt;
    if (jwt_decode(&jwt, token, NULL, 0) < 0) {
        pam_syslog(pamh, LOG_CRIT, "decoding token failed");
        return EXIT_FAILURE;
    }

    const char *upn = jwt_get_grant(jwt, "unique_name");
    if (upn == NULL) {
        pam_syslog(pamh, LOG_CRIT, "decoding token failed");
        goto out;
    }


    if (strcmp(upn, username) == 0) {
        if (debug) {
            pam_syslog(pamh, LOG_DEBUG, "user %s successfully verified", username);
        }

        ret = EXIT_SUCCESS;
    } else {
        pam_syslog(pamh, LOG_WARNING, "logon user %s does not match credential user %s", username, upn);
    }

out:
    jwt_free(jwt);
    return ret;
}

STATIC int verify_group(pam_handle_t *pamh, const char *auth_token, const char *username, const char *group_id,
                        bool debug)
{
    json_t *resp;
    struct curl_slist *headers = NULL;
    int ret = EXIT_FAILURE;

    sds auth_header = sdsnew("Authorization: Bearer ");
    auth_header = sdscat(auth_header, auth_token);
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    sds endpoint = sdsnew(RESOURCE);
    endpoint = sdscat(endpoint, "v1.0/me/checkMemberGroups");

    sds post_body = sdsnew("{\"groupIds\":[\"");
    post_body = sdscat(post_body, group_id);
    post_body = sdscat(post_body, "\"]}");

    resp = curl(pamh, endpoint, post_body, headers, debug);
    if (resp == NULL) {
        pam_syslog(pamh, LOG_CRIT, "no data returned from group member check endpoint");
        goto out;
    }

    resp = json_object_get(resp, "value");

    if (resp) {
        size_t index;
        json_t *value;

        json_array_foreach(resp, index, value) {
            if (strcmp(json_string_value(value), group_id) == 0) {
                if (debug) {
                    pam_syslog(pamh, LOG_DEBUG, "successfully verfied that user %s is member of group %s", username, group_id);
                }

                ret = EXIT_SUCCESS;
                break;
            }
        }

        if (ret != EXIT_SUCCESS) {
            pam_syslog(pamh, LOG_WARNING, "user %s is not member of group %s", username, group_id);
        }
    } else {
        pam_syslog(pamh, LOG_CRIT, "json_object_get() failed: value NULL\n");
    }

    json_decref(resp);

out:
    curl_slist_free_all(headers);
    sdsfree(endpoint);
    sdsfree(auth_header);
    return ret;
}

STATIC int notify_user(pam_handle_t *pamh, const char *to_addr, const char *from_addr, const char *message, const char *smtp_server, bool debug)
{
    int ret = EXIT_FAILURE;
    CURL *curl;
    CURLcode res;
    int msg_len = 9;
    struct curl_slist *recipients = NULL;
    struct message *msg;

    sds to_str = sdsnew("To: ");
    to_str = sdscat(to_str, to_addr);
    to_str = sdscat(to_str, "\r\n");

    sds from_str = sdsnew("From: ");
    from_str = sdscat(from_str, from_addr);
    from_str = sdscat(from_str, "\r\n");

    sds msg_str = sdsempty();
    msg_str = sdscat(msg_str, message);
    msg_str = sdscat(msg_str, "\r\n");

    sds smtp_url = sdsempty();
    smtp_url = sdscat(smtp_url, "smtp://");
    smtp_url = sdscat(smtp_url, smtp_server);

    msg = malloc(sizeof(struct message) + (msg_len * sizeof(char *)));
    msg->lines_read = 0;

    msg->data[0] = get_date();
    msg->data[1] = to_str;
    msg->data[2] = from_str;
    msg->data[3] = get_message_id();
    msg->data[4] = "Subject: " SUBJECT "\r\n";
    msg->data[5] = "\r\n";
    msg->data[6] = msg_str;
    msg->data[7] = "\r\n";
    msg->data[8] = NULL;

    curl = curl_easy_init();
    if (curl == NULL) {
        pam_syslog(pamh, LOG_CRIT, "error initialising curl for user notification");
        goto out;
    }

    curl_easy_setopt(curl, CURLOPT_USE_SSL, (long) CURLUSESSL_ALL);
    curl_easy_setopt(curl, CURLOPT_URL, smtp_url);
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, from_addr);
    recipients = curl_slist_append(recipients, to_addr);
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    curl_easy_setopt(curl, CURLOPT_READDATA, msg);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

    if (debug) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, curl_log);
        curl_easy_setopt(curl, CURLOPT_DEBUGDATA, pamh);
    }

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        pam_syslog(pamh, LOG_CRIT, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
        goto out2;
    }

    ret = EXIT_SUCCESS;

out2:
    curl_slist_free_all(recipients);
    curl_easy_cleanup(curl);

out:
    free(msg->data[0]);
    free(msg->data[3]);
    free(msg);
    return ret;
}

STATIC int azure_authenticator(pam_handle_t * pamh, const char *user)
{
    bool debug = DEBUG;
    bool send_email = false;
    const char *client_id, *group_id, *tenant,
        *domain, *ab_token, *tenant_addr, *smtp_server;

    struct ret_data data;
    json_t *config = NULL;
    json_error_t error;
    int ret = EXIT_FAILURE;

    config = json_load_file(CONFIG_FILE, 0, &error);
    if (!config) {
        pam_syslog(pamh, LOG_CRIT, "error in config on line %d: %s\n", error.line,
                error.text);
        return ret;
    }

    if (json_object_get(config, "debug"))
        if (strcmp
            (json_string_value(json_object_get(config, "debug")),
             "true") == 0)
            debug = true;

    if (json_object_get(json_object_get(config, "client"), "id")) {
        client_id =
            json_string_value(json_object_get
                              (json_object_get(config, "client"), "id"));
    } else {
        pam_syslog(pamh, LOG_CRIT, "error with Client ID in JSON\n");
        return ret;
    }

    if (json_object_get(config, "domain")) {
        domain = json_string_value(json_object_get(config, "domain"));
    } else {
        pam_syslog(pamh, LOG_CRIT, "error with Domain in JSON\n");
        return ret;
    }

    if (json_object_get(json_object_get(config, "group"), "id")) {
        group_id =
            json_string_value(json_object_get
                              (json_object_get(config, "group"), "id"));
    } else {
        pam_syslog(pamh, LOG_CRIT, "error with Group ID in JSON\n");
        return ret;
    }

    if (json_object_get(config, "smtp_server")) {
        send_email = true;
        smtp_server =
            json_string_value(json_object_get(config, "smtp_server"));
    }

    if (json_object_get(config, "tenant")) {
        tenant =
            json_string_value(json_object_get
                              (json_object_get(config, "tenant"), "name"));

        if (send_email) {
            if (json_object_get(json_object_get(config, "tenant"), "address")) {
                tenant_addr =
                    json_string_value(json_object_get
                                      (json_object_get(config, "tenant"),
                                       "address"));
            } else {
                pam_syslog(pamh, LOG_CRIT, "error with tenant address in JSON\n");
                return ret;
            }
        }
    } else {
        pam_syslog(pamh, LOG_CRIT, "error with tenant in JSON\n");
        return ret;
    }

    sds user_addr = sdsnew(user);
    user_addr = sdscat(user_addr, "@");
    user_addr = sdscat(user_addr, domain);

    curl_global_init(CURL_GLOBAL_ALL);

    if (oauth_request(pamh, &data, client_id, tenant, debug) != EXIT_SUCCESS) {
        pam_syslog(pamh, LOG_CRIT, "request to devicecode endpoint failed");
        goto out_config;
    }

    sds prompt = sdsnew(CODE_PROMPT);
    prompt = sdscat(prompt, data.u_code);
    prompt = sdscat(prompt, USER_PROMPT);
    prompt = sdscat(prompt, data.verify_uri);

    if (send_email) {
        prompt = sdscat(prompt, ".");
        if (notify_user(pamh, user_addr, tenant_addr, prompt, smtp_server, debug) != EXIT_SUCCESS) {
            pam_syslog(pamh, LOG_CRIT, "notifying user failed");
            goto out_config;
        }
    } else {
        prompt = sdscat(prompt, ", then press enter.");
        (void) pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, NULL, "%s", prompt);
    }

    if (auth_bearer_request(pamh, &data, client_id, tenant, data.d_code,
                        debug) != EXIT_SUCCESS) {
        pam_syslog(pamh, LOG_CRIT, "request to token endpoint failed");
        goto out_config;
    }

    curl_global_cleanup();
    if (verify_user(pamh, data.token, user_addr, debug) == EXIT_SUCCESS
        && verify_group(pamh, data.token, user_addr, group_id, debug) == EXIT_SUCCESS) {
        ret = EXIT_SUCCESS;
    }

out_config:
    json_decref(config);
    free(data.token);
    free(data.d_code);
    free(data.u_code);
    free(data.verify_uri);

    return ret;
}


PAM_EXTERN int pam_sm_authenticate(pam_handle_t *
                                   pamh, int flags, int argc, const char
                                   **argv)
{
    const char *user;
    int ret = PAM_AUTH_ERR;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_CRIT, "pam_get_user(): failed to get a username\n");
        return ret;
    }

    if (azure_authenticator(pamh, user) == EXIT_SUCCESS)
        return PAM_SUCCESS;
    return ret;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t * pamh,
                              int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *
                                pamh, int flags,
                                int argc, const char **argv)
{
    return PAM_SUCCESS;
}
