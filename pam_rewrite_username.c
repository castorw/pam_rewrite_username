#define MODULE_NAME   "pam_rewrite_username"

#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <string.h>

#if !defined(LOG_AUTHPRIV) && defined(LOG_AUTH)
#define LOG_AUTHPRIV LOG_AUTH
#endif

static void log_message(int priority, pam_handle_t *pamh, const char *format, ...) {
    char *service = NULL;
    if (pamh)
        pam_get_item(pamh, PAM_SERVICE, (void *) &service);
    if (!service)
        service = "";

    char logname[80];
    snprintf(logname, sizeof (logname), "%s(" MODULE_NAME ")", service);

    va_list args;
    va_start(args, format);
    openlog(logname, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
    vsyslog(priority, format, args);
    closelog();

    va_end(args);

    if (priority == LOG_EMERG) {
        exit(1);
    }
}

int rewrite_username(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL;
    const char *user_new = NULL;
    char *user_manipulation = NULL;

    int pgu_ret;

    pgu_ret = pam_get_user(pamh, &user, NULL);
    if (pgu_ret != PAM_SUCCESS || user == NULL) {
        return (PAM_IGNORE);
    }
    user_new = user;

    int i;
    for (i = 0; i < argc; i++) {
        if (strncmp("prefix=", argv[i], 7) == 0) {
            int new_length = strlen(argv[i]) - 7 + strlen(user_new) + 1;
            user_manipulation = malloc(new_length * sizeof (const char));
            snprintf(user_manipulation, new_length, "%s%s", argv[i] + 7, user_new);
            user_new = user_manipulation;
        } else if (strncmp("suffix=", argv[i], 7) == 0) {
            int new_length = strlen(argv[i]) - 7 + strlen(user_new) + 1;
            user_manipulation = malloc(new_length * sizeof (const char));
            snprintf(user_manipulation, new_length, "%s%s", user_new, argv[i] + 7);
            user_new = user_manipulation;
        }
    }

    if (strcmp(user, user_new) != 0) {
        log_message(LOG_INFO, pamh, "rewritten username %s to %s", user, user_new);
        pam_set_item(pamh, PAM_USER, user_new);
    }
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return rewrite_username(pamh, flags, argc, argv);
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_IGNORE;
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_IGNORE;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return rewrite_username(pamh, flags, argc, argv);
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return rewrite_username(pamh, flags, argc, argv);
}

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return rewrite_username(pamh, flags, argc, argv);
}