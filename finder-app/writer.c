#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Error: Missing arguments. Usage: %s <file path> <text string>\n", argv[0]);
        syslog(LOG_ERR, "Missing arguments. Usage: %s <file path> <text string>", argv[0]);
        return 1;
    }

    const char *writefile = argv[1];
    const char *writestr = argv[2];

    openlog("writer", LOG_PID, LOG_USER);

    FILE *fp = fopen(writefile, "w");
    if (fp == NULL) {
        printf("Error: Could not create or write to file %s\n", writefile);
        syslog(LOG_ERR, "Could not create or write to file %s", writefile);
        closelog();
        return 1;
    }

    if (fputs(writestr, fp) == EOF) {
        printf("Error: Failed to write to file %s\n", writefile);
        syslog(LOG_ERR, "Failed to write to file %s", writefile);
        fclose(fp);
        closelog();
        return 1;
    }

    syslog(LOG_DEBUG, "Writing %s to %s", writestr, writefile);

    fclose(fp);
    closelog();
    return 0;
}