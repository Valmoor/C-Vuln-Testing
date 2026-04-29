/*
 * Vulnerable Network Server - FOR SECURITY TESTING ONLY
 *
 * Additional vulnerabilities:
 *   - Unbounded recv() into fixed buffer (CWE-120)
 *   - Hardcoded port and credentials
 *   - No input validation on protocol fields
 *   - Information disclosure in error messages (CWE-209)
 *   - Race condition / TOCTOU (CWE-362)
 *   - Insecure file permissions (CWE-732)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>

/* VULNERABILITY: Hardcoded secrets */
#define SERVER_SECRET  "jwt_secret_key_DO_NOT_SHARE_abc123xyz"
#define AWS_ACCESS_KEY "AKIAIOSFODNN7EXAMPLE"
#define AWS_SECRET_KEY "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
#define DB_CONN_STR    "postgresql://admin:prod_password_9812@db.internal:5432/appdb"

/* VULNERABILITY: No bounds on receive buffer */
void handle_client(int client_fd) {
    char buffer[256];
    int  n;

    /* Receives up to 4096 bytes into a 256-byte buffer */
    n = recv(client_fd, buffer, 4096, 0);
    if (n < 0) {
        /* VULNERABILITY: Exposes internal error details (CWE-209) */
        perror("recv failed - internal socket error details");
        return;
    }

    /* VULNERABILITY: Format string from network data */
    printf(buffer);

    send(client_fd, "OK\n", 3, 0);
    close(client_fd);
}

/* VULNERABILITY: TOCTOU race condition (CWE-362) */
int safe_open(const char *path) {
    if (access(path, R_OK) == 0) {
        /* Window between access() and open() allows race */
        return open(path, O_RDONLY);
    }
    return -1;
}

/* VULNERABILITY: Insecure temp file (CWE-377) */
void write_temp_data(const char *data) {
    char *tmpfile = tmpnam(NULL);  /* predictable temp name */
    FILE *f = fopen(tmpfile, "w");
    if (f) {
        fprintf(f, "%s", data);
        fclose(f);
        /* VULNERABILITY: World-readable permissions */
        chmod(tmpfile, 0777);
    }
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    printf("AWS Key: %s\n", AWS_ACCESS_KEY);  /* leaks key at startup */

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(8080);

    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(server_fd, 5);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&addr, &addrlen);
        handle_client(client_fd);
    }

    return 0;
}
