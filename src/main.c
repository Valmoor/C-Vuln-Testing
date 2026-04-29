/*
 * Vulnerable C Application - FOR SECURITY TESTING ONLY
 * Contains intentional vulnerabilities for AppSec tool evaluation.
 *
 * Vulnerabilities present:
 *   - Buffer overflow (CWE-120)
 *   - Format string injection (CWE-134)
 *   - Command injection via system() (CWE-78)
 *   - Use of gets() (CWE-242)
 *   - Integer overflow (CWE-190)
 *   - Null pointer dereference (CWE-476)
 *   - Hardcoded credentials (CWE-798)
 *   - Use-after-free (CWE-416)
 *   - Stack-based buffer overflow in login
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* VULNERABILITY: Hardcoded credentials (CWE-798) */
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "SuperSecret123!"
#define DB_PASSWORD    "db_pass_prod_9x!@#"
#define API_KEY        "AKIAIOSFODNN7EXAMPLE_SECRET_KEY_1234567890"

/* VULNERABILITY: Fixed-size buffer prone to overflow (CWE-120) */
char global_buffer[64];

typedef struct {
    char username[32];
    int  is_admin;
    char token[16];
} User;

/* VULNERABILITY: Buffer overflow - no bounds check (CWE-120) */
void copy_username(char *dst, const char *src) {
    strcpy(dst, src);  /* unsafe strcpy */
}

/* VULNERABILITY: Format string injection (CWE-134) */
void log_message(char *user_input) {
    printf(user_input);  /* user input passed directly as format string */
    printf("\n");
}

/* VULNERABILITY: Command injection via system() (CWE-78) */
void ping_host(char *hostname) {
    char command[256];
    sprintf(command, "ping -c 1 %s", hostname);  /* no sanitisation */
    system(command);
}

/* VULNERABILITY: Use of gets() - unbounded input (CWE-242) */
void read_input_unsafe() {
    char buf[64];
    printf("Enter data: ");
    gets(buf);  /* deprecated and dangerous */
    printf("You entered: %s\n", buf);
}

/* VULNERABILITY: Integer overflow (CWE-190) */
int allocate_array(int count, int element_size) {
    int total = count * element_size;  /* can overflow before malloc */
    return total;
}

/* VULNERABILITY: Stack buffer overflow in authentication (CWE-121) */
int authenticate(const char *username, const char *password) {
    char local_user[16];
    char local_pass[16];

    /* No length check - classic stack smash */
    strcpy(local_user, username);
    strcpy(local_pass, password);

    if (strcmp(local_user, ADMIN_USERNAME) == 0 &&
        strcmp(local_pass, ADMIN_PASSWORD) == 0) {
        return 1;
    }
    return 0;
}

/* VULNERABILITY: Use-after-free (CWE-416) */
void use_after_free_demo() {
    User *u = (User *)malloc(sizeof(User));
    if (!u) return;

    strncpy(u->username, "testuser", sizeof(u->username) - 1);
    u->is_admin = 0;

    free(u);

    /* BUG: accessing freed memory */
    printf("Username after free: %s\n", u->username);
}

/* VULNERABILITY: Null pointer dereference (CWE-476) */
void process_user(User *u) {
    /* No NULL check before dereference */
    printf("Processing user: %s\n", u->username);
    if (u->is_admin) {
        printf("Admin access granted\n");
    }
}

/* VULNERABILITY: Path traversal (CWE-22) */
void read_file(char *filename) {
    char path[256];
    FILE *f;
    char line[512];

    /* No sanitisation of filename - allows ../../etc/passwd */
    snprintf(path, sizeof(path), "/var/app/data/%s", filename);
    f = fopen(path, "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            printf("%s", line);
        }
        fclose(f);
    }
}

/* VULNERABILITY: Insecure random number (CWE-338) */
int generate_token() {
    srand(42);       /* fixed seed - predictable */
    return rand();
}

int main(int argc, char *argv[]) {
    char input[32];

    printf("=== Vulnerable C App ===\n");
    printf("DB Password in use: %s\n", DB_PASSWORD);  /* leaks secret */

    /* VULNERABILITY: argv used directly in format string */
    if (argc > 1) {
        log_message(argv[1]);
    }

    /* Demo various vulnerable paths */
    if (argc > 2) {
        ping_host(argv[2]);
    }

    read_input_unsafe();

    printf("Token: %d\n", generate_token());

    /* Trigger null dereference */
    process_user(NULL);

    return 0;
}
