#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <memory.h>
#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>
#include "netLinkKernelUtils.h"

/* ============================================================================
 * CONFIGURATION & DEFINES
 * ============================================================================ */

#define DEFAULT_TIMEOUT_CYCLES  (148204 * 4)  // Timeout for read operations
#define KERNEL_REPLY_SIZE       256

/* ============================================================================
 * TYPE DEFINITIONS
 * ============================================================================ */

typedef enum {
    CFG,
    MMIO
} msg_type_t;

struct kernel_msg {
    msg_type_t type;
    int is_write;
    unsigned long address;
    unsigned long value;
};

typedef struct thread_arg_ {
    int sock_fd;
} thread_arg_t;

typedef struct {
    bool verbose;
    int timeout_cycles;
} app_config_t;

/* ============================================================================
 * GLOBAL VARIABLES
 * ============================================================================ */

static app_config_t g_config = {
    .verbose = false,
    .timeout_cycles = DEFAULT_TIMEOUT_CYCLES
};

static int doorbell_pci_ack = 0;
static char kernel_reply[KERNEL_REPLY_SIZE];
static int kernel_reply_length = 0;

/* ============================================================================
 * FORWARD DECLARATIONS
 * ============================================================================ */

int send_netlink_msg_to_kernel(int sock_fd, char *msg, uint32_t msg_size, int nlmsg_type, uint16_t flags);
int create_netlink_socket(int protocol_number);
void start_kernel_data_receiver_thread(thread_arg_t *thread_arg);
char* lread(int sock_fd, msg_type_t type, unsigned long address);
int lwrite(int sock_fd, msg_type_t type, unsigned long address, unsigned long value);
void open_cfg_registers(int sock_fd);
static void exit_userspace(int sock_fd);

/* ============================================================================
 * NETLINK INFRASTRUCTURE
 * ============================================================================ */

uint32_t new_seq_no() {
    static uint32_t seq_no = 0;
    return seq_no++;
}

static void exit_userspace(int sock_fd) {
    close(sock_fd);
}

int send_netlink_msg_to_kernel(int sock_fd, char *msg, uint32_t msg_size, int nlmsg_type, uint16_t flags) {
    struct sockaddr_nl dest_addr;
    struct nlmsghdr *nlh;
    struct iovec iov;
    static struct msghdr outermsghdr;

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;  /* For Linux Kernel this is always Zero */

    nlh = (struct nlmsghdr *)calloc(1, NLMSG_SPACE(msg_size));
    if (!nlh) {
        printf("Failed to allocate netlink message\n");
        return -ENOMEM;
    }

    /* Fill the netlink message header fields */
    nlh->nlmsg_len = NLMSG_SPACE(msg_size);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = flags;
    nlh->nlmsg_type = nlmsg_type;
    nlh->nlmsg_seq = new_seq_no();

    /* Copy the application data to Netlink payload space */
    memcpy(NLMSG_DATA(nlh), msg, msg_size);

    if (g_config.verbose) {
        printf("[DEBUG] Sending msg type=%d, size=%u, flags=0x%x\n", 
               nlmsg_type, msg_size, flags);
    }

    /* Wrap the data inside iovec */
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;

    /* Wrap the iovec inside the msghdr */
    memset(&outermsghdr, 0, sizeof(struct msghdr));
    outermsghdr.msg_name = (void *)&dest_addr;
    outermsghdr.msg_namelen = sizeof(dest_addr);
    outermsghdr.msg_iov = &iov;
    outermsghdr.msg_iovlen = 1;

    int rc = sendmsg(sock_fd, &outermsghdr, 0);
    if (rc < 0) {
        printf("Msg Sending Failed, error no = %d\n", errno);
    }

    free(nlh);
    return rc;
}

int create_netlink_socket(int protocol_number) {
    int sock_fd = socket(PF_NETLINK, SOCK_RAW, protocol_number);
    return sock_fd;
}

static void * _start_kernel_data_receiver_thread(void *arg) {
    int rc = 0;
    struct iovec iov;
    struct nlmsghdr *nlh_recv = NULL;
    static struct msghdr outermsghdr;
    int sock_fd = 0;

    thread_arg_t *thread_arg = (thread_arg_t *)arg;
    sock_fd = thread_arg->sock_fd;

    nlh_recv = (struct nlmsghdr *)calloc(1, NLMSG_HDRLEN + NLMSG_SPACE(MAX_PAYLOAD));

    do {
        memset(nlh_recv, 0, NLMSG_HDRLEN + NLMSG_SPACE(MAX_PAYLOAD));

        iov.iov_base = (void *)nlh_recv;
        iov.iov_len = NLMSG_HDRLEN + NLMSG_SPACE(MAX_PAYLOAD);

        memset(&outermsghdr, 0, sizeof(struct msghdr));
        outermsghdr.msg_iov = &iov;
        outermsghdr.msg_name = NULL;
        outermsghdr.msg_iovlen = 1;
        outermsghdr.msg_namelen = 0;

        /* Blocking receive - waits for kernel messages */
        rc = recvmsg(sock_fd, &outermsghdr, 0);

        nlh_recv = outermsghdr.msg_iov->iov_base;

        if (nlh_recv->nlmsg_type & PCIE_TRANSACTION) {
            doorbell_pci_ack = 1;
            char *payload = NLMSG_DATA(nlh_recv);
            memset(kernel_reply, 0, sizeof(kernel_reply));
            kernel_reply_length = rc - NLMSG_HDRLEN;
            strncpy(kernel_reply, payload, kernel_reply_length);

            if (g_config.verbose) {
                printf("[DEBUG] Received PCIE_TRANSACTION response: %s\n", payload);
            }
        } else {
            char *lpayload = NLMSG_DATA(nlh_recv);
            printf("Received Netlink msg from kernel, bytes recvd = %d\n", rc);
            printf("msg recvd from kernel = %s\n", lpayload);
        }
    } while (1);

    return NULL;
}

void start_kernel_data_receiver_thread(thread_arg_t *thread_arg) {
    pthread_attr_t attr;
    pthread_t recv_pkt_thread;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&recv_pkt_thread, &attr,
                   _start_kernel_data_receiver_thread,
                   (void *)thread_arg);
}

/* ============================================================================
 * OPERATION LAYER (READ/WRITE WITH TIMEOUT)
 * ============================================================================ */

char* lread(int sock_fd, msg_type_t type, unsigned long address) {
    struct kernel_msg msg;
    int counter = 0;
    int success = -1;

    doorbell_pci_ack = 0;

    msg.type = type;
    msg.address = address;
    msg.value = 0;
    msg.is_write = 0;

    char buffer[sizeof(struct kernel_msg)];
    memcpy(buffer, &msg, sizeof(struct kernel_msg));

    success = send_netlink_msg_to_kernel(sock_fd, buffer, sizeof(buffer), 
                                         PCIE_TRANSACTION, NLM_F_ACK);

    if (success > 0) {
        while (doorbell_pci_ack == 0) {
            if (counter > g_config.timeout_cycles) {
                printf("Timeout for read command trying to read 0x%lx address\n", address);
                if (g_config.verbose) {
                    printf("[DEBUG] Counter: %d\n", counter);
                }
                break;
            }
            counter++;
        }

        if (kernel_reply_length > 0) {
            return kernel_reply;
        }
    }

    return "0";
}

int lwrite(int sock_fd, msg_type_t type, unsigned long address, unsigned long value) {
    struct kernel_msg msg;
    int success = -1;

    msg.type = type;
    msg.address = address;
    msg.value = value;
    msg.is_write = 1;

    char buffer[sizeof(struct kernel_msg)];
    memcpy(buffer, &msg, sizeof(struct kernel_msg));

    success = send_netlink_msg_to_kernel(sock_fd, buffer, sizeof(buffer), 
                                         PCIE_TRANSACTION, NLM_F_ECHO);

    if (success > 0) {
        if (g_config.verbose) {
            printf("[DEBUG] Write sent successfully\n");
        }
        return 1;
    }

    return 0;
}

/* ============================================================================
 * FUZZING/TESTING FUNCTIONS
 * ============================================================================ */

void open_cfg_registers(int sock_fd) {
    printf("Starting fuzzing from 0x0 to 0xfff for all CFG registers..\n");
    
    for (int offset = 0x0; offset < 0x1fff; offset += 4) {
        if (offset != 0x260 && offset != 0x278) {  // Skip problematic offsets
            char *current = lread(sock_fd, CFG, offset);
            lwrite(sock_fd, CFG, offset, 0xffffffff);
            char *after = lread(sock_fd, CFG, offset);

            if (strcmp(current, after) != 0) {
                printf("Change detected at offset 0x%x, default 0x%s to 0x%s !!\n", 
                       offset, current, after);
            } else {
                printf("No changes in offset 0x%x, default 0x%s to 0x%s\n", 
                       offset, current, after);
            }
        } else {
            printf("Skipping offset 0x%x\n", offset);
        }
    }
    
    printf("Done!!\n");
}

void fuzz_cfg_space_kernel(int sock_fd) {
    char user_msg[MAX_PAYLOAD];
    memset(user_msg, 'A', MAX_PAYLOAD);
    
    printf("Sending CFG space fuzzing request to kernel..\n");
    send_netlink_msg_to_kernel(sock_fd, user_msg, sizeof(MAX_PAYLOAD), 
                               FUZZING_CFG_SPACE, NLM_F_ACK);
}

void fuzz_mmio_space_kernel(int sock_fd) {
    char user_msg[MAX_PAYLOAD];
    memset(user_msg, 'A', MAX_PAYLOAD);
    
    printf("Sending MMIO space fuzzing request to kernel..\n");
    send_netlink_msg_to_kernel(sock_fd, user_msg, sizeof(MAX_PAYLOAD), 
                               FUZZING_MMIO_SPACE, NLM_F_ACK);
}

/* ============================================================================
 * SOCKET INITIALIZATION
 * ============================================================================ */

int init_netlink_socket() {
    int sock_fd;
    struct sockaddr_nl src_addr;

    sock_fd = create_netlink_socket(NETLINK_TEST_PROTOCOL);
    if (sock_fd == -1) {
        printf("Error: Netlink socket creation failed: error = %d\n", errno);
        return -1;
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    if (bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr)) == -1) {
        printf("Error: Bind has failed\n");
        close(sock_fd);
        return -1;
    }

    if (g_config.verbose) {
        printf("[DEBUG] Netlink socket initialized successfully, fd=%d\n", sock_fd);
    }

    return sock_fd;
}

/* ============================================================================
 * CLI MODE (ONE-SHOT OPERATION)
 * ============================================================================ */

void print_usage(const char *prog_name) {
    printf("Usage:\n");
    printf("  %s                                    # Interactive mode\n", prog_name);
    printf("  %s <type> <address> [value]          # CLI mode\n\n", prog_name);
    printf("CLI Mode:\n");
    printf("  type       : cfg|mmio (register type)\n");
    printf("  address    : offset/address (hex or decimal)\n");
    printf("  value      : value to write (optional, hex or decimal)\n\n");
    printf("Options:\n");
    printf("  -v, --verbose    Enable verbose debug output\n");
    printf("  -h, --help       Show this help message\n\n");
    printf("Examples:\n");
    printf("  %s cfg 0x100              # Read CFG register at offset 0x100\n", prog_name);
    printf("  %s cfg 0x100 0xff         # Write 0xff to CFG register 0x100\n", prog_name);
    printf("  %s mmio 0x1000            # Read MMIO register at 0x1000\n", prog_name);
    printf("  %s                        # Start interactive mode\n", prog_name);
}

int cli_mode(int argc, char *argv[]) {
    struct kernel_msg msg;
    char *ltype;
    int sock_fd;

    if (argc < 3 || argc > 4) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    ltype = argv[1];

    if (strcmp(ltype, "cfg") == 0 || strcmp(ltype, "CFG") == 0) {
        msg.type = CFG;
    } else if (strcmp(ltype, "mmio") == 0 || strcmp(ltype, "MMIO") == 0) {
        msg.type = MMIO;
    } else {
        printf("Invalid type of message. Use 'cfg' or 'mmio'\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    msg.address = strtoul(argv[2], NULL, 0);
    msg.value = 0;
    msg.is_write = (argc == 4);

    if (msg.is_write) {
        msg.value = strtoul(argv[3], NULL, 0);
    }

    sock_fd = init_netlink_socket();
    if (sock_fd == -1) {
        return EXIT_FAILURE;
    }

    thread_arg_t thread_arg;
    thread_arg.sock_fd = sock_fd;
    start_kernel_data_receiver_thread(&thread_arg);

    /* Give receiver thread time to start */
    usleep(100000);  // 100ms

    if (msg.is_write) {
        printf("Writing 0x%lx to %s address 0x%lx\n", 
               msg.value, (msg.type == CFG) ? "CFG" : "MMIO", msg.address);
        int result = lwrite(sock_fd, msg.type, msg.address, msg.value);
        if (result) {
            printf("Write successful\n");
        } else {
            printf("Write failed\n");
        }
    } else {
        printf("Reading from %s address 0x%lx\n", 
               (msg.type == CFG) ? "CFG" : "MMIO", msg.address);
        char *value = lread(sock_fd, msg.type, msg.address);
        printf("Value: 0x%s\n", value);
    }

    exit_userspace(sock_fd);
    return EXIT_SUCCESS;
}

/* ============================================================================
 * INTERACTIVE MODE (MENU-DRIVEN)
 * ============================================================================ */

int interactive_mode() {
    int choice;
    int sock_fd;

    printf("\n=== G3 Fake Driver - Interactive Mode ===\n\n");

    sock_fd = init_netlink_socket();
    if (sock_fd == -1) {
        return EXIT_FAILURE;
    }

    thread_arg_t thread_arg;
    thread_arg.sock_fd = sock_fd;
    start_kernel_data_receiver_thread(&thread_arg);

    /* Give receiver thread time to start */
    usleep(100000);  // 100ms

    while (1) {
        printf("\n=== Main Menu ===\n");
        printf("  1. Fuzzing CFG Space (kernel-side)\n");
        printf("  2. Fuzzing MMIO Space (kernel-side)\n");
        printf("  3. Get CFG open registers (user-side)\n");
        printf("  4. Read Register\n");
        printf("  5. Write Register\n");
        printf("  6. Toggle Verbose Mode [%s]\n", g_config.verbose ? "ON" : "OFF");
        printf("  7. Exit\n");
        printf("choice ? ");

        if (scanf("%d", &choice) != 1) {
            printf("Invalid input\n");
            while (getchar() != '\n');  // Clear input buffer
            continue;
        }

        switch (choice) {
            case 1:
                fuzz_cfg_space_kernel(sock_fd);
                break;

            case 2:
                fuzz_mmio_space_kernel(sock_fd);
                break;

            case 3:
                open_cfg_registers(sock_fd);
                break;

            case 4: {
                char type_str[10];
                unsigned long address;
                printf("Enter type (cfg/mmio): ");
                scanf("%s", type_str);
                printf("Enter address (hex): ");
                scanf("%lx", &address);

                msg_type_t type = (strcmp(type_str, "mmio") == 0) ? MMIO : CFG;
                char *value = lread(sock_fd, type, address);
                printf("Value at 0x%lx: 0x%s\n", address, value);
                break;
            }

            case 5: {
                char type_str[10];
                unsigned long address, value;
                printf("Enter type (cfg/mmio): ");
                scanf("%s", type_str);
                printf("Enter address (hex): ");
                scanf("%lx", &address);
                printf("Enter value (hex): ");
                scanf("%lx", &value);

                msg_type_t type = (strcmp(type_str, "mmio") == 0) ? MMIO : CFG;
                int result = lwrite(sock_fd, type, address, value);
                if (result) {
                    printf("Write successful\n");
                } else {
                    printf("Write failed\n");
                }
                break;
            }

            case 6:
                g_config.verbose = !g_config.verbose;
                printf("Verbose mode: %s\n", g_config.verbose ? "ON" : "OFF");
                break;

            case 7:
                printf("Exiting...\n");
                exit_userspace(sock_fd);
                return EXIT_SUCCESS;

            default:
                printf("Invalid selection\n");
        }
    }

    return EXIT_SUCCESS;
}

/* ============================================================================
 * MAIN ENTRY POINT
 * ============================================================================ */

int main(int argc, char *argv[]) {
    /* Parse global options */
    int arg_start = 1;
    
    while (arg_start < argc && argv[arg_start][0] == '-') {
        if (strcmp(argv[arg_start], "-v") == 0 || strcmp(argv[arg_start], "--verbose") == 0) {
            g_config.verbose = true;
            printf("Verbose mode enabled\n");
            arg_start++;
        } else if (strcmp(argv[arg_start], "-h") == 0 || strcmp(argv[arg_start], "--help") == 0) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        } else {
            printf("Unknown option: %s\n", argv[arg_start]);
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    /* Adjust argc/argv to skip processed options */
    argc -= (arg_start - 1);
    argv += (arg_start - 1);

    /* Decide mode based on remaining arguments */
    if (argc == 1) {
        /* No arguments -> Interactive mode */
        return interactive_mode();
    } else {
        /* Arguments provided -> CLI mode */
        return cli_mode(argc, argv);
    }
}
