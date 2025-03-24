#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
//#include <cstdint>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <memory.h>
#include <stdint.h>
#include <pthread.h>
#include "netLinkKernelUtils.h"


//#define CFG_DEVICE "/dev/g3_fake_pci"
//#define MMIO_DEVICE "/dev/g3_fake_mmio"

// Define an enumeration for the type
typedef enum {
    CFG,
    MMIO
} msg_type_t;

struct kernel_msg {
    msg_type_t type;  // Use the enumeration instead of a string
    int is_write;
    unsigned long address;
    unsigned long value;
};

int send_netlink_msg_to_kernel(int sock_fd, char *msg, uint32_t msg_size, int nlmsg_type, uint16_t flags);
char* lread(int sock_fd, msg_type_t type, unsigned long address);
int lwrite(int sock_fd, msg_type_t type,unsigned long address, unsigned long value);
void open_cfg_registers(int sock_fd);
int doorbell_pci_ack = 0;
char kernel_reply[256];
int kernel_reply_length = 0;  // Variable to track the length of valid data

static void exit_userspace(int sock_fd){
    close(sock_fd);
}

uint32_t new_seq_no(){
    static uint32_t seq_no = 0 ;
    return seq_no++;
}

/*Return the number of bytes send to kernel*/
int send_netlink_msg_to_kernel(int sock_fd,char *msg, uint32_t msg_size, int nlmsg_type, uint16_t flags){
    /* The application needs to specify whom it is sending the msg over 
     * Netlink Protocol.
     * In this case, our application is interested in sending msg to kernel 
     * (Other options are : Other userspace applications).
     * Our application needs to specify the destination address - 
     * The kernel's address using dest-pid = 0.
     * In kernel, any kernel subsystem/module which has
     * opened the Netlink socket for protocol NETLINK_TEST_PROTOCOL 
     * as Netlink protocol will going to recieve this msg. */
    
     struct sockaddr_nl dest_addr;

     memset(&dest_addr, 0, sizeof(dest_addr));
     dest_addr.nl_family = AF_NETLINK;
     dest_addr.nl_pid = 0;    /* For Linux Kernel this is always Zero*/

    /* now, we need to send a Netlink msg to Linux kernel Module.
     * We need to take a memory space to accomodate 
     * Netlink Msg Hdr followed by payload msg.
     * */

     /* Always use the macro NLMSG_SPACE to calculate the size of Payload data. 
      * This macro will take care to do all necessary alignment*/

     //struct nlmsghdr *nlh=(struct nlmsghdr *)calloc(1, NLMSG_HDRLEN + NLMSG_SPACE(MAX_PAYLOAD));
     struct nlmsghdr *nlh = (struct nlmsghdr *)calloc(1, NLMSG_SPACE(msg_size));

     /* Fill the netlink message header fields*/
     /* size of the payload + padding + netlink header*/
     
     //nlh->nlmsg_len = NLMSG_HDRLEN + NLMSG_SPACE(MAX_PAYLOAD);
     nlh->nlmsg_len = NLMSG_SPACE(msg_size);
     nlh->nlmsg_pid = getpid();
     nlh->nlmsg_flags = flags;
     nlh->nlmsg_type = nlmsg_type;
     nlh->nlmsg_seq = new_seq_no();

     /* Fill in the netlink message payload */
     /* Copy the application data to Netlink payload space.
      * Use macro NLMSG_DATA to get ptr to netlink payload data
      * space*/
     //printf("Msg to send: %lx\n", msg);
     
     //strncpy(NLMSG_DATA(nlh), msg, msg_size);
     memcpy(NLMSG_DATA(nlh), msg, msg_size);
    
     /*Now, wrap the data to be send inside iovec*/
     /* iovector - It is a conatiner of netlink msg*/
     struct iovec iov; 

     iov.iov_base = (void *)nlh;
     iov.iov_len = nlh->nlmsg_len;

    /* Outermost msg sturucture which will be a container of iovec. 
     * This Outermost msg structure is required to support unified
     * interface of message exchange between kernel and user-space*/
     static struct msghdr outermsghdr;

    /*Now wrap the iovec inside the msghdr*/
     memset(&outermsghdr, 0, sizeof(struct msghdr));
     outermsghdr.msg_name = (void *)&dest_addr; /*Whom you are sending this msg to*/
     outermsghdr.msg_namelen = sizeof(dest_addr);
     outermsghdr.msg_iov = &iov;
     outermsghdr.msg_iovlen = 1;
     //printf("Msg size to send: %d\n", sizeof(&outermsghdr));
     int rc = sendmsg(sock_fd, &outermsghdr, 0);
     if(rc < 0){
        printf("Msg Sending Failed, error no = %d\n", errno);
     }    
     free(nlh); // Free the allocated memory
     return rc;
}

int create_netlink_socket(int protocol_number){
     /* Create a net link socket using usual socket() system call
      * When SOCK_RAW is used, Application has to pepare the struct msghdr
      * structure and send msg using sendmsg().
      * When SOCK_DGRAM is used, socket layer will take care to prepare struct
      * msghdr for you. You have to use sendto() in this case.
      * In this file, I have demonstrated SOCK_RAW case
      * */

    int sock_fd = socket(PF_NETLINK, SOCK_RAW, protocol_number);
    return sock_fd;
}

typedef struct thread_arg_{
    int sock_fd;
} thread_arg_t;

static void * _start_kernel_data_receiver_thread(void *arg){
    int rc = 0;
    struct iovec iov;
    struct nlmsghdr *nlh_recv = NULL;
    static struct msghdr outermsghdr;
    int sock_fd = 0;

    thread_arg_t *thread_arg = (thread_arg_t *)arg;
    sock_fd = thread_arg->sock_fd;

    /*Take a new buffer to recv data from kernel*/
    nlh_recv = (struct nlmsghdr *)calloc(1,
            NLMSG_HDRLEN + NLMSG_SPACE(MAX_PAYLOAD));
    
    do{
        /* Since, USA is receiving the msg from KS, so, just leave all
         * fields of nlmsghdr empty. they shall be filled by kernel
         * while delivering the msg to USA*/
        memset(nlh_recv, 0, NLMSG_HDRLEN + NLMSG_SPACE(MAX_PAYLOAD));
        
        iov.iov_base = (void *)nlh_recv;
        iov.iov_len = NLMSG_HDRLEN + NLMSG_SPACE(MAX_PAYLOAD);

        memset(&outermsghdr, 0, sizeof(struct msghdr));

        outermsghdr.msg_iov     = &iov;
        outermsghdr.msg_name    = NULL;
        outermsghdr.msg_iovlen  = 1;
        outermsghdr.msg_namelen = 0;

        /* Read message from kernel. Its a blocking system call 
         * Application execuation is suspended at this point 
         * and would not resume until it receives linux kernel
         * msg. We can configure recvmsg() to not to block, 
         * but lets use it in blocking mode for now */

        rc = recvmsg(sock_fd, &outermsghdr, 0);

        /* We have successfully received msg from linux kernel*/
        /* print the msg from kernel. kernel msg shall be stored 
         * in outermsghdr.msg_iov->iov_base
         * in same format : that is Netlink hdr followed by payload data*/
        nlh_recv = outermsghdr.msg_iov->iov_base;
        //printf("Reciving %u = %s\n", nlh_recv->nlmsg_type);

        if (nlh_recv->nlmsg_type & PCIE_TRANSACTION){
            doorbell_pci_ack = 1;
            char *payload = NLMSG_DATA(nlh_recv);
            memset(kernel_reply , 0 , sizeof(kernel_reply));
            kernel_reply_length = rc - NLMSG_HDRLEN;  // Set the length of valid data
            //snprintf(kernel_reply, sizeof(kernel_reply),"%s", payload);
            //strncpy(kernel_reply, payload, sizeof(kernel_reply) - 1);
            strncpy(kernel_reply, payload, kernel_reply_length);
            //printf("Reciving PCIE_TRANSACTION = %s\n", payload);

        }else{
            char *lpayload = NLMSG_DATA(nlh_recv);
            printf("Received Netlink msg from kernel, bytes recvd = %d\n", rc);
            printf("msg recvd from kernel = %s\n", lpayload);
        }
        // char *payload = NLMSG_DATA(nlh_recv);
        // printf("Received Netlink msg from kernel, bytes recvd = %d\n", rc);
        // printf("msg recvd from kernel = %s\n", payload);
    } while(1);
}

void start_kernel_data_receiver_thread(thread_arg_t *thread_arg){
    pthread_attr_t attr;
    pthread_t recv_pkt_thread;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&recv_pkt_thread, &attr,
            _start_kernel_data_receiver_thread,
            (void *)thread_arg);
}

char* lread(int sock_fd, msg_type_t type, unsigned long address){
    struct kernel_msg msg;
    doorbell_pci_ack = 0;
    int counter = 0;
    int success = -1;
    msg.type = type;
    msg.address = address;
    msg.value = 0;
    msg.is_write = 0;
    char buffer[sizeof(struct kernel_msg)];
    memcpy(buffer, &msg, sizeof(struct kernel_msg));
    success = send_netlink_msg_to_kernel(sock_fd,buffer,sizeof(buffer),PCIE_TRANSACTION,NLM_F_ACK);
    if(success > 0){
        while (doorbell_pci_ack == 0){
            if (counter > ((148204)*4)){ //If delays so much we need to skip the register
                printf("Timeout for read command trying to read 0x%x address\n", address);
                printf("Counter: %d \n", counter);
                break;
            }
            counter++;
        }
        if (kernel_reply_length > 0) {
                //printf("Read ACK: %s\n", kernel_reply);
                return kernel_reply;
        }
    }
return "0";
}

int lwrite(int sock_fd, msg_type_t type, unsigned long address, unsigned long value){
    struct kernel_msg msg;
    int counter = 0;
    int success = -1;
    msg.type = type;
    msg.address = address;
    msg.value = value;
    msg.is_write = 1;
    char buffer[sizeof(struct kernel_msg)];
    memcpy(buffer, &msg, sizeof(struct kernel_msg));
    success = send_netlink_msg_to_kernel(sock_fd,buffer,sizeof(buffer),PCIE_TRANSACTION,NLM_F_ECHO);
    if(success > 0){
        //printf("Write sent..\n");
        return 1;
    }
return 0;
}

void open_cfg_registers(int sock_fd){
    printf("Starting fuzzing from 0x0 to 0xfff for all CFG registers.. \n");
    for(int offset = 0x0; offset < 0x1fff; offset += 4){
        if(offset != 0x260 && offset != 0x278){ // Skipping problematic offsets
            char *current = lread(sock_fd, CFG, offset);
            lwrite(sock_fd, CFG, offset, 0xffffffff);
            char *after =  lread(sock_fd, CFG, offset);	 
            if (strcmp(current, after) != 0) {
                printf("Change detected at offset 0x%x, default 0x%s to 0x%s !!\n", offset,current, after);
            }else{
                printf("No changes in offset 0x%x, default 0x%s to 0x%s \n", offset, current, after);
            }
        }else{
            printf("Skipping offset 0x%x \n", offset);
        }
    }
    printf("Done!! \n");
}

int main(int argc, char **argv){
    int choice;
    int sock_fd;
    sock_fd = create_netlink_socket(NETLINK_TEST_PROTOCOL);
    
    if(sock_fd == -1){
        printf("Error : Netlink socket creation failed"
        ": error = %d\n", errno);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_nl src_addr;
    struct nlmsghdr *nlh = NULL;
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); 

    if(bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr)) == -1){
        printf("Error : Bind has failed\n");
        exit(1);
    }

    thread_arg_t thread_arg;
    thread_arg.sock_fd = sock_fd;

    start_kernel_data_receiver_thread(&thread_arg);
    while(1){
        //Main - Menu
        printf("Main-Menu\n");
        printf("\t1. Fuzzing CFG Space\n");
        printf("\t2. Fuzzing MMIO Space\n");
        printf("\t3. Get CFG open registers\n");
        printf("\t4. Exit\n");
        printf("choice ? ");
        scanf("%d", &choice);

        switch(choice){
            case 1:
                {
                    char user_msg[MAX_PAYLOAD];
                    memset(user_msg, "A", MAX_PAYLOAD);
                    if((fgets((char *)user_msg, MAX_PAYLOAD, stdin) == NULL)){
                        printf("error in reading from stdin\n");
                        exit(EXIT_FAILURE);
                    }
                    printf("Sending fuzz cfg msg.. \n");
                    send_netlink_msg_to_kernel(sock_fd,user_msg,sizeof(MAX_PAYLOAD),FUZZING_CFG_SPACE,NLM_F_ACK);
                    break;
                }
            case 2:
                {
                    char user_msg[MAX_PAYLOAD];
                    memset(user_msg, "A", MAX_PAYLOAD);
                    if((fgets((char *)user_msg, MAX_PAYLOAD, stdin) == NULL)){
                        printf("error in reading from stdin\n");
                        exit(EXIT_FAILURE);
                    }
                    send_netlink_msg_to_kernel(sock_fd,user_msg,sizeof(MAX_PAYLOAD),FUZZING_MMIO_SPACE,NLM_F_ACK);

                     break;
                }
            case 3:
                {
                    open_cfg_registers(sock_fd);
                    break;
                }
            case 4:
                {
                exit_userspace(sock_fd);
                exit(0);
                }
            break;
            default:
                printf("No valid selection\n");
                ;
        }
    }
    return 0;
}