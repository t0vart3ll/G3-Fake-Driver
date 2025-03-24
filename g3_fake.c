#include <linux/module.h>
#include <linux/netlink.h> 
#include <net/sock.h>  
#include <linux/string.h>  
#include <linux/kernel.h>  
#include "netLinkKernelUtils.h"
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/delay.h>

#define DRIVER_NAME "G3_Fake_Driver"
#define VENDOR_ID 0x8086  //CHANGE HERE!!
#define DEVICE_ID 0x5375  //CHANGE HERE!!

/*Global variables of this LKM*/
static struct sock *nl_sk = NULL;       /*Kernel space Netlink socket ptr*/
struct my_driver_priv *drv_priv;
unsigned long mmio_start,mmio_len;
bool sleep_enabled = true;

/* This is a "private" data structure */
/* You can store there any data that should be passed between driver's functions */
struct my_driver_priv {
    u8 __iomem *hwmem;
};

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

static struct pci_device_id pci_ids[] = {
    { PCI_DEVICE(VENDOR_ID, DEVICE_ID) },
    { 0, }
};

MODULE_DEVICE_TABLE(pci, pci_ids);

static int major;
static struct cdev cdev;
static struct class *cls;
static struct pci_dev *g3_fake_dev;

// Function prototypes
static int g3_fake_probe(struct pci_dev *dev, const struct pci_device_id *id);
static void g3_fake_remove(struct pci_dev *dev);
static void netlink_recv_msg_fn(struct sk_buff *skb_in);
static unsigned long dev_read(struct pci_dev *dev, struct kernel_msg msg);
static unsigned long dev_write(struct pci_dev *dev, struct kernel_msg msg);
void dbg_print_bar_info(struct pci_dev *dev);
void dbg_print_cfgdw(struct pci_dev *dev, u32 offset);
static void test_pci_config_space(struct pci_dev *dev, unsigned long start_addr, unsigned long end_addr);
static void test_mmio_space(struct pci_dev *dev, unsigned long start_addr, unsigned long end_addr);

static struct pci_driver g3_fake_driver = {
    .name = DRIVER_NAME,
    .id_table = pci_ids,
    .probe = g3_fake_probe,
    .remove = g3_fake_remove,
};

static struct file_operations fops = {
    .owner = THIS_MODULE,
};

static struct netlink_kernel_cfg cfg = {
    .input = netlink_recv_msg_fn, /*This fn would recieve msgs from userspace for
                                    Netlink protocol no 31*/
    /* There are other parameters of this structure*/
};   

static void netlink_recv_msg_fn(struct sk_buff *skb_in){
    struct nlmsghdr *nlh_recv, *nlh_reply;
    char *user_space_data;
    int user_space_data_len;
    struct sk_buff *skb_out;
    char kernel_reply[256];
    int user_space_process_port_id;
    int res;
    u32 kernel_reply_back = 0;

    printk(KERN_INFO "%s() invoked", __FUNCTION__);

    /*skb carries Netlink Msg which starts with Netlink Header*/
    nlh_recv = (struct nlmsghdr*)(skb_in->data);

    nlmsg_dump(nlh_recv);

    user_space_process_port_id = nlh_recv->nlmsg_pid;

    printk(KERN_INFO "%s(%d) : port id of the sending user space process = %u\n", 
            __FUNCTION__, __LINE__, user_space_process_port_id);

    user_space_data = (char*)nlmsg_data(nlh_recv);
    user_space_data_len = skb_in->len;

    printk(KERN_INFO "%s(%d) : msg recvd from user space= %s, skb_in->len = %d, nlh->nlmsg_len = %d\n", 
            __FUNCTION__, __LINE__, user_space_data, user_space_data_len, nlh_recv->nlmsg_len);
    
    if(nlh_recv->nlmsg_type == PCIE_TRANSACTION){
        struct kernel_msg parsed_data;
        memcpy(&parsed_data, nlmsg_data(nlh_recv), sizeof(struct kernel_msg));
        printk(KERN_INFO "%s(%d) : PCIE_TRANSACTION, type: %d, is_write?: %d, address: %x, value: %x\n", 
            __FUNCTION__, __LINE__, parsed_data.type , parsed_data.is_write, parsed_data.address, parsed_data.value);
        if(parsed_data.is_write){
            kernel_reply_back = dev_write(g3_fake_dev,parsed_data);
        }else{
            kernel_reply_back = dev_read(g3_fake_dev,parsed_data);
        }
    }else if(nlh_recv->nlmsg_type == FUZZING_CFG_SPACE){
        //struct kernel_msg parsed_data;
        //memcpy(&parsed_data, nlmsg_data(nlh_recv), sizeof(struct kernel_msg));
        printk(KERN_INFO "%s(%d) : Starting fuzzing in Config Space.. ;) \n", __FUNCTION__, __LINE__);
        test_pci_config_space(g3_fake_dev,0x0,0x1fff); //CHANGE HERE THE COVERAGE!!

    }else if(nlh_recv->nlmsg_type == FUZZING_MMIO_SPACE){
        //struct kernel_msg parsed_data;
        //memcpy(&parsed_data, nlmsg_data(nlh_recv), sizeof(struct kernel_msg));
        printk(KERN_INFO "%s(%d) : Starting fuzzing in MMIO Space.. ;) \n", __FUNCTION__, __LINE__);
        test_mmio_space(g3_fake_dev,0x0,0xff); //CHANGE HERE THE COVERAGE!!
    }
    if(nlh_recv->nlmsg_flags & NLM_F_ACK && nlh_recv->nlmsg_type == NLMSG_GREET){
        /*Sending reply back to user space process*/
        memset(kernel_reply, 0 , sizeof(kernel_reply));

        /*defined in linux/kernel.h */
        snprintf(kernel_reply, sizeof(kernel_reply), 
                "Msg from Process %d has been processed by kernel", nlh_recv->nlmsg_pid);

        /*Get a new sk_buff with empty Netlink hdr already appended before payload space
         * i.e skb_out->data will be pointer to below msg : 
         *
         * +----------+---------------+
         * |Netlink Hdr|   payload    |
         * ++---------+---------------+
         *
         * */

        skb_out = nlmsg_new(sizeof(kernel_reply), 0/*Related to memory allocation, skip...*/);

        /*Add a TLV*/ 
        nlh_reply = nlmsg_put(skb_out,
                0,                  /*Sender is kernel, hence, port-id = 0*/
                nlh_recv->nlmsg_seq,        /*reply with same Sequence no*/
                NLMSG_DONE,                 /*Metlink Msg type*/
                sizeof(kernel_reply),       /*Payload size*/
                0);                         /*Flags*/

        /* copy the paylod now. In userspace, use NLMSG_DATA, in kernel space
         * use nlmsg_data*/
        strncpy(nlmsg_data(nlh_reply), kernel_reply, sizeof(kernel_reply));

        /*Finaly Send the  msg to user space space process*/
        res = nlmsg_unicast(nl_sk, skb_out, user_space_process_port_id);

        if(res < 0){     
            printk(KERN_INFO "Error while sending the data back to user-space\n");
            kfree_skb(skb_out); /*free the internal skb_data also*/
        }                
    }
    if(nlh_recv->nlmsg_flags & NLM_F_ACK && nlh_recv->nlmsg_type == PCIE_TRANSACTION){
        printk(KERN_INFO "%s(%d) : PCIE_TRANSACTION, sending back response..\n", __FUNCTION__, __LINE__);
        memset(kernel_reply , 0 , sizeof(kernel_reply));
        snprintf(kernel_reply, sizeof(kernel_reply),"%x", kernel_reply_back);
        skb_out = nlmsg_new(sizeof(kernel_reply), 0/*Related to memory allocation, skip...*/);
        /*Add a TLV*/ 
        nlh_reply = nlmsg_put(skb_out,
                0,                  /*Sender is kernel, hence, port-id = 0*/
                nlh_recv->nlmsg_seq,        /*reply with same Sequence no*/
                NLMSG_DONE,                 /*Metlink Msg type*/
                sizeof(kernel_reply),       /*Payload size*/
                0);                         /*Flags*/

        strncpy(nlmsg_data(nlh_reply), kernel_reply, sizeof(kernel_reply));
        res = nlmsg_unicast(nl_sk, skb_out, user_space_process_port_id);
        if(res < 0){     
            printk(KERN_INFO "Error while sending the data back to user-space\n");
            kfree_skb(skb_out); /*free the internal skb_data also*/
        }                
    }
}

static int g3_fake_probe(struct pci_dev *dev, const struct pci_device_id *id) {
    int err;

    err = pci_enable_device(dev);
    if (err) {
        printk(KERN_ERR "Failed to enable PCI device\n");
        return err;
    }

    printk(KERN_INFO "%s(%d) : Function number: %d\n", __FUNCTION__, __LINE__, dev->devfn & 0x7);
    pci_request_regions( dev, DRIVER_NAME );
    dbg_print_bar_info( dev );
    
    printk(KERN_INFO "Enabling BME  \n"); 
    pci_set_master(dev);
    dbg_print_cfgdw(dev, PCI_COMMAND);

    // Check if the function number is 0
    if (PCI_FUNC(dev->devfn & 0x7) == 0x0) {
        g3_fake_dev = dev;
        printk(KERN_INFO "PCI function %d successfully assigned!\n", PCI_FUNC(dev->devfn));
        /* Get start and stop memory offsets */

        mmio_start = pci_resource_start(dev, 0); //Change here the bar number
        mmio_len = pci_resource_len(dev, 0); //Change here the bar number

        /* Allocate memory for the driver private data */
        drv_priv = kzalloc(sizeof(struct my_driver_priv), GFP_KERNEL);
        if (!drv_priv) {
            //release_device(pdev);
            return -ENOMEM;
        }
        /* Remap BAR to the local pointer */
        drv_priv->hwmem = ioremap(mmio_start, mmio_len);

        if (!drv_priv->hwmem) {
            printk(KERN_ERR "PCIe MMIO space null!\n", PCI_FUNC(dev->devfn));
            //release_device(dev);
            return -EIO;
        }else{
            printk(KERN_INFO "PCIe MMIO Space successfully assigned!\n");
            printk(KERN_INFO "PCIe MMIO Spac 0x%X - 0x%X!\n", mmio_start,mmio_len);
        }
        pci_set_drvdata(dev, drv_priv);
        printk(KERN_INFO "PCIe MMIO Space Base: 0x%x \n", drv_priv->hwmem);
    }
    return 0;
}

void dbg_print_bar_info(struct pci_dev *dev){
    
    int i;
    for(i=0; i<6; i++){
        if(pci_resource_len(dev,i)!=0){
            printk(KERN_INFO "BAR INFO BAR%d base: 0x%llx\tsize: 0x%llx\n", \
                    i,pci_resource_start(dev,i),pci_resource_len(dev,i)); 
        }
    }

}

void dbg_print_cfgdw(struct pci_dev *dev, u32 offset){

    int err ;
    u32 dw ;

    err = pci_bus_read_config_dword( dev->bus, dev->devfn, offset, &dw);

    if(err){
        printk(KERN_INFO "Error reading PCIe config space, error code: %d\n", err); 
    } else {
        printk(KERN_INFO "PCIe cfg addr 0x%03x : 0x%08x\n", offset, dw); 
    }

}

static void g3_fake_remove(struct pci_dev *dev) {
struct my_driver_priv *drv_priv = pci_get_drvdata(dev);
    if (drv_priv) {
        if (drv_priv->hwmem) {
            iounmap(drv_priv->hwmem);
        }
        pci_free_irq_vectors(dev);
        kfree(drv_priv);
    }
    pci_disable_device(dev);
	printk(KERN_INFO "PCI device disabled\n");
}

static unsigned long dev_read(struct pci_dev *dev, struct kernel_msg msg) {
    // unsigned long address;
    u32 value;
    if (msg.type == 0){ // cfg
        if (msg.address >= 0x1fff){
            printk(KERN_ERR "%s(%d) : Address out of CFG bounds: 0x%lx\n", __FUNCTION__, __LINE__, msg.address);
            return -EFAULT; //TODO: should we change this to 0x0?
        }
        pci_read_config_dword(g3_fake_dev, msg.address, &value);
        printk(KERN_INFO "%s(%d) : Readed address in CFG: 0x%x value: 0x%x\n", __FUNCTION__, __LINE__, msg.address, value); //TODO: Remove the comment, this is necesary for log
        return value;
    }
    else { // mmio
        if (msg.address >= mmio_len){
            printk(KERN_ERR "%s(%d) : Address out of bounds: 0x%lx\n", __FUNCTION__, __LINE__, drv_priv->hwmem + msg.address);
            return -EFAULT; //TODO: should we change this to 0x0?
        }
        value = ioread32(drv_priv->hwmem + msg.address);
        printk(KERN_INFO "%s(%d) : Readed address in MMIO: 0x%x value: 0x%x\n", __FUNCTION__, __LINE__, msg.address, value); //TODO: Remove the comment, this is necesary for log
        return value;
    }
}

static unsigned long dev_write(struct pci_dev *dev, struct kernel_msg msg) {
    if (msg.type == 0) { // cfg
        if (msg.address >= 0x1fff) {
                printk(KERN_ERR "%s(%d) : Address out of CFG bounds: 0x%lx\n", __FUNCTION__, __LINE__, msg.address);
                return -EFAULT; //TODO: should we change this to 0x0?
        }
        pci_write_config_dword(dev, msg.address, msg.value);
        printk(KERN_INFO "%s(%d) : Wrote value in CFG: 0x%x\n", __FUNCTION__, __LINE__, msg.value); //TODO: Remove the comment, this is necesary for log
        return 1;
    } else { // mmio
        if (msg.address >= mmio_len) {
            printk(KERN_ERR "%s(%d) : Address out of bounds: 0x%lx\n", __FUNCTION__, __LINE__, drv_priv->hwmem + msg.address);
            return -EFAULT; //TODO: should we change this to 0x0?
        }
        iowrite32(msg.value, drv_priv->hwmem + msg.address);
        printk(KERN_INFO "%s(%d) : Wrote value in MMIO: 0x%x\n", __FUNCTION__, __LINE__, msg.value); //TODO: Remove the comment, this is necesary for log
        return 1;
    }
}

// static struct kernel_msg sync_dev_read(struct pci_dev *dev, struct kernel_msg msg) {
//     // unsigned long address;
//     u32 value;
//     if (msg.type == 0){ // cfg
//         if (msg.address >= 0x1fff){
//             printk(KERN_ERR "%s(%d) : Address out of CFG bounds: 0x%lx\n", __FUNCTION__, __LINE__, msg.address);
//             return -EFAULT; //TODO: should we change this to 0x0?
//         }
//         pci_read_config_dword(g3_fake_dev, msg.address, &value);
//         printk(KERN_INFO "%s(%d) : Readed address in CFG: 0x%x value: 0x%x\n", __FUNCTION__, __LINE__, msg.address, value);
//         return value;
//     }
//     else { // mmio
//         if (msg.address >= mmio_len){
//             printk(KERN_ERR "%s(%d) : Address out of bounds: 0x%lx\n", __FUNCTION__, __LINE__, drv_priv->hwmem + msg.address);
//             return -EFAULT; //TODO: should we change this to 0x0?
//         }
//         value = ioread32(drv_priv->hwmem + msg.address);
//         printk(KERN_INFO "%s(%d) : Readed address in MMIO: 0x%x value: 0x%x\n", __FUNCTION__, __LINE__, msg.address, value);
//         return value;
//     }
// }

// static struct kernel_msg sync_dev_write(struct pci_dev *dev, struct kernel_msg msg) {
//     if (msg.type == 0) { // cfg
//         if (msg.address >= 0x1fff) {
//                 printk(KERN_ERR "%s(%d) : Address out of CFG bounds: 0x%lx\n", __FUNCTION__, __LINE__, msg.address);
//                 return -EFAULT; //TODO: should we change this to 0x0?
//         }
//         pci_write_config_dword(dev, msg.address, msg.value);
//         printk(KERN_INFO "%s(%d) : Wrote value in CFG: 0x%x\n", __FUNCTION__, __LINE__, msg.value);
//         return 1;
//     } else { // mmio
//         if (msg.address >= mmio_len) {
//             printk(KERN_ERR "%s(%d) : Address out of bounds: 0x%lx\n", __FUNCTION__, __LINE__, drv_priv->hwmem + msg.address);
//             return -EFAULT; //TODO: should we change this to 0x0?
//         }
//         iowrite32(msg.value, drv_priv->hwmem + msg.address);
//         printk(KERN_INFO "%s(%d) : Wrote value in MMIO: 0x%x\n", __FUNCTION__, __LINE__, msg.value);
//         return 1;
//     }
// }

static void test_pci_config_space(struct pci_dev *dev, unsigned long start_addr, unsigned long end_addr) {
    struct kernel_msg msg;
    u32 original_value, test_value , AERU, AERC;
    unsigned long addr;
    // //Read local AER
    // msg.type = CFG;
    // msg.is_write = 0;
    // msg.address = 0x104; //AER Uncorrectable Error Status
    // AERU = dev_read(dev, msg);
    // //Read local AER
    // msg.type = CFG;
    // msg.is_write = 0;
    // msg.address = 0x110; //AER Correctable Error Status
    // AERC = dev_read(dev, msg);

    printk(KERN_INFO "Testing PCI configuration space for device %s from 0x%lx to 0x%lx\n", pci_name(dev), start_addr, end_addr);
    //printk(KERN_INFO "Initial AER Uncorrectable Error Status: 0x%lx\n", AERU);
    //printk(KERN_INFO "Initial AER Correctable Error Status:   0x%lx\n", AERC);

    // Iterate through each 4-byte register in the specified range of the PCI configuration space
    for (addr = start_addr; addr <= end_addr; addr += 4) {
        if(addr != 0x260 && addr != 0x278){
            // Read the original value of the register
            msg.type = CFG;
            msg.is_write = 0;
            msg.address = addr;
            original_value = dev_read(dev, msg);

            // Write 0xFFFFFFFF to the register
            msg.is_write = 1;
            msg.value = 0xFFFFFFFF;
            dev_write(dev, msg);
            
            msg.is_write = 0;
            test_value = dev_read(dev, msg);
            
            // Print the results
            if (original_value != test_value) {
                printk(KERN_ERR "Change detected at offset 0x%lx, default 0x%08x to 0x%08x [CHANED!]\n",addr, original_value, test_value);
            } else {
                printk(KERN_INFO "No changes in offset 0x%lx, default 0x%08x to 0x%08x \n", addr, original_value, test_value);
            }

            if(sleep_enabled){
                // //Read local AER
                // msg.type = CFG;
                // msg.is_write = 0;
                // msg.address = 0x104; //AER Uncorrectable Error Status
                // AERU = dev_read(dev, msg);
                // //Read local AER
                // msg.type = CFG;
                // msg.is_write = 0;
                // msg.address = 0x110; //AER Correctable Error Status
                // AERC = dev_read(dev, msg);
                // printk(KERN_INFO "Initial AER Uncorrectable Error Status: 0x%lx\n", AERU);
                // printk(KERN_INFO "Initial AER Correctable Error Status:   0x%lx\n", AERC);
                
                // Sleep for 1000 milliseconds (1 second)
                msleep(7000);
            }

            // Restore the original value of the register
            //msg.is_write = 1;
            //msg.value = original_value;
            //dev_write(dev, msg);
        }else{
            printk(KERN_ERR "Skipping 0x%lx offsets\n");
        }
    }
    printk(KERN_INFO "Finished testing PCI configuration space for device %s\n", pci_name(dev));
}

static void test_mmio_space(struct pci_dev *dev, unsigned long start_addr, unsigned long end_addr) {
    struct kernel_msg msg;
    u32 original_value, test_value;
    unsigned long addr;

    printk(KERN_INFO "Testing MMIO space for device %s from 0x%lx to 0x%lx\n", pci_name(dev), start_addr, end_addr);

    // Iterate through each 4-byte register in the MMIO space
    for (addr = start_addr; addr <= end_addr; addr += 4) {
        // Read the original value of the register
        msg.type = MMIO;
        msg.is_write = 0;
        msg.address = addr;
        original_value = dev_read(dev, msg);

        // Write 0xFFFFFFFF to the register
        msg.is_write = 1;
        msg.value = 0xFFFFFFFF;
        dev_write(dev, msg);

        // Read back the register to check if the value changes
        msg.is_write = 0;
        test_value = dev_read(dev, msg);

        // Print the results
        if (original_value != test_value) {
            printk(KERN_ERR "MMIO Register 0x%lx: original value = 0x%08x, test value = 0x%08x [CHANED!]\n",
                   addr, original_value, test_value);
        } else {
            printk(KERN_INFO "MMIO Register 0x%lx: value did not change (0x%08x)\n",
                   addr, original_value);
        }

        // Restore the original value of the register
        msg.is_write = 1;
        msg.value = original_value;
        dev_write(dev, msg);
    }

    printk(KERN_INFO "Finished testing MMIO space for device %s\n", pci_name(dev));
}

static int __init g3_fake_init(void) {
    printk(KERN_INFO "Loading custom kernel module.. \n");
    nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST_PROTOCOL, &cfg);
     
     if(!nl_sk){
         printk(KERN_INFO "Kernel Netlink Socket for Netlink protocol %u failed.\n", NETLINK_TEST_PROTOCOL);
         return -ENOMEM; /*All errors are defined in ENOMEM for kernel space, and in stdio.h for user space*/
     }
     
     printk(KERN_INFO "Netlink Socket Created Successfully");
    return pci_register_driver(&g3_fake_driver);
}

static void __exit g3_fake_exit(void) {
    printk(KERN_INFO "Removing custom kernel module.. \n");
    /*Release any kernel resources held by this module in this fn*/
    netlink_kernel_release(nl_sk);
    nl_sk = NULL;
    printk(KERN_INFO "Done!.. \n");
	pci_unregister_driver(&g3_fake_driver);
    
}

module_init(g3_fake_init);
module_exit(g3_fake_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luis Enrique Tovar Tellez");
MODULE_DESCRIPTION("G3_Fake PCIe Driver");
