# G3-Fake-Driver

## Overview

The `G3_Fake_Driver` is a Linux Kernel Module designed to simulate interactions with a PCIe device. This module facilitates communication between user space and kernel space using the Netlink protocol, and provides functionality for reading and writing to PCI configuration and MMIO spaces.

## Features

- **Netlink Communication**: Utilizes Netlink sockets to receive messages from user space processes, allowing for efficient communication between user space and kernel space.
- **PCIe Device Interaction**: Implements probe and remove functions to manage PCIe devices, enabling reading and writing operations in both configuration and MMIO spaces.
- **Fuzzing Capabilities**: Includes functions to test and fuzz PCI configuration and MMIO spaces, helping identify potential vulnerabilities or changes in register values.
- **Debugging Utilities**: Provides debugging functions to print information about PCIe BARs and configuration space.

## Module Details

- **Driver Name**: `G3_Fake_Driver`
- **Vendor ID**: `0x8086` (modifiable)
- **Device ID**: `0x5375` (modifiable)
- **License**: GPL
- **Author**: Luis Enrique Tovar Tellez
- **Description**: G3_Fake PCIe Driver

## Installation

To install the module, use the following commands:

```bash
make
sudo insmod g3_fake_driver.ko
```

## Usage

Once installed, the module will create a Netlink socket and register the PCI driver. You can interact with the driver using user space applications that send Netlink messages for reading or writing operations.

## Functions

- **`g3_fake_probe`**: Enables the PCI device and sets up memory mappings.
- **`g3_fake_remove`**: Cleans up resources when the PCI device is removed.
- **`netlink_recv_msg_fn`**: Handles incoming Netlink messages and performs appropriate actions based on message type.
- **`dev_read`**: Reads data from the specified address in the PCI configuration or MMIO space.
- **`dev_write`**: Writes data to the specified address in the PCI configuration or MMIO space.
- **`test_pci_config_space`**: Tests and fuzzes the PCI configuration space.
- **`test_mmio_space`**: Tests and fuzzes the MMIO space.

## Debugging

The module includes several debugging functions to assist in development and testing:

- **`dbg_print_bar_info`**: Prints information about PCIe BARs.
- **`dbg_print_cfgdw`**: Prints configuration space data at specified offsets.

## Removal

To remove the module, use the following command:

```bash
sudo rmmod g3_fake_driver
```

## Disclaimer

This module is intended for educational and testing purposes. Modify the Vendor ID and Device ID as needed to match your target PCIe device.


# User Application for G3_Fake_Driver

## Overview

This user application is designed to interact with the `G3_Fake_Driver` Linux Kernel Module. It facilitates communication with the kernel module using Netlink sockets, allowing users to perform read and write operations on PCI configuration and MMIO spaces from user space.

## Features

- **Netlink Communication**: Establishes a Netlink socket connection to send and receive messages to and from the kernel module.
- **Read and Write Operations**: Supports reading from and writing to specified addresses in PCI configuration and MMIO spaces.
- **Multithreading**: Utilizes a separate thread to handle incoming messages from the kernel, ensuring efficient and non-blocking communication.

## Usage

```bash
gcc -o user_app user_app.c -lpthread
./user_app <type: cfg|mmio> <offset/address> [value to write]
```

### Parameters

- **type**: Specifies the type of operation (`cfg` for configuration space, `mmio` for MMIO space).
- **offset/address**: The address or offset in the specified space to perform the operation.
- **value to write**: (Optional) The value to write to the specified address. If omitted, the application performs a read operation.

## Functions

- **`create_netlink_socket`**: Creates a Netlink socket for communication with the kernel module.
- **`send_netlink_msg_to_kernel`**: Sends a message to the kernel module via Netlink, specifying the operation type, address, and value.
- **`start_kernel_data_receiver_thread`**: Starts a separate thread to receive messages from the kernel, ensuring non-blocking operation.
- **`_start_kernel_data_receiver_thread`**: The thread function that continuously listens for and processes incoming messages from the kernel.

## Example

```bash
./user_app cfg 0x100
```

```bash
./user_app mmio 0x200 0xFFFFFFFF
```

## Error Handling

The application includes basic error handling for socket creation, binding, and message sending. Ensure that the kernel module is loaded and running before using the application.

## Disclaimer

This application is intended for educational and testing purposes. Ensure that you have the necessary permissions and understand the implications of interacting with PCI devices on your system.

---

Feel free to explore the code and contribute to its development on GitHub!
