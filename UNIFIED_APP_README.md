# G3 Fake Driver - Unified Application

## Overview

`app_g3_unified.c` is a merged and improved version of `app_g3_fake.c` and `fuzzing_app.c` that provides both CLI and interactive modes for communicating with the G3 Fake Driver kernel module.

## Key Improvements

### 1. **Dual Operating Modes**
   - **CLI Mode**: Quick one-shot read/write operations via command-line arguments
   - **Interactive Mode**: Menu-driven interface with fuzzing capabilities
   - Auto-detects mode based on command-line arguments

### 2. **Consolidated Codebase**
   - Eliminated ~70% code duplication
   - Single implementation of netlink infrastructure
   - Unified configuration and state management

### 3. **Enhanced Receiver Thread**
   - Smart message differentiation (PCIE_TRANSACTION vs others)
   - Synchronous operation support with `doorbell_pci_ack`
   - Proper response buffering with length tracking

### 4. **Clean Abstraction Layer**
   - `lread()` and `lwrite()` functions with timeout/retry logic
   - Consistent API for both CLI and interactive modes
   - Better error handling and reporting

### 5. **Better Code Organization**
   ```
   ├── Configuration & Defines
   ├── Type Definitions
   ├── Global Variables
   ├── Netlink Infrastructure (sockets, send/receive)
   ├── Operation Layer (lread/lwrite with timeout)
   ├── Fuzzing/Testing Functions
   ├── Socket Initialization
   ├── CLI Mode
   ├── Interactive Mode
   └── Main Entry Point
   ```

### 6. **Configuration Options**
   - Verbose/quiet mode toggle
   - Configurable timeouts
   - Better debug output when enabled

## Building

```bash
make app_g3_unified
```

Or build everything:
```bash
make all
```

## Usage

### CLI Mode

**Read from register:**
```bash
./app_g3_unified cfg 0x100              # Read CFG register at offset 0x100
./app_g3_unified mmio 0x1000            # Read MMIO register at 0x1000
```

**Write to register:**
```bash
./app_g3_unified cfg 0x100 0xff         # Write 0xff to CFG register 0x100
./app_g3_unified mmio 0x1000 0xdeadbeef # Write to MMIO register
```

**With verbose mode:**
```bash
./app_g3_unified -v cfg 0x100           # Enable debug output
./app_g3_unified --verbose mmio 0x1000
```

### Interactive Mode

**Start interactive mode:**
```bash
./app_g3_unified
```

**Menu options:**
1. **Fuzzing CFG Space (kernel-side)** - Triggers kernel driver fuzzing (0x0-0x1000)
2. **Fuzzing MMIO Space (kernel-side)** - Triggers kernel driver MMIO fuzzing
3. **Get CFG open registers (user-side)** - User-space fuzzing with detailed output
4. **Read Register** - Read individual register (CFG or MMIO)
5. **Write Register** - Write individual register (CFG or MMIO)
6. **Toggle Verbose Mode** - Enable/disable debug messages
7. **Exit** - Clean exit

## Features Comparison

| Feature | app_g3_fake.c | fuzzing_app.c | app_g3_unified.c |
|---------|---------------|---------------|------------------|
| CLI mode | ✓ | ✗ | ✓ |
| Interactive mode | ✗ | ✓ | ✓ |
| Kernel-side fuzzing | ✗ | ✓ | ✓ |
| User-side fuzzing | ✗ | ✓ | ✓ |
| Individual read/write | ✓ | ✗ | ✓ (both modes) |
| Verbose mode | ✗ | ✗ | ✓ |
| Synchronous reads | ✗ | ✓ | ✓ |
| Timeout handling | ✗ | ✓ | ✓ (configurable) |
| Help message | ✗ | ✗ | ✓ |

## Configuration

Edit the defines at the top of `app_g3_unified.c`:

```c
#define DEFAULT_TIMEOUT_CYCLES  (148204 * 4)  // Adjust timeout
#define KERNEL_REPLY_SIZE       256           // Response buffer size
```

Runtime configuration via global `g_config`:
- `verbose`: Debug output toggle
- `timeout_cycles`: Read operation timeout

## Architecture

### Netlink Communication Flow

```
User Space (app_g3_unified)
    │
    ├─ Main Thread
    │   ├─ CLI Mode: Parse args → send_msg → wait
    │   └─ Interactive: Menu loop → lread/lwrite
    │
    └─ Receiver Thread (detached)
        └─ Continuous recvmsg() → process responses
            ├─ PCIE_TRANSACTION: Set doorbell_pci_ack
            └─ Other: Print to console

Kernel Space (g3_fake.ko)
    │
    └─ netlink_recv_msg_fn()
        ├─ PCIE_TRANSACTION: dev_read/dev_write
        ├─ FUZZING_CFG_SPACE: test_pci_config_space()
        └─ FUZZING_MMIO_SPACE: test_mmio_space()
```

### Read Operation Flow

1. User calls `lread(sock_fd, CFG, 0x100)`
2. `lread()` resets `doorbell_pci_ack = 0`
3. Sends PCIE_TRANSACTION message to kernel
4. Waits in loop checking `doorbell_pci_ack`
5. Receiver thread gets kernel reply
6. Sets `doorbell_pci_ack = 1` and copies to `kernel_reply`
7. `lread()` returns `kernel_reply` buffer

## Known Limitations

1. **Timeout**: Hardcoded timeout may need adjustment for slower systems
2. **Single-threaded operations**: Only one lread/lwrite at a time
3. **Buffer overflow risk**: `kernel_reply` is fixed size (mitigated with length tracking)
4. **Skipped offsets**: 0x260 and 0x278 are skipped in CFG fuzzing (known problematic)

## Best Practices

1. **Start with verbose mode** during debugging:
   ```bash
   ./app_g3_unified -v
   ```

2. **Use CLI mode for scripting**:
   ```bash
   ./app_g3_unified cfg 0x100 > output.txt
   ```

3. **Use interactive mode for exploration**:
   - Toggle verbose mode on/off as needed
   - Test individual registers before fuzzing

4. **Check kernel logs** (`dmesg`) for driver-side information

## Troubleshooting

**"Netlink socket creation failed"**
- Ensure kernel module is loaded: `lsmod | grep g3_fake`
- Check NETLINK_TEST_PROTOCOL value matches kernel module

**"Timeout for read command"**
- Increase timeout cycles in configuration
- Check if kernel module is responding: `dmesg | tail`
- Verify PCI device is accessible

**"Bind has failed"**
- Another instance might be running
- Check for zombie processes: `ps aux | grep app_g3`

## Migration Guide

### From app_g3_fake.c
Replace:
```bash
./app_g3_fake cfg 0x100 0xdeadbeef
```
With:
```bash
./app_g3_unified cfg 0x100 0xdeadbeef
```
(Same syntax, drop-in replacement)

### From fuzzing_app.c
Just run:
```bash
./app_g3_unified
```
Menu options are the same, plus additional features.

## Future Enhancements

- [ ] Batch operation support from file
- [ ] Transaction logging to file
- [ ] Configurable skipped offsets
- [ ] Non-blocking mode option
- [ ] Multiple simultaneous reads
- [ ] JSON output format
- [ ] Configuration file support

## Author

Luis Enrique Tovar Tellez

## License

GPL (same as kernel module)
