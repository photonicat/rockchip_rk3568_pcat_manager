# PCat Manager

PCat Manager is a power management and device control system for photonicat2 devices.
For photonicat (v1) device, use v1 branch.

## Building Dependencies

libglib2.0-dev libusb-1.0-0-dev libjson-c-dev libgpiod-dev

## Interfaces

### Socket API Documentation

**Socket Type:** Unix Domain Socket  
**Socket Path:** `/tmp/pcat-manager.sock`  
**Protocol:** JSON over stream socket  
**Message Format:** JSON string terminated with null byte (`\0`)

#### Connection Example:
```python
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('/tmp/pcat-manager.sock')
s.send(b"{'command':'pmu-status'}\0")
response = s.recv(1024)
```

#### Available Commands:

**Power Management Commands:**
- `pmu-status` - Get PMU status (battery voltage, charger voltage, battery percentage, board temperature)
- `pmu-fw-version-get` - Get PMU firmware version
- `pmu-io-get` - Get PMU I/O states (LED, beeper)
- `pmu-io-set` - Set PMU I/O states

**Power Scheduling Commands:**
- `schedule-power-event-set` - Set power schedule events
- `schedule-power-event-get` - Get power schedule events

**Charger Commands:**
- `charger-on-auto-start-set` - Configure charger auto-start
- `charger-on-auto-start-get` - Get charger auto-start configuration

**Modem Commands:**
- `modem-status-get` - Get modem status (mode, SIM state, signal strength, ISP info)
- `modem-rfkill-mode-set` - Set RF kill mode
- `modem-network-setup` - Configure modem network settings
- `modem-network-get` - Get modem network configuration

**System Commands:**
- `network-route-mode-get` - Get current network routing mode

#### Response Format:
All responses are JSON objects containing:
- `command` - Echo of the command sent
- `code` - Response code (0 = success)
- Additional fields specific to each command

#### Example:

**pmu-status**
Request:
```json
{
  "command": "pmu-status"
}
```

Response:
```json
{
  "command": "pmu-status",
  "code": 0,
  "battery-voltage": 4200,
  "charger-voltage": 5000,
  "on-battery": 0,
  "charge-percentage": 85,
  "board-temperature": 35
}
```

**modem-status-get**
Request:
```json
{
  "command": "modem-status-get"
}
```

Response:
```json
{
  "command": "modem-status-get", 
  "code": 0,
  "mode": "LTE",
  "sim-state": 2,
  "rfkill-state": 0,
  "signal-strength": -75,
  "isp-name": "Carrier",
  "isp-plmn": "12345"
}
```

**pmu-io-set**
Request:
```json
{
  "command": "pmu-io-set",
  "status-led-v2-enabled": 1,
  "beeper-enabled": 1
}
```

Response:
```json
{
  "command": "pmu-io-set", 
  "code": 0
}
```

**pmu-io-get**
Request:
```json
{
  "command": "pmu-io-get"
}
```

Response:
```json
{
  "command": "pmu-io-set", 
  "code": 0,
  "status-led-v2-enabled": 1,
  "beeper-enabled": 1
}
```



**modem-network-setup**
Request:
```json
{
  "command": "modem-network-setup",
  "apn": "",
  "user": "",
  "password": "",
  "auth": "",
  "disable-connection-5g-fail-auto-reset": 0,
  "modem-iface-auto-stop-if-wired": 1
}
```

- auto: default, need to set "modem-iface-auto-stop-if-wired": 1
- 4g/5g only: just set wan disabled and set "modem-iface-auto-stop-if-wired": 0
- ethernet only: just set wwan disabled and set "modem-iface-auto-stop-if-wired": 0

Response:
```json
{
  "command": "modem-network-setup", 
  "code": 0
}
```

**modem-network-get**
Request:
```json
{
  "command": "modem-network-get"
}
```

Response:
```json
{
  "command": "modem-network-get", 
  "code": 0,
  "device-type": "5g",
  "apn": "",
  "user": "",
  "password": "",
  "auth": "",
  "disable-connection-5g-fail-auto-reset": 0,
  "modem-iface-auto-stop-if-wired": 1
}
```
