# HAPwn – Home Assistant Pwnagotchi Plugin

HAPwn is a Pwnagotchi plugin that sends **real-time status updates, session statistics, and handshake events** directly to Home Assistant using its REST API.

It provides **online/offline detection**, session tracking, and automation-ready events — perfect for dashboards, notifications, and historical tracking.

---

## Features

* **Online / Offline presence detection**
* **Real-time handshake reporting**
* Session & lifetime handshake statistics
* Session duration tracking
* Tracks unique access points and clients seen
* Periodic heartbeat to Home Assistant
* Home Assistant events for automations
* Threaded event queue with graceful shutdown
* Deduplication to prevent duplicate handshake spam

---

### Home Assistant must be accessible remotely!
Though more testing needs to be done on my part.

## Installation

1. Copy the plugin to your Pwnagotchi custom plugins directory:

   ```bash
   sudo wget https://github.com/BraedenP232/HAPwn/blob/main/hapwn.py
   sudo cp hapwn.py /usr/local/share/pwnagotchi/custom-plugins/
   ```

2. Enable and configure the plugin in `/etc/pwnagotchi/config.toml`:

   ```toml
   main.plugins.hapwn.enabled = true
   main.plugins.hapwn.ha_url = "https://homeassistant.local:8123"
   main.plugins.hapwn.ha_token = "YOUR_LONG_LIVED_ACCESS_TOKEN"
   main.plugins.hapwn.unit_name = "pwnagotchi"      # Optional
   main.plugins.hapwn.heartbeat_interval = 60       # Optional (seconds)
   ```

3. Restart Pwnagotchi:

   ```bash
   sudo systemctl restart pwnagotchi
   ```

---

## Configuration Options

| Option               | Description                  | Default      |
| -------------------- | ---------------------------- | ------------ |
| `ha_url`             | Home Assistant base URL      | **Required** |
| `ha_token`           | Long-lived access token      | **Required** |
| `unit_name`          | Sensor/entity name           | `pwnagotchi` |
| `heartbeat_interval` | Heartbeat interval (seconds) | `60`         |

---

## Home Assistant Integration

### Sensor Entity

The plugin creates a sensor:

```
sensor.<unit_name>
```

Example:

```
sensor.pwnagotchi
```

### State Values

| State     | Meaning                                 |
| --------- | --------------------------------------- |
| `online`  | Pwnagotchi is active and reporting      |
| `offline` | Pwnagotchi shut down or plugin unloaded |

Offline state is sent automatically during shutdown or unload.

---

### Sensor Attributes

| Attribute               | Description                         |
| ----------------------- | ----------------------------------- |
| `session_id`            | Unique ID for the current session   |
| `session_handshakes`    | Handshakes captured this session    |
| `total_handshakes`      | Total handshakes since plugin start |
| `session_duration`      | Current session uptime (HH:MM:SS)   |
| `access_points_seen`    | Unique APs observed                 |
| `clients_seen`          | Unique client MACs observed         |
| `last_seen`             | Last heartbeat timestamp (UTC)      |
| `last_handshake_ssid`   | SSID of last handshake              |
| `last_handshake_bssid`  | BSSID of last handshake             |
| `last_handshake_client` | Client MAC of last handshake        |
| `last_handshake_time`   | Local timestamp of capture          |

---

## Home Assistant Events

### `pwnagotchi_handshake_captured`

Triggered every time a **new handshake** is captured.

```yaml
unit_name: pwnagotchi
session_id: abc123
ssid: NetworkName
bssid: AA:BB:CC:DD:EE:FF
client_mac: 11:22:33:44:55:66
filename: handshake.pcap
session_total: 5
```

---

### `pwnagotchi_session_completed`

Sent when a previous session exists and Pwnagotchi boots again.

```yaml
unit_name: pwnagotchi
session_id: abc123
handshakes: 42
duration: "2:15:30"
epochs: 150
```

---

## Example Home Assistant Dashboard

```yaml
type: entities
title: Pwnagotchi Status
entities:
  - entity: sensor.pwnagotchi
    name: Status
  - type: attribute
    entity: sensor.pwnagotchi
    attribute: session_handshakes
    name: Session Handshakes
  - type: attribute
    entity: sensor.pwnagotchi
    attribute: total_handshakes
    name: Total Handshakes
  - type: attribute
    entity: sensor.pwnagotchi
    attribute: session_duration
    name: Session Duration
  - type: attribute
    entity: sensor.pwnagotchi
    attribute: last_handshake_ssid
    name: Last Capture
```

---

## Automation Example

```yaml
alias: Notify on Handshake Capture
trigger:
  - platform: event
    event_type: pwnagotchi_handshake_captured
action:
  - service: notify.mobile_app
    data:
      title: Handshake Captured
      message: "Captured handshake from {{ trigger.event.data.ssid }}"
```

---

## Logging & Troubleshooting

### Plugin Log File

```bash
tail -f /etc/pwnagotchi/log/hapwn_plugin.log
```

### Potential Issues

**Sensor not appearing**

* Check Pwnlogs for errors first
* `tail -n 50 /etc/pwnagotchi/log/hapwn_plugin.log` 
* Restart Home Assistant
* Confirm token permissions
* Check HA logs for `/api/states` errors

**Offline status stuck**

* Ensure Pwnagotchi shut down cleanly
* Verify heartbeat interval is not too long

**Connection errors**

* Use HTTPS when remote
* Verify token validity
* Confirm HA is reachable from the Pwnagotchi network

## Security Notes

* **Never commit your Home Assistant token**
* Use **HTTPS** for remote access
* Tokens grant full API access — treat them like passwords

## Credits
* Inspired by [WPA2’s Discord plugin](https://github.com/wpa-2/Pwnagotchi-Plugins/blob/main/discord.py) architecture

## Contributing

Issues and pull requests are welcome.
For major changes, please open an issue first to discuss ideas.

## License

[GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.en.html)
