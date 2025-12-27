import json
import logging
import os
import time
import threading
import queue
import atexit
from typing import Any, Dict, Optional
from datetime import datetime

import requests
from requests import RequestException

import pwnagotchi.plugins as plugins
from pwnagotchi.agent import Agent

# main.plugins.hapwn.enabled = true
# main.plugins.hapwn.ha_url = "YOUR_HOME_ASSISTANT_EXTERNAL_URL" # eg. "https://myhome.duckdns.org" - No trailing slash, no port
# main.plugins.hapwn.ha_token = "YOUR_LONG_LIVED_ACCESS_TOKEN"
# main.plugins.hapwn.unit_name = "pwnagotchi"      # Optional
# main.plugins.hapwn.heartbeat_interval = 60       # Optional (seconds)

# This plugin is inspired by WPA2's dicord.py plugin
# https://github.com/wpa-2/Pwnagotchi-Plugins/blob/main/discord.py

LOG_DIR = "/etc/pwnagotchi/log"
LOG_FILE = os.path.join(LOG_DIR, "hapwn_plugin.log")

os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("pwnagotchi.plugins.hapwn")
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    fmt="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


class HAPwn(plugins.Plugin):
    __author__ = "Duedz"
    __version__ = '1.0.0'
    __license__ = 'GPL3'
    __description__ = 'Sends Pwnagotchi stats and handshakes to Home Assistant with offline detection'

    def __init__(self):
        super().__init__()
        self.ha_url: Optional[str] = None
        self.ha_token: Optional[str] = None
        self.unit_name: str = "pwnagotchi"
        self.http_session = requests.Session()
        
        # Deduplication
        self.recent_handshakes = set()
        self.recent_handshakes_limit = 200

        # Threading & Queue
        self._event_queue = queue.Queue()
        self._stop_event = threading.Event()
        self._worker_thread = None
        self._heartbeat_thread = None

        # Session Stats
        self.session_handshakes = 0
        self.total_handshakes = 0
        self.start_time = time.time()
        self.session_id = os.urandom(4).hex()
        
        # Heartbeat settings
        self.heartbeat_interval = 60  # Send heartbeat every 60 seconds
        self.last_heartbeat = time.time()
        
        # Track APs and clients
        self.access_points_seen = set()
        self.clients_seen = set()
        
        atexit.register(self._on_exit_cleanup)

    def on_loaded(self):
        logger.info("Home Assistant plugin loaded.")
        logger.debug(f"Available options: {self.options}")
        
        self.ha_url = self.options.get("ha_url", None)
        self.ha_token = self.options.get("ha_token", None)
        self.unit_name = self.options.get("unit_name", "pwnagotchi")
        self.heartbeat_interval = self.options.get("heartbeat_interval", 60)

        logger.debug(f"ha_url: {self.ha_url}")
        logger.debug(f"ha_token present: {bool(self.ha_token)}")
        logger.debug(f"unit_name: {self.unit_name}")
        logger.debug(f"heartbeat_interval: {self.heartbeat_interval}")

        if not self.ha_url or not self.ha_token:
            logger.error("Home Assistant plugin: Missing ha_url or ha_token in config.")
            return

        self.ha_url = self.ha_url.rstrip('/')

        # Start the background workers
        self._stop_event.clear()
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()
        
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()
        
        logger.info(f"Home Assistant plugin: Worker threads started. Session ID: {self.session_id}")

    def on_unload(self, ui):
        self._on_exit_cleanup()

    def _on_exit_cleanup(self):
        if self._stop_event.is_set():
            return

        logger.info("Home Assistant plugin: Cleaning up...")
        
        # Send final stats before shutdown
        self._update_ha_state("offline", {
            "session_handshakes": self.session_handshakes,
            "total_handshakes": self.total_handshakes,
            "session_duration": self._get_session_duration(),
            "access_points_seen": len(self.access_points_seen),
            "clients_seen": len(self.clients_seen)
        })
        
        # Stop threads
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=5.0)
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            self._heartbeat_thread.join(timeout=5.0)

    def on_ready(self, agent: Agent):
        self.start_time = time.time()
        logger.info("Home Assistant plugin: Pwnagotchi is ready.")
        
        try:
            self.unit_name = agent.config()['main']['name']
        except:
            self.unit_name = "pwnagotchi"

        # Send online state
        self._update_ha_state("online", {
            "session_id": self.session_id,
            "session_handshakes": 0,
            "total_handshakes": self.total_handshakes,
            "uptime": "00:00:00",
            "access_points_seen": 0,
            "clients_seen": 0
        })

        # Report previous session if available
        if hasattr(agent, 'last_session') and agent.last_session:
            last = agent.last_session
            if hasattr(last, 'duration') and str(last.duration) != "0:00:00":
                logger.info(f"Home Assistant plugin: Reporting last session stats. Duration: {last.duration}")
                
                self._send_event("session_completed", {
                    "handshakes": getattr(last, 'handshakes', 0),
                    "duration": str(last.duration),
                    "epochs": getattr(last, 'epochs', 0)
                })

    def on_handshake(self, agent: Agent, filename: str, access_point: Dict[str, Any], client_station: Dict[str, Any]):
        bssid = access_point.get("mac", "00:00:00:00:00:00")
        client_mac = client_station.get("mac", "00:00:00:00:00:00")
        handshake_key = (filename, bssid.lower(), client_mac.lower())

        if handshake_key in self.recent_handshakes:
            return 
        
        self.recent_handshakes.add(handshake_key)
        if len(self.recent_handshakes) > self.recent_handshakes_limit:
            self.recent_handshakes.pop()

        # Track unique APs and clients
        self.access_points_seen.add(bssid.lower())
        self.clients_seen.add(client_mac.lower())

        self.session_handshakes += 1
        self.total_handshakes += 1

        self._event_queue.put({
            'type': 'handshake',
            'filename': filename,
            'access_point': access_point,
            'client_station': client_station
        })

    def on_epoch(self, agent, epoch, epoch_data):
        """Update stats on each epoch"""
        self._event_queue.put({
            'type': 'epoch_update',
            'epoch': epoch,
            'data': epoch_data
        })

    def _heartbeat_loop(self):
        """Periodic heartbeat to keep Home Assistant aware of online status"""
        while not self._stop_event.is_set():
            try:
                time.sleep(self.heartbeat_interval)
                if not self._stop_event.is_set():
                    self._update_ha_state("online", {
                        "session_handshakes": self.session_handshakes,
                        "total_handshakes": self.total_handshakes,
                        "session_duration": self._get_session_duration(),
                        "access_points_seen": len(self.access_points_seen),
                        "clients_seen": len(self.clients_seen)
                    })
                    self.last_heartbeat = time.time()
            except Exception as e:
                logger.error(f"Error in heartbeat loop: {e}")

    def _worker_loop(self):
        while not self._stop_event.is_set() or not self._event_queue.empty():
            try:
                timeout = 1.0 if not self._stop_event.is_set() else 0.1
                event = self._event_queue.get(timeout=timeout)
            except queue.Empty:
                if self._stop_event.is_set():
                    break
                continue

            try:
                if event.get('type') == 'handshake':
                    self._process_handshake(event)
                elif event.get('type') == 'state_update':
                    self._send_ha_state(event['state'], event['attributes'])
                elif event.get('type') == 'event':
                    self._send_ha_event(event['event_type'], event['data'])
                elif event.get('type') == 'epoch_update':
                    self._process_epoch(event)
                
                if not self._stop_event.is_set():
                    time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Home Assistant plugin: Error in worker loop: {e}")
            finally:
                self._event_queue.task_done()

    def _process_handshake(self, event):
        ap = event['access_point']
        client = event['client_station']
        
        # Update state with new handshake count
        self._update_ha_state("online", {
            "session_handshakes": self.session_handshakes,
            "total_handshakes": self.total_handshakes,
            "session_duration": self._get_session_duration(),
            "last_handshake_ssid": ap.get('hostname', 'Unknown'),
            "last_handshake_bssid": ap.get('mac', 'Unknown'),
            "last_handshake_client": client.get('mac', 'Unknown'),
            "last_handshake_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "access_points_seen": len(self.access_points_seen),
            "clients_seen": len(self.clients_seen)
        })

        # Send handshake event
        self._send_event("handshake_captured", {
            "ssid": ap.get('hostname', 'Unknown'),
            "bssid": ap.get('mac', 'Unknown'),
            "client_mac": client.get('mac', 'Unknown'),
            "filename": os.path.basename(event['filename']),
            "session_total": self.session_handshakes
        })

    def _process_epoch(self, event):
        """Process epoch updates"""
        epoch_data = event.get('data', {})
        logger.debug(f"Epoch {event.get('epoch')}: {epoch_data}")

    # Home Assistant API Methods

    def _update_ha_state(self, state: str, attributes: Dict[str, Any]):
        """Queue a state update to Home Assistant"""
        attributes['last_seen'] = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        self._event_queue.put({
            'type': 'state_update',
            'state': state,
            'attributes': attributes
        })

    def _send_event(self, event_type: str, data: Dict[str, Any]):
        """Queue an event to Home Assistant"""
        self._event_queue.put({
            'type': 'event',
            'event_type': event_type,
            'data': data
        })

    def _send_ha_state(self, state: str, attributes: Dict[str, Any]):
        """Send state update to Home Assistant sensor"""
        if not self.ha_url or not self.ha_token:
            return

        entity_id = f"sensor.{self.unit_name.lower().replace(' ', '_')}"
        url = f"{self.ha_url}/api/states/{entity_id}"
        
        headers = {
            'Authorization': f'Bearer {self.ha_token}',
            'Content-Type': 'application/json'
        }

        payload = {
            'state': state,
            'attributes': {
                'friendly_name': f"{self.unit_name} Status",
                'icon': 'mdi:wifi-lock',
                'device_class': 'connectivity',
                **attributes
            }
        }

        try:
            response = self.http_session.post(url, json=payload, headers=headers, timeout=10)
            if response.status_code in [200, 201]:
                logger.debug(f"State updated successfully: {state}")
            else:
                logger.error(f"Failed to update state: {response.status_code} - {response.text}")
        except Exception as e:
            logger.error(f"Error updating Home Assistant state: {e}")

    def _send_ha_event(self, event_type: str, data: Dict[str, Any]):
        """Send event to Home Assistant"""
        if not self.ha_url or not self.ha_token:
            return

        url = f"{self.ha_url}/api/events/pwnagotchi_{event_type}"
        
        headers = {
            'Authorization': f'Bearer {self.ha_token}',
            'Content-Type': 'application/json'
        }

        payload = {
            'unit_name': self.unit_name,
            'session_id': self.session_id,
            **data
        }

        try:
            response = self.http_session.post(url, json=payload, headers=headers, timeout=10)
            if response.status_code in [200, 201]:
                logger.debug(f"Event sent successfully: {event_type}")
            else:
                logger.error(f"Failed to send event: {response.status_code} - {response.text}")
        except Exception as e:
            logger.error(f"Error sending Home Assistant event: {e}")

    def _get_session_duration(self) -> str:
        """Get formatted session duration"""
        duration = int(time.time() - self.start_time)
        hours = duration // 3600
        minutes = (duration % 3600) // 60
        seconds = duration % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
