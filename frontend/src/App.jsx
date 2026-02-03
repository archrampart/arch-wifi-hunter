import React, { useState, useEffect, useRef, useMemo } from 'react';


function App() {
  const [logs, setLogs] = useState([]);
  const [crackLogs, setCrackLogs] = useState([]);
  const [attackLogs, setAttackLogs] = useState([]);
  const [stats, setStats] = useState({ aps: 0, clients: 0, handshakes: 0 });
  const [mode, setMode] = useState('IDLE');
  const [hunterStatus, setHunterStatus] = useState({ running: false, status: 'IDLE', visited_count: 0 });
  const [networks, setNetworks] = useState([]);
  const [bleDevices, setBleDevices] = useState([]);
  const [wifiClients, setWifiClients] = useState([]);  // NEW: WiFi Clients
  const [status, setStatus] = useState('disconnected');
  const [activeTab, setActiveTab] = useState('DASHBOARD'); // DASHBOARD, WIFI, BLE, CLIENTS, SETTINGS
  const [wifiSubTab, setWifiSubTab] = useState('NETWORKS'); // NETWORKS, CAPTURED
  const [bleSubTab, setBleSubTab] = useState('SCAN'); // SCAN, ATTACK
  const [clientsSubTab, setClientsSubTab] = useState('CLIENT LIST'); // CLIENT LIST, PROBE ANALYZER

  // Evil Twin State
  const [eviltwinRunning, setEviltwinRunning] = useState(false);
  const [eviltwinStatus, setEviltwinStatus] = useState({});
  const [eviltwinCreds, setEviltwinCreds] = useState([]);
  const [selectedEviltwinTarget, setSelectedEviltwinTarget] = useState(null);
  const [eviltwinPortalType, setEviltwinPortalType] = useState('generic');
  const [eviltwinMode, setEviltwinMode] = useState('captive_portal');
  const [eviltwinCustomSSID, setEviltwinCustomSSID] = useState('');

  // MITM State
  const [mitmStatus, setMitmStatus] = useState({});
  const [mitmSnifferRunning, setMitmSnifferRunning] = useState(false);
  const [mitmPackets, setMitmPackets] = useState([]);
  const [mitmPacketFilter, setMitmPacketFilter] = useState('all');
  const [mitmDnsSpoofActive, setMitmDnsSpoofActive] = useState(false);
  const [mitmDnsSpoofEntries, setMitmDnsSpoofEntries] = useState([]);
  const [mitmNewDomain, setMitmNewDomain] = useState('');
  const [mitmNewIP, setMitmNewIP] = useState('192.168.4.1');
  const [mitmSubTab, setMitmSubTab] = useState('SNIFFER');
  const [mitmSnifferStats, setMitmSnifferStats] = useState({ total_packets: 0, http_requests: 0, dns_queries: 0, credentials: 0, elapsed_seconds: 0 });
  const [mitmExpandedPacket, setMitmExpandedPacket] = useState(null);

  // PMKID State
  const [pmkidRunning, setPmkidRunning] = useState(false);
  const [pmkidStatus, setPmkidStatus] = useState({});
  const [pmkidResults, setPmkidResults] = useState([]);
  const [selectedPmkidTarget, setSelectedPmkidTarget] = useState(null);
  const [pmkidTimeout, setPmkidTimeout] = useState(60);
  const [pmkidSubTab, setPmkidSubTab] = useState('NETWORKS');
  // PMKID cracking now handled by unified CRACK tab

  // WPS State
  const [wpsSubTab, setWpsSubTab] = useState('NETWORKS');
  const [wpsRunning, setWpsRunning] = useState(false);
  const [wpsStatus, setWpsStatus] = useState({});
  const [wpsResults, setWpsResults] = useState([]);
  const [wpsLogs, setWpsLogs] = useState([]);
  const [selectedWpsTarget, setSelectedWpsTarget] = useState(null);
  const [wpsAttackType, setWpsAttackType] = useState('pixie_dust');

  // Beacon Flood State
  const [floodRunning, setFloodRunning] = useState(false);
  const [floodStatus, setFloodStatus] = useState({});
  const [floodLogs, setFloodLogs] = useState([]);
  const [floodMode, setFloodMode] = useState('random');
  const [floodManualSSIDs, setFloodManualSSIDs] = useState('');
  const [floodFileName, setFloodFileName] = useState('');
  const [floodFileSSIDs, setFloodFileSSIDs] = useState([]);
  const [floodChannel, setFloodChannel] = useState(0);
  const [floodSpeed, setFloodSpeed] = useState(1000);

  // Controls
  const [wifiActive, setWifiActive] = useState(false);
  const [bleActive, setBleActive] = useState(false);
  const [autoPilot, setAutoPilot] = useState(false);

  // BLE Attack State
  const [bleAttackRunning, setBleAttackRunning] = useState(false);
  const [bleAttackResult, setBleAttackResult] = useState(null);
  const [selectedAttackTarget, setSelectedAttackTarget] = useState(null);
  const [beaconSpoofMode, setBeaconSpoofMode] = useState('ibeacon');
  const [beaconSpoofConfig, setBeaconSpoofConfig] = useState({ uuid: '', major: 1, minor: 1, tx_power: -59, url: 'https://example.com', count: 100 });
  const [showBeaconSpoofPanel, setShowBeaconSpoofPanel] = useState(false);

  const [customWordlist, setCustomWordlist] = useState("");
  const [availableWordlists, setAvailableWordlists] = useState([]);
  const [showWordlistPicker, setShowWordlistPicker] = useState(false);
  const [verifyingWordlist, setVerifyingWordlist] = useState(false);

  // Cracking State (Unified)
  const [cracking, setCracking] = useState(false);
  const [crackTarget, setCrackTarget] = useState(null);
  const [crackProgress, setCrackProgress] = useState({
    keys_tested: 0, total_keys: 0, keys_per_sec: 0, elapsed: "00:00:00", percentage: 0
  });
  const [crackHistory, setCrackHistory] = useState([]);

  // Captured Networks (persistent)
  const [capturedNetworks, setCapturedNetworks] = useState(() => {
    try {
      const saved = localStorage.getItem('capturedNetworks');
      if (saved) {
        const parsed = JSON.parse(saved);
        // Deduplicate on load by BSSID (keep first occurrence)
        const unique = parsed.filter((net, idx, arr) =>
          arr.findIndex(n => n.bssid === net.bssid) === idx
        );
        return unique;
      }
      return [];
    } catch {
      return [];
    }
  });

  // Inspection State
  const [inspectionResult, setInspectionResult] = useState(null);
  const [watchedDevices, setWatchedDevices] = useState(() => {
    // Load from localStorage on init
    try {
      const saved = localStorage.getItem('watchedBleDevices');
      return saved ? new Set(JSON.parse(saved)) : new Set();
    } catch {
      return new Set();
    }
  });
  const [watchedDeviceInfo, setWatchedDeviceInfo] = useState(() => {
    // Load watched device info (name, vendor, last_seen) from localStorage
    try {
      const saved = localStorage.getItem('watchedBleDeviceInfo');
      return saved ? JSON.parse(saved) : {};
    } catch {
      return {};
    }
  });
  const [detectedWatchTarget, setDetectedWatchTarget] = useState(null); // For visual banner
  const [alertsEnabled, setAlertsEnabled] = useState(() => {
    // Load alerts enabled state from localStorage
    try {
      const saved = localStorage.getItem('bleAlertsEnabled');
      return saved === 'true';
    } catch {
      return false;
    }
  });

  // Save watched devices to localStorage whenever it changes
  useEffect(() => {
    localStorage.setItem('watchedBleDevices', JSON.stringify(Array.from(watchedDevices)));
  }, [watchedDevices]);

  // Save watched device info to localStorage
  useEffect(() => {
    localStorage.setItem('watchedBleDeviceInfo', JSON.stringify(watchedDeviceInfo));
  }, [watchedDeviceInfo]);

  // Save alerts enabled state to localStorage
  useEffect(() => {
    localStorage.setItem('bleAlertsEnabled', alertsEnabled.toString());
  }, [alertsEnabled]);

  // Save captured networks to localStorage
  useEffect(() => {
    localStorage.setItem('capturedNetworks', JSON.stringify(capturedNetworks));
  }, [capturedNetworks]);

  // Load crack history on mount
  useEffect(() => {
    fetch('http://localhost:8000/crack/history')
      .then(r => r.json())
      .then(d => { if (d.history) setCrackHistory(d.history); })
      .catch(() => {});
  }, []);

  // MITM packet polling — only when MITM tab active and sniffer running
  useEffect(() => {
    if (activeTab !== 'MITM' || !mitmSnifferRunning) return;
    const interval = setInterval(() => {
      fetch(`http://localhost:8000/mitm/sniffer/packets?offset=0&limit=100&filter_type=${mitmPacketFilter}`)
        .then(r => r.json())
        .then(d => { if (d.packets) setMitmPackets(d.packets); })
        .catch(() => {});
    }, 1500);
    return () => clearInterval(interval);
  }, [activeTab, mitmSnifferRunning, mitmPacketFilter]);

  // Update watched device info when devices are detected
  useEffect(() => {
    if (bleDevices && bleDevices.length > 0 && watchedDevices.size > 0) {
      const newInfo = { ...watchedDeviceInfo };
      let updated = false;

      watchedDevices.forEach(mac => {
        const dev = bleDevices.find(d => d.mac === mac);
        if (dev) {
          newInfo[mac] = {
            name: dev.name || 'Unknown Device',
            vendor: dev.vendor || 'Unknown',
            last_seen: Date.now()
          };
          updated = true;
        }
      });

      if (updated) {
        setWatchedDeviceInfo(newInfo);
      }
    }
  }, [bleDevices, watchedDevices]);

  const toggleWatch = (mac, deviceData = null) => {
    const newSet = new Set(watchedDevices);
    if (newSet.has(mac)) {
      newSet.delete(mac);
      setLogs(p => [...p.slice(-50), `[WATCH] ❌ Stopped watching ${mac}`]);
      if (detectedWatchTarget?.mac === mac) setDetectedWatchTarget(null);

      // Remove from saved info
      const newInfo = { ...watchedDeviceInfo };
      delete newInfo[mac];
      setWatchedDeviceInfo(newInfo);
    } else {
      newSet.add(mac);
      setLogs(p => [...p.slice(-50), `[WATCH] 👁️ Started watching ${mac}`]);

      // Save device info when adding to watch list
      if (deviceData) {
        setWatchedDeviceInfo(prev => ({
          ...prev,
          [mac]: {
            name: deviceData.name || 'Unknown Device',
            vendor: deviceData.vendor || 'Unknown',
            last_seen: Date.now()
          }
        }));
      }
    }
    setWatchedDevices(newSet);
  };

  // Watcher Alert System with Sound & Notification
  useEffect(() => {
    if (bleDevices && bleDevices.length > 0 && watchedDevices.size > 0 && alertsEnabled) {
      const found = bleDevices.find(d => watchedDevices.has(d.mac));

      // Check if this is a NEW detection (wasn't detected before)
      const wasDetected = detectedWatchTarget !== null;
      const isNowDetected = found !== undefined;

      if (found) {
        // If this is a new detection (just came into range)
        if (!wasDetected) {
          // Play alert sound
          try {
            const audio = new Audio('data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmwhBTGH0fPTgjMGHm7A7+OZJQ0PVqvm7q1aFgxBm+HyvmwhBTGH0fPTgjMGHm7A7+OZJQ0PVqvm7q1aFgxBm+HyvmwhBTGH0fPTgjMGHm7A7+OZJQ0PVqvm7q1aFgxBm+HyvmwhBTGH0fPTgjMGHm7A7+OZJQ0PVqvm7q1aFgxBm+HyvmwhBTGH0fPTgjMGHm7A7+OZJQ0PVqvm7q1aFgxBm+HyvmwhBTGH0fPTgjMGHm7A7+OZJQ0PVqvm7q1aFgxBm+Hy');
            audio.volume = 0.5;
            audio.play().catch(() => {});
          } catch (e) {}

          // Show browser notification if permitted
          if ('Notification' in window && Notification.permission === 'granted') {
            new Notification('🎯 BLE Device Detected!', {
              body: `${found.name || 'Unknown Device'}\nMAC: ${found.mac}\nVendor: ${found.vendor || 'Unknown'}`,
              icon: '/favicon.ico',
              tag: `ble-watch-${found.mac}`,
              requireInteraction: false
            });
          }

          // Log to console
          setLogs(p => [...p.slice(-50), `[WATCH] 🚨 TARGET IN RANGE: ${found.mac} (${found.name || 'Unknown'})`]);
        }

        setDetectedWatchTarget(found);
      } else {
        // Device left range
        if (wasDetected && detectedWatchTarget) {
          setLogs(p => [...p.slice(-50), `[WATCH] ⚠️ TARGET LEFT RANGE: ${detectedWatchTarget.mac}`]);
        }
        setDetectedWatchTarget(null);
      }
    } else {
      // If alerts are disabled, don't show banner
      if (!alertsEnabled) {
        setDetectedWatchTarget(null);
      }
    }
  }, [bleDevices, watchedDevices, alertsEnabled]);

  // Removed WebSerial refs - no longer needed

  // WebSocket handles all real-time data updates (stats, networks, ble devices, etc.)
  // No need for polling - removed fetchStats() and fetchNetworks()

  // Removed ESP32/Serial related state - no longer needed
  // Removed WebSerial and Marauder functions - no longer needed



  // HELPER: Get Signal Color
  const getSignalColor = (rssi) => {
    if (rssi >= -50) return '#0f0'; // Strong
    if (rssi >= -70) return '#ff0'; // Med
    return '#f00'; // Weak
  };

  // HELPER: Get BLE Icon
  const getBleIcon = (name, vendor) => {
    const n = (name || '').toLowerCase();
    const v = (vendor || '').toLowerCase();

    if (n.includes('watch') || n.includes('band') || v.includes('garmin') || v.includes('fitbit')) return '⌚';
    if (n.includes('phone') || n.includes('iphone') || v.includes('apple') || v.includes('samsung')) return '📱';
    if (n.includes('head') || n.includes('bud') || n.includes('airpod') || v.includes('bose') || v.includes('sony')) return '🎧';
    if (n.includes('tv') || n.includes('cast')) return '📺';
    if (n.includes('pc') || n.includes('mac') || n.includes('computer')) return '💻';
    return '📡'; // Generic
  };

  // Removed Canvas animation and serial reading code - no longer needed
  const logEndRef = useRef(null);
  const crackLogEndRef = useRef(null);
  const wpsLogEndRef = useRef(null);
  const floodLogEndRef = useRef(null);
  const floodFileInputRef = useRef(null);
  const lastClosedInspection = useRef(null);


  const scrollToBottom = (ref) => ref.current?.scrollIntoView({ behavior: "smooth" });
  useEffect(() => scrollToBottom(logEndRef), [logs]);
  useEffect(() => scrollToBottom(crackLogEndRef), [crackLogs]);
  // pmkid crack scroll removed — unified in CRACK tab
  useEffect(() => scrollToBottom(wpsLogEndRef), [wpsLogs]);
  useEffect(() => scrollToBottom(floodLogEndRef), [floodLogs]);

  useEffect(() => {
    let ws;
    const connect = () => {
      ws = new WebSocket('ws://localhost:8000/ws');
      ws.onopen = () => { setStatus('connected'); setLogs(p => [...p, "[SYS] Backend Connected"]); };
      ws.onclose = () => { setStatus('disconnected'); setTimeout(connect, 3000); };
      ws.onmessage = (e) => {
        const data = JSON.parse(e.data);
        if (data.type === 'scan_update') {
          setStats({ aps: data.aps, handshakes: data.handshakes, clients: data.wifi_clients?.length || 0 });
          setMode(data.mode);
          const newNetworks = data.networks || [];
          setNetworks(newNetworks);
          setBleDevices(data.ble_devices || []);
          setWifiClients(data.wifi_clients || []);  // NEW: Update WiFi clients
          if (data.hunter_status) {
            setHunterStatus(data.hunter_status);
            setAutoPilot(data.hunter_status.running);
          }

          // Auto-add pwned networks to captured list (deduplicate)
          newNetworks.forEach(net => {
            if (net.pwned) {
              setCapturedNetworks(prev => {
                // Check if already exists in current state
                if (prev.find(c => c.bssid === net.bssid)) {
                  return prev; // Already exists, don't add
                }
                // Add new capture
                return [...prev, {
                  ...net,
                  capturedAt: Date.now()
                }];
              });
            }
          });

          // Evil Twin status update
          if (data.eviltwin_status) {
            setEviltwinStatus(data.eviltwin_status);
            setEviltwinRunning(data.eviltwin_status.running || false);
          }

          // PMKID status update
          if (data.pmkid_status) {
            setPmkidStatus(data.pmkid_status);
            setPmkidRunning(data.pmkid_status.running || false);
          }

          // WPS status update
          if (data.wps_status) {
            setWpsStatus(data.wps_status);
            setWpsRunning(data.wps_status.running || false);
          }

          // Flood status update
          if (data.flood_status) {
            setFloodStatus(data.flood_status);
            setFloodRunning(data.flood_status.running || false);
          }

          // MITM status update
          if (data.mitm_status) {
            setMitmStatus(data.mitm_status);
            if (data.mitm_status.sniffer) {
              setMitmSnifferRunning(data.mitm_status.sniffer.running || false);
              setMitmSnifferStats(data.mitm_status.sniffer);
            }
            if (data.mitm_status.dns_spoof) {
              setMitmDnsSpoofActive(data.mitm_status.dns_spoof.active || false);
              setMitmDnsSpoofEntries(data.mitm_status.dns_spoof.entries || []);
            }
          }

          if (data.crack_status) {
            setCracking(data.crack_status.cracking || false);
            if (data.crack_status.progress) {
              setCrackProgress(data.crack_status.progress);
            }
          }

          // BLE Inspection Update
          // Prevent re-opening if user just closed it
          if (data.ble_inspection && data.ble_inspection.mac) {
            if (data.ble_inspection.mac !== lastClosedInspection.current) {
              setInspectionResult(data.ble_inspection);
            }
          }
        } else if (data.type === 'log') {
          setLogs(p => [...p.slice(-50), `[LOG] ${data.msg}`]);
        } else if (data.type === 'crack_log') {
          setCrackLogs(p => [...p, data.msg]);
        } else if (data.type === 'crack_progress') {
          setCrackProgress({
            keys_tested: data.keys_tested || 0,
            total_keys: data.total_keys || 0,
            keys_per_sec: data.keys_per_sec || 0,
            elapsed: data.elapsed || "00:00:00",
            percentage: data.percentage || 0
          });
        } else if (data.type === 'crack_result') {
          setCracking(false);
          // Fetch updated history from backend
          fetch('http://localhost:8000/crack/history')
            .then(r => r.json())
            .then(d => { if (d.history) setCrackHistory(d.history); })
            .catch(() => {});
        } else if (data.type === 'pmkid_crack_log') {
          // Backward compat: redirect to unified crack logs
          setCrackLogs(p => [...p, data.msg]);
        } else if (data.type === 'pmkid_crack_result') {
          setCracking(false);
        } else if (data.type === 'wps_log') {
          setWpsLogs(p => [...p, data.msg]);
          // Check for success/result in log
          if (data.msg && data.msg.includes('SUCCESS:')) {
            // Refresh results
            fetch('http://localhost:8000/wps/results')
              .then(r => r.json())
              .then(d => { if (d.results) setWpsResults(d.results); })
              .catch(() => {});
            setWpsRunning(false);
            // Auto-switch to RESULTS tab
            setWpsSubTab('RESULTS');
          } else if (data.msg && (data.msg.includes('FAILED:') || data.msg.includes('STOPPED:'))) {
            setWpsRunning(false);
          }
        } else if (data.type === 'flood_log') {
          setFloodLogs(p => [...p, data.msg]);
          if (data.msg && (data.msg.includes('STOPPED:') || data.msg.includes('finished'))) {
            setFloodRunning(false);
          }
        } else if (data.type === 'attack') {
          // BLE Attack logs - add to both attack logs and system logs
          setAttackLogs(p => [...p.slice(-100), data.msg]);
          setLogs(p => [...p.slice(-50), data.msg]);
        }
      };
    };
    connect();
    return () => ws?.close();
  }, []);

  const api = async (endpoint, body = {}, method = 'POST') => {
    try {
      const response = await fetch(`http://localhost:8000${endpoint}`, {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await response.json();
      return data;
    } catch (e) {
      if (endpoint !== '/stats') {
        setLogs(p => [...p, `[ERR] API ${endpoint} failed`]);
      }
      return null;
    }
  };



  const toggleWifi = async () => {
    // Prevent disabling WIFI Scanner while Hunter is active
    if (wifiActive && autoPilot) {
      setLogs(p => [...p.slice(-50), '[WARN] Cannot disable WIFI Scanner while Hunter Mode is active']);
      return;
    }
    const response = await api(wifiActive ? '/scan/stop' : '/scan/start');
    if (response) {
      setWifiActive(!wifiActive);
    }
  };

  const toggleBle = async () => {
    const response = await api(bleActive ? '/ble/stop' : '/ble/start');
    if (response) {
      setBleActive(!bleActive);
    }
  };

  const toggleAuto = async () => {
    const newState = !autoPilot;

    // If enabling Hunter, ensure WIFI Scanner is active
    if (newState && !wifiActive) {
      setLogs(p => [...p.slice(-50), '[HUNTER] Auto-starting WIFI Scanner...']);
      await api('/scan/start');
      setWifiActive(true);
    }

    // Call the API and wait for response
    const response = await api(newState ? '/hunter/start' : '/hunter/stop');

    // Only update state if API call was successful
    if (response) {
      setAutoPilot(newState);
      setLogs(p => [...p.slice(-50), `[HUNTER] ${newState ? 'Started' : 'Stopped'}`]);
    }
  };

  // Wordlist Selection via Backend (Web Mode)

  const startCrack = (net, sourceType = 'auto') => {
    setCracking(true);
    setCrackTarget({ ...net, source_type: sourceType });
    setCrackLogs([`>>> STARTING CRACK ON ${net.ssid} (${sourceType.toUpperCase()}) <<<`]);
    setCrackProgress({ keys_tested: 0, total_keys: 0, keys_per_sec: 0, elapsed: "00:00:00", percentage: 0 });
    setActiveTab('CRACK');
    api('/crack/unified/start', {
      bssid: net.bssid,
      ssid: net.ssid,
      wordlist: customWordlist || 'wordlists/wordlist.txt',
      source_type: sourceType
    });
  };

  const stopCrack = () => {
    api('/crack/unified/stop');
    setCracking(false);
    setCrackLogs(p => [...p, ">>> PROCESS TERMINATED <<<"]);
  };

  const inspectBle = (dev) => {
    // Allow re-opening if clicked explicitly
    lastClosedInspection.current = null;
    setLogs(p => [...p, `[BLE] Requesting Inspection for ${dev.mac}...`]);
    setInspectionResult({ mac: dev.mac, status: "pending", details: {} });
    api('/ble/inspect', { mac: dev.mac });
  };

  const closeInspector = () => {
    if (inspectionResult) {
      lastClosedInspection.current = inspectionResult.mac; // Mark as ignored
    }
    setInspectionResult(null);
  };

  // BLE Attack Functions
  const startBleAttack = async (attackType, targetMac = null) => {
    try {
      const payload = { attack_type: attackType };
      if (targetMac) payload.target_mac = targetMac;

      const res = await fetch('http://localhost:8000/ble/attack/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();

      if (data.status === 'success') {
        setBleAttackRunning(true);
        setBleAttackResult(null);
        setLogs(p => [...p, `[BLE ATTACK] ${data.message}`]);
      } else {
        setLogs(p => [...p, `[BLE ATTACK ERROR] ${data.message}`]);
      }
    } catch (e) {
      setLogs(p => [...p, `[BLE ATTACK ERROR] ${e.message}`]);
    }
  };

  const startBeaconSpoof = async () => {
    try {
      const options = { mode: beaconSpoofMode };
      if (beaconSpoofMode === 'ibeacon') {
        options.uuid = beaconSpoofConfig.uuid || '';
        options.major = beaconSpoofConfig.major;
        options.minor = beaconSpoofConfig.minor;
        options.tx_power = beaconSpoofConfig.tx_power;
      } else if (beaconSpoofMode === 'eddystone_url') {
        options.url = beaconSpoofConfig.url;
      } else if (beaconSpoofMode === 'flood') {
        options.count = beaconSpoofConfig.count;
      }
      const payload = {
        attack_type: 'beacon_spoof',
        target_mac: beaconSpoofMode === 'name_clone' ? selectedAttackTarget : null,
        options
      };
      const res = await fetch('http://localhost:8000/ble/attack/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (data.status === 'success') {
        setBleAttackRunning(true);
        setBleAttackResult(null);
        setShowBeaconSpoofPanel(false);
        setLogs(p => [...p, `[BEACON SPOOF] ${data.message}`]);
      } else {
        setLogs(p => [...p, `[BEACON SPOOF ERROR] ${data.message}`]);
      }
    } catch (e) {
      setLogs(p => [...p, `[BEACON SPOOF ERROR] ${e.message}`]);
    }
  };

  const stopBleAttack = async () => {
    try {
      await fetch('http://localhost:8000/ble/attack/stop', { method: 'POST' });
      setBleAttackRunning(false);
      setLogs(p => [...p, `[BLE ATTACK] Attack stopped`]);

      // Wait a bit for backend to update result, then fetch final result
      setTimeout(async () => {
        try {
          const res = await fetch('http://localhost:8000/ble/attack/status');
          const data = await res.json();
          if (data.result && Object.keys(data.result).length > 0) {
            setBleAttackResult(data.result);
          }
        } catch (e) {
          console.error('Failed to fetch final attack result:', e);
        }
      }, 500);
    } catch (e) {
      setLogs(p => [...p, `[BLE ATTACK ERROR] ${e.message}`]);
    }
  };

  // Poll BLE attack status
  useEffect(() => {
    if (!bleAttackRunning) return;

    const interval = setInterval(async () => {
      try {
        const res = await fetch('http://localhost:8000/ble/attack/status');
        const data = await res.json();

        if (data.running) {
          setBleAttackResult(data.result);

          // Auto-stop when attack completes
          if (data.result && (data.result.status === 'completed' || data.result.status === 'failed' || data.result.status === 'stopped')) {
            setBleAttackRunning(false);
          }
        } else {
          // Attack stopped - get final result
          if (data.result && Object.keys(data.result).length > 0) {
            setBleAttackResult(data.result);
          }
          setBleAttackRunning(false);
        }
      } catch (e) {
        console.error('BLE attack status poll error:', e);
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [bleAttackRunning]);

  const factoryReset = async () => {
    if (confirm("FACTORY RESET WARNING:\nThis will delete all captures, logs, and settings.\nThe app will restart.")) {
      try {
        await fetch('http://localhost:8000/system/reset', { method: 'POST' });
        setTimeout(() => { window.location.reload(); }, 1000);
      } catch (e) {
        alert("Reset failed: " + e);
      }
    }
  };

  return (
    <div style={{
      display: 'flex',
      height: '100vh',
      width: '100vw',
      background: '#050505',
      color: '#e0e0e0',
      fontFamily: 'var(--font-mono)',
      overflow: 'hidden',
      fontSize: '14px',
      position: 'relative'
    }}>

      {/* 1. SIDEBAR */}
      <div style={{
        width: '240px',
        flexShrink: 0,
        background: '#080808',
        borderRight: '1px solid var(--glass-border)',
        display: 'flex',
        flexDirection: 'column',
        padding: '15px',
        zIndex: 20
      }}>
        {/* Logo */}
        {/* Logo */}
        <div style={{ marginBottom: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <h1 className="neon-text" style={{ margin: 0, fontSize: '1.1rem', fontFamily: 'var(--font-display)', lineHeight: '1' }}>ARCH</h1>
            <h1 style={{ margin: 0, fontSize: '1.1rem', fontFamily: 'var(--font-display)', lineHeight: '1', color: '#555' }}>WIFI</h1>
            <h1 className="neon-text" style={{ margin: 0, fontSize: '1.1rem', fontFamily: 'var(--font-display)', color: '#fff' }}>HUNTER</h1>
          </div>
          <div style={{ fontSize: '0.85rem', color: '#555', marginTop: '4px' }}>v2.0.0</div>
          <a href="https://www.archrampart.com" target="_blank" rel="noopener noreferrer"
            style={{ fontSize: '9px', color: '#333', textDecoration: 'none', marginTop: '2px', display: 'block', letterSpacing: '0.5px' }}
            onMouseEnter={e => e.target.style.color = '#0f0'}
            onMouseLeave={e => e.target.style.color = '#333'}
          >archrampart.com</a>
        </div>

        {/* Status */}
        <div className="glass-panel" style={{ padding: '10px', marginBottom: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '2px', fontSize: '12px' }}>
            <span style={{ color: '#666' }}>CORE</span>
            <b style={{ color: status === 'connected' ? 'var(--color-primary)' : 'red' }}>{status === 'connected' ? 'ONLINE' : 'OFFLINE'}</b>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '2px', fontSize: '12px' }}>
            <span style={{ color: '#666' }}>MODE</span>
            <b style={{ color: '#fff' }}>{mode}</b>
          </div>
          {autoPilot && (
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', marginTop: '5px', paddingTop: '5px', borderTop: '1px solid #222' }}>
              <span style={{ color: '#666' }}>HUNTER</span>
              <b style={{ color: 'var(--color-danger)', fontFamily: 'monospace' }}>{hunterStatus.status}</b>
            </div>
          )}
          {autoPilot && hunterStatus.visited_count > 0 && (
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', marginTop: '2px' }}>
              <span style={{ color: '#555' }}>TARGETS</span>
              <span style={{ color: '#888' }}>{hunterStatus.visited_count} visited</span>
            </div>
          )}
          {eviltwinRunning && (
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', marginTop: '5px', paddingTop: '5px', borderTop: '1px solid #222' }}>
              <span style={{ color: '#666' }}>EVIL TWIN</span>
              <b style={{ color: eviltwinStatus?.mode === 'internet_relay' ? '#00ffff' : '#ff0', fontFamily: 'monospace', fontSize: '10px' }}>
                {eviltwinStatus?.mode === 'internet_relay' ? 'RELAY' : 'PORTAL'}
              </b>
            </div>
          )}
          {mitmSnifferRunning && (
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', marginTop: '3px' }}>
              <span style={{ color: '#666' }}>MITM</span>
              <b style={{ color: '#00ffff', fontFamily: 'monospace', fontSize: '10px' }}>SNIFFING</b>
            </div>
          )}
          {cracking && (
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', marginTop: '3px' }}>
              <span style={{ color: '#666' }}>CRACK</span>
              <b style={{ color: '#ff0', fontFamily: 'monospace', fontSize: '10px' }}>RUNNING</b>
            </div>
          )}
        </div>

        {/* Controls */}
        <div style={{ flex: 1 }}>
          <div style={{ color: '#444', fontSize: '12px', marginBottom: '5px', letterSpacing: '1px' }}>CONTROLS</div>

          <div className="control-row" style={{ padding: '8px' }}>
            <span className="control-label" style={{ fontSize: '13px' }}>WIFI SCANNER</span>
            <label className="switch" style={{ width: '36px', height: '18px' }}>
              <input type="checkbox" checked={wifiActive} onChange={toggleWifi} />
              <span className="slider green"></span>
            </label>
          </div>

          <div className="control-row" style={{ padding: '8px' }}>
            <span className="control-label" style={{ fontSize: '13px' }}>BLE RADAR</span>
            <label className="switch" style={{ width: '36px', height: '18px' }}>
              <input type="checkbox" checked={bleActive} onChange={toggleBle} />
              <span className="slider blue"></span>
            </label>
          </div>

          <div className="control-row" style={{ padding: '8px' }}>
            <span className="control-label" style={{ fontSize: '13px' }}>HUNTER MODE</span>
            <label className="switch" style={{ width: '36px', height: '18px' }}>
              <input type="checkbox" checked={autoPilot} onChange={toggleAuto} />
              <span className="slider red"></span>
            </label>
          </div>

          {/* Target Detection Status */}
          {watchedDevices.size > 0 && (
            <div style={{ marginTop: '15px', paddingTop: '15px', borderTop: '1px solid #222' }}>
              <div style={{
                fontSize: '11px',
                marginBottom: '8px',
                display: 'flex',
                flexDirection: 'column',
                gap: '6px'
              }}>
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}>
                  <span style={{ color: '#444', letterSpacing: '1px' }}>🎯 TARGET TRACKING</span>
                  <label
                    className="switch"
                    style={{ width: '28px', height: '14px' }}
                    title={alertsEnabled ? 'Alerts ON' : 'Alerts OFF'}
                  >
                    <input
                      type="checkbox"
                      checked={alertsEnabled}
                      onChange={() => {
                        if (!alertsEnabled) {
                          // Turning ON alerts
                          if ('Notification' in window && Notification.permission !== 'granted') {
                            Notification.requestPermission().then(permission => {
                              if (permission === 'granted') {
                                setAlertsEnabled(true);
                                setLogs(p => [...p.slice(-50), '[WATCH] 🔔 Alerts enabled']);
                                new Notification('🎯 Watch Alerts Enabled', {
                                  body: `You'll be notified when watched devices come into range`,
                                  icon: '/favicon.ico'
                                });
                              }
                            });
                          } else {
                            setAlertsEnabled(true);
                            setLogs(p => [...p.slice(-50), '[WATCH] 🔔 Alerts enabled']);
                          }
                        } else {
                          // Turning OFF alerts
                          setAlertsEnabled(false);
                          setDetectedWatchTarget(null);
                          setLogs(p => [...p.slice(-50), '[WATCH] 🔕 Alerts disabled']);
                        }
                      }}
                    />
                    <span className="slider" style={{
                      background: alertsEnabled ? '#0f0' : '#333'
                    }}></span>
                  </label>
                </div>
                <div style={{ fontSize: '9px', color: '#666', textAlign: 'right' }}>
                  {watchedDevices.size} target{watchedDevices.size > 1 ? 's' : ''}
                </div>
              </div>
              <div className="glass-panel" style={{
                padding: '8px',
                background: (() => {
                  const detectedTargets = bleDevices?.filter(d => watchedDevices.has(d.mac)) || [];
                  return detectedTargets.length > 0 && alertsEnabled
                    ? 'linear-gradient(135deg, rgba(255, 0, 0, 0.15), rgba(255, 100, 0, 0.1))'
                    : 'rgba(0,0,0,0.3)';
                })(),
                border: (() => {
                  const detectedTargets = bleDevices?.filter(d => watchedDevices.has(d.mac)) || [];
                  return detectedTargets.length > 0 && alertsEnabled
                    ? '1px solid rgba(255, 0, 0, 0.5)'
                    : '1px solid rgba(255, 255, 255, 0.05)';
                })(),
                animation: (() => {
                  const detectedTargets = bleDevices?.filter(d => watchedDevices.has(d.mac)) || [];
                  return detectedTargets.length > 0 && alertsEnabled ? 'pulse 2s infinite' : 'none';
                })(),
                maxHeight: '150px',
                overflowY: 'auto'
              }}>
                {(() => {
                  // Get all detected targets in range
                  const detectedTargets = bleDevices?.filter(d => watchedDevices.has(d.mac)) || [];

                  if (detectedTargets.length > 0 && alertsEnabled) {
                    return detectedTargets.map((target, idx) => (
                      <div
                        key={target.mac}
                        style={{
                          marginBottom: idx < detectedTargets.length - 1 ? '8px' : '0',
                          paddingBottom: idx < detectedTargets.length - 1 ? '8px' : '0',
                          borderBottom: idx < detectedTargets.length - 1 ? '1px solid rgba(255,255,255,0.05)' : 'none'
                        }}
                      >
                        <div style={{
                          fontSize: '10px',
                          color: '#ff4444',
                          fontWeight: 'bold',
                          marginBottom: '4px',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '6px'
                        }}>
                          <span style={{
                            width: '6px',
                            height: '6px',
                            background: '#ff0000',
                            borderRadius: '50%',
                            boxShadow: '0 0 8px #ff0000',
                            animation: 'flash 0.8s infinite'
                          }}></span>
                          IN RANGE
                        </div>
                        <div style={{
                          fontSize: '9px',
                          fontFamily: 'monospace',
                          color: '#ffd700',
                          marginBottom: '3px',
                          wordBreak: 'break-all'
                        }}>
                          {target.mac}
                        </div>
                        <div style={{ fontSize: '8px', color: '#aaa', marginBottom: '2px' }}>
                          {target.name || 'Unknown Device'}
                        </div>
                        <div style={{ fontSize: '8px', color: '#888' }}>
                          RSSI: {target.rssi} dBm
                        </div>
                      </div>
                    ));
                  } else {
                    return (
                      <div style={{ fontSize: '10px', color: '#666', textAlign: 'center', padding: '5px' }}>
                        {alertsEnabled ? '👁️ Monitoring...' : '💤 Alerts Disabled'}
                      </div>
                    );
                  }
                })()}
              </div>
            </div>
          )}

        </div>

        {/* Mini Terminal */}
        <div className="glass-panel" style={{ height: '150px', display: 'flex', flexDirection: 'column', marginTop: '15px' }}>
          <div style={{ padding: '5px', borderBottom: '1px solid var(--glass-border)', fontSize: '9px', color: '#444' }}>SYSTEM LOGS</div>
          <div style={{ flex: 1, overflowY: 'auto', padding: '5px', fontSize: '9px', fontFamily: 'monospace', color: '#888' }}>
            {logs.map((L, i) => <div key={i}>{L}</div>)}
            <div ref={logEndRef} />
          </div>
        </div>

        {/* Quick Settings Button */}
        <button
          onClick={() => setActiveTab('SETTINGS')}
          className="cyber-button"
          style={{
            marginTop: '15px',
            width: '100%',
            background: activeTab === 'SETTINGS' ? 'rgba(0, 255, 255, 0.1)' : 'transparent',
            borderColor: activeTab === 'SETTINGS' ? 'var(--color-primary)' : '#333',
            color: activeTab === 'SETTINGS' ? 'var(--color-primary)' : '#666',
            padding: '10px',
            fontSize: '11px',
            fontFamily: 'var(--font-display)',
            letterSpacing: '1px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '8px'
          }}
        >
          <span>⚙️</span>
          <span>SETTINGS</span>
        </button>
      </div>

      {/* 2. MAIN CONTENT (Right) */}
      <div style={{
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        background: 'radial-gradient(circle at 50% 50%, #0c0c0c 0%, #000 100%)',
        position: 'relative',
        overflow: 'hidden'
      }}>

        {/* Header: Stats Row */}
        <div style={{
          flexShrink: 0,
          display: 'flex',
          padding: '8px 20px',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: 'rgba(255,255,255,0.01)',
          borderBottom: '1px solid rgba(255,255,255,0.05)'
        }}>
          <div style={{ display: 'flex', gap: '30px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ fontSize: '1.2rem', fontWeight: 'bold', color: '#fff' }}>{stats.aps}</span>
              <span style={{ color: '#666', fontSize: '10px' }}>NETWORKS</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ fontSize: '1.2rem', fontWeight: 'bold', color: '#0ff' }}>{stats.clients}</span>
              <span style={{ color: '#666', fontSize: '10px' }}>CLIENTS</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ fontSize: '1.2rem', fontWeight: 'bold', color: 'var(--color-secondary)' }}>{bleDevices.length}</span>
              <span style={{ color: '#666', fontSize: '10px' }}>BLE</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ fontSize: '1.2rem', fontWeight: 'bold', color: 'var(--color-danger)' }}>{stats.handshakes}</span>
              <span style={{ color: '#666', fontSize: '10px' }}>PWNED</span>
            </div>
          </div>
        </div>

        {/* Header: Tab Navigation Row */}
        <div style={{
          flexShrink: 0,
          display: 'flex',
          gap: '4px',
          padding: '6px 20px',
          overflowX: 'auto',
          overflowY: 'hidden',
          borderBottom: '1px solid var(--glass-border)',
          background: 'rgba(255,255,255,0.01)',
          scrollbarWidth: 'none',
          msOverflowStyle: 'none'
        }}>
          {['DASHBOARD', 'WIFI', 'CLIENTS', 'BLE', 'EVILTWIN', 'MITM', 'PMKID', 'WPS', 'FLOOD', 'CRACK'].map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              style={{
                flexShrink: 0,
                background: activeTab === tab ? '#111' : 'transparent',
                color: activeTab === tab ? 'var(--color-primary)' : '#666',
                border: activeTab === tab ? '1px solid var(--color-primary)' : '1px solid #222',
                borderRadius: '3px',
                padding: '5px 12px',
                cursor: 'pointer',
                fontWeight: 'bold',
                fontFamily: 'var(--font-mono)',
                letterSpacing: '1px',
                fontSize: '11px',
                transition: 'all 0.2s ease',
                whiteSpace: 'nowrap'
              }}
            >
              {tab}
            </button>
          ))}
        </div>

        {/* TABLE VIEW */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '0' }}>

          {/* DASHBOARD TAB */}
          {activeTab === 'DASHBOARD' && (
            <div style={{ padding: '20px' }}>
              {/* Stats Cards Row */}
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                gap: '15px',
                marginBottom: '20px'
              }}>
                {/* WiFi Networks Card */}
                <div className="glass-panel" style={{ padding: '20px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                    <div style={{ fontSize: '11px', color: '#666', letterSpacing: '1px' }}>NETWORKS</div>
                    <div style={{ fontSize: '14px', color: 'var(--color-primary)', fontFamily: 'var(--font-mono)', opacity: 0.4 }}>///</div>
                  </div>
                  <div style={{ fontSize: '2.5rem', fontWeight: 'bold', color: 'var(--color-primary)', fontFamily: 'var(--font-display)' }}>
                    {stats.aps}
                  </div>
                  <div style={{ fontSize: '10px', color: '#555', marginTop: '5px' }}>
                    {networks.filter(n => n.band === '2.4GHz').length} @ 2.4GHz • {networks.filter(n => n.band === '5GHz').length} @ 5GHz
                  </div>
                </div>

                {/* Handshakes Card */}
                <div className="glass-panel" style={{ padding: '20px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                    <div style={{ fontSize: '11px', color: '#666', letterSpacing: '1px' }}>CAPTURED</div>
                    <div style={{ fontSize: '14px', color: 'var(--color-danger)', fontFamily: 'var(--font-mono)', opacity: 0.4 }}>///</div>
                  </div>
                  <div style={{ fontSize: '2.5rem', fontWeight: 'bold', color: 'var(--color-danger)', fontFamily: 'var(--font-display)' }}>
                    {capturedNetworks.length}
                  </div>
                  <div style={{ fontSize: '10px', color: '#555', marginTop: '5px' }}>
                    {networks.filter(n => n.pwned).length} active • {capturedNetworks.length - networks.filter(n => n.pwned).length} stored
                  </div>
                </div>

                {/* BLE Devices Card */}
                <div className="glass-panel" style={{ padding: '20px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                    <div style={{ fontSize: '11px', color: '#666', letterSpacing: '1px' }}>BLE DEVICES</div>
                    <div style={{ fontSize: '14px', color: '#00bfff', fontFamily: 'var(--font-mono)', opacity: 0.4 }}>///</div>
                  </div>
                  <div style={{ fontSize: '2.5rem', fontWeight: 'bold', color: '#00bfff', fontFamily: 'var(--font-display)' }}>
                    {bleDevices.length}
                  </div>
                  <div style={{ fontSize: '10px', color: '#555', marginTop: '5px' }}>
                    {bleDevices.filter(d => d.is_random_mac).length} random MAC • {watchedDevices.size} watched
                  </div>
                </div>

                {/* WiFi Clients Card */}
                <div className="glass-panel" style={{ padding: '20px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                    <div style={{ fontSize: '11px', color: '#666', letterSpacing: '1px' }}>CLIENTS</div>
                    <div style={{ fontSize: '14px', color: '#ffa500', fontFamily: 'var(--font-mono)', opacity: 0.4 }}>///</div>
                  </div>
                  <div style={{ fontSize: '2.5rem', fontWeight: 'bold', color: '#ffa500', fontFamily: 'var(--font-display)' }}>
                    {stats.clients}
                  </div>
                  <div style={{ fontSize: '10px', color: '#555', marginTop: '5px' }}>
                    {wifiClients ? wifiClients.filter(c => c && c.connected_to).length : 0} connected • {wifiClients ? wifiClients.filter(c => c && !c.connected_to).length : 0} probing
                  </div>
                </div>
              </div>

              {/* Active Attacks Row */}
              <div className="glass-panel" style={{ padding: '15px 20px', marginBottom: '20px' }}>
                <div style={{ fontSize: '11px', color: '#666', letterSpacing: '1px', marginBottom: '12px', fontWeight: 'bold' }}>
                  ACTIVE OPERATIONS
                </div>
                <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                  {[
                    { label: 'WIFI SCAN', active: wifiActive, color: '#0f0' },
                    { label: 'BLE RADAR', active: bleActive, color: '#00bfff' },
                    { label: 'HUNTER', active: autoPilot, color: 'var(--color-danger)' },
                    { label: 'EVIL TWIN', active: eviltwinRunning, color: eviltwinStatus?.mode === 'internet_relay' ? '#00ffff' : '#ff0' },
                    { label: 'MITM', active: mitmSnifferRunning, color: '#00ffff' },
                    { label: 'CRACK', active: cracking, color: '#ff0' },
                  ].map(op => (
                    <div key={op.label} style={{
                      display: 'flex', alignItems: 'center', gap: '6px',
                      padding: '6px 12px', borderRadius: '4px',
                      background: op.active ? 'rgba(255,255,255,0.03)' : 'transparent',
                      border: `1px solid ${op.active ? op.color : '#1a1a1a'}`,
                      opacity: op.active ? 1 : 0.3
                    }}>
                      <div style={{
                        width: '6px', height: '6px', borderRadius: '50%',
                        background: op.active ? op.color : '#333',
                        boxShadow: op.active ? `0 0 8px ${op.color}` : 'none'
                      }}/>
                      <span style={{ fontSize: '10px', color: op.active ? op.color : '#444', fontWeight: 'bold' }}>{op.label}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Activity Overview */}
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '15px', marginBottom: '20px' }}>
                {/* Top Networks */}
                <div className="glass-panel" style={{ padding: '20px' }}>
                  <div style={{ fontSize: '12px', color: '#666', letterSpacing: '1px', marginBottom: '15px', fontWeight: 'bold' }}>
                    TOP NETWORKS BY SIGNAL
                  </div>
                  {networks.slice().sort((a, b) => b.signal - a.signal).slice(0, 5).map((net, idx) => (
                    <div key={net.bssid} style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      padding: '10px',
                      marginBottom: '8px',
                      background: idx === 0 ? 'rgba(0, 255, 255, 0.05)' : 'rgba(255, 255, 255, 0.02)',
                      borderRadius: '4px',
                      border: `1px solid ${idx === 0 ? 'var(--color-primary)' : '#222'}`
                    }}>
                      <div style={{ flex: 1 }}>
                        <div style={{ color: '#eee', fontSize: '13px', fontWeight: 'bold' }}>
                          {net.ssid || '<HIDDEN>'}
                        </div>
                        <div style={{ color: '#666', fontSize: '10px', fontFamily: 'monospace' }}>{net.bssid}</div>
                      </div>
                      <div style={{ textAlign: 'right' }}>
                        <div style={{
                          color: net.signal > -60 ? 'var(--color-primary)' : (net.signal > -80 ? 'var(--color-warning)' : 'var(--color-danger)'),
                          fontSize: '14px',
                          fontWeight: 'bold'
                        }}>
                          {net.signal} dBm
                        </div>
                        <div style={{ color: '#888', fontSize: '10px' }}>CH {net.channel}</div>
                      </div>
                    </div>
                  ))}
                  {networks.length === 0 && (
                    <div style={{ textAlign: 'center', color: '#444', padding: '20px', fontSize: '12px' }}>
                      Start WiFi scanner to see networks
                    </div>
                  )}
                </div>

                {/* System Status */}
                <div className="glass-panel" style={{ padding: '20px' }}>
                  <div style={{ fontSize: '12px', color: '#666', letterSpacing: '1px', marginBottom: '15px', fontWeight: 'bold' }}>
                    SYSTEM STATUS
                  </div>

                  <div style={{ marginBottom: '12px' }}>
                    <div style={{ fontSize: '10px', color: '#666', marginBottom: '4px' }}>BACKEND</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <div style={{
                        width: '8px',
                        height: '8px',
                        borderRadius: '50%',
                        background: status === 'connected' ? 'var(--color-primary)' : 'var(--color-danger)',
                        boxShadow: status === 'connected' ? '0 0 10px var(--color-primary)' : 'none'
                      }}></div>
                      <span style={{ color: '#eee', fontSize: '12px', fontWeight: 'bold' }}>
                        {status === 'connected' ? 'ONLINE' : 'OFFLINE'}
                      </span>
                    </div>
                  </div>

                  <div style={{ marginBottom: '12px' }}>
                    <div style={{ fontSize: '10px', color: '#666', marginBottom: '4px' }}>WIFI SCANNER</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <div style={{
                        width: '8px',
                        height: '8px',
                        borderRadius: '50%',
                        background: wifiActive ? '#0f0' : '#333'
                      }}></div>
                      <span style={{ color: '#eee', fontSize: '12px' }}>
                        {wifiActive ? 'ACTIVE' : 'IDLE'}
                      </span>
                    </div>
                  </div>

                  <div style={{ marginBottom: '12px' }}>
                    <div style={{ fontSize: '10px', color: '#666', marginBottom: '4px' }}>BLE RADAR</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <div style={{
                        width: '8px',
                        height: '8px',
                        borderRadius: '50%',
                        background: bleActive ? '#00bfff' : '#333'
                      }}></div>
                      <span style={{ color: '#eee', fontSize: '12px' }}>
                        {bleActive ? 'SCANNING' : 'IDLE'}
                      </span>
                    </div>
                  </div>

                  <div style={{ marginBottom: '12px' }}>
                    <div style={{ fontSize: '10px', color: '#666', marginBottom: '4px' }}>HUNTER MODE</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <div style={{
                        width: '8px',
                        height: '8px',
                        borderRadius: '50%',
                        background: autoPilot ? 'var(--color-danger)' : '#333'
                      }}></div>
                      <span style={{ color: '#eee', fontSize: '12px' }}>
                        {autoPilot ? hunterStatus.status : 'DISABLED'}
                      </span>
                    </div>
                  </div>

                  <div style={{ marginTop: '15px', paddingTop: '15px', borderTop: '1px solid #222' }}>
                    <div style={{ fontSize: '10px', color: '#666', marginBottom: '4px' }}>MODE</div>
                    <div style={{
                      color: 'var(--color-primary)',
                      fontSize: '13px',
                      fontWeight: 'bold',
                      fontFamily: 'monospace'
                    }}>
                      {mode}
                    </div>
                  </div>
                </div>
              </div>

              {/* Security Overview Row */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px', marginBottom: '20px' }}>
                {/* Encryption Distribution */}
                <div className="glass-panel" style={{ padding: '20px' }}>
                  <div style={{ fontSize: '12px', color: '#666', letterSpacing: '1px', marginBottom: '15px', fontWeight: 'bold' }}>
                    ENCRYPTION DISTRIBUTION
                  </div>
                  {(() => {
                    const encMap = {};
                    networks.forEach(n => {
                      const enc = n.encryption || 'OPEN';
                      encMap[enc] = (encMap[enc] || 0) + 1;
                    });
                    const total = networks.length || 1;
                    const encColors = { 'WPA3': '#0f0', 'WPA2': '#00ffff', 'WPA': '#ff0', 'WEP': '#f80', 'OPEN': '#f00' };
                    const sorted = Object.entries(encMap).sort((a, b) => b[1] - a[1]);
                    return sorted.length > 0 ? sorted.map(([enc, count]) => (
                      <div key={enc} style={{ marginBottom: '8px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', marginBottom: '3px' }}>
                          <span style={{ color: encColors[enc] || '#888', fontWeight: 'bold' }}>{enc}</span>
                          <span style={{ color: '#666' }}>{count} ({Math.round(count / total * 100)}%)</span>
                        </div>
                        <div style={{ height: '4px', background: '#111', borderRadius: '2px', overflow: 'hidden' }}>
                          <div style={{
                            width: `${(count / total) * 100}%`,
                            height: '100%',
                            background: encColors[enc] || '#888',
                            borderRadius: '2px',
                            transition: 'width 0.5s'
                          }}/>
                        </div>
                      </div>
                    )) : (
                      <div style={{ textAlign: 'center', color: '#444', padding: '20px', fontSize: '11px' }}>No networks scanned yet</div>
                    );
                  })()}
                </div>

                {/* Channel Usage */}
                <div className="glass-panel" style={{ padding: '20px' }}>
                  <div style={{ fontSize: '12px', color: '#666', letterSpacing: '1px', marginBottom: '15px', fontWeight: 'bold' }}>
                    CHANNEL USAGE
                  </div>
                  {(() => {
                    const chMap = {};
                    networks.forEach(n => {
                      if (!n.channel || n.channel === 0) return;
                      const ch = n.channel;
                      chMap[ch] = (chMap[ch] || 0) + 1;
                    });
                    const maxCount = Math.max(...Object.values(chMap), 1);
                    const sorted = Object.entries(chMap).sort((a, b) => Number(a[0]) - Number(b[0]));
                    return sorted.length > 0 ? (
                      <div style={{ display: 'flex', alignItems: 'flex-end', gap: '3px', height: '100px' }}>
                        {sorted.map(([ch, count]) => (
                          <div key={ch} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                            <div style={{
                              width: '100%', maxWidth: '20px',
                              height: `${(count / maxCount) * 80}px`,
                              background: count === maxCount ? '#ff0055' : 'var(--color-primary)',
                              borderRadius: '2px 2px 0 0',
                              opacity: 0.7,
                              transition: 'height 0.5s'
                            }}/>
                            <div style={{ fontSize: '8px', color: '#666', marginTop: '3px' }}>{ch}</div>
                            <div style={{ fontSize: '7px', color: '#444' }}>{count}</div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div style={{ textAlign: 'center', color: '#444', padding: '20px', fontSize: '11px' }}>No networks scanned yet</div>
                    );
                  })()}
                </div>
              </div>

              {/* Recent Activity */}
              <div className="glass-panel" style={{ padding: '20px' }}>
                <div style={{ fontSize: '12px', color: '#666', letterSpacing: '1px', marginBottom: '15px', fontWeight: 'bold' }}>
                  RECENT ACTIVITY
                </div>
                <div style={{
                  maxHeight: '200px',
                  overflowY: 'auto',
                  fontSize: '11px',
                  fontFamily: 'monospace',
                  color: '#888'
                }}>
                  {logs.slice(-10).reverse().map((log, idx) => (
                    <div key={idx} style={{
                      padding: '6px 0',
                      borderBottom: '1px solid #111',
                      color: log.includes('ERROR') || log.includes('❌') ? '#f44' :
                             log.includes('SUCCESS') || log.includes('✅') ? '#0f0' :
                             log.includes('WARN') || log.includes('⚠️') ? '#fa0' : '#888'
                    }}>
                      {log}
                    </div>
                  ))}
                  {logs.length === 0 && (
                    <div style={{ textAlign: 'center', color: '#444', padding: '20px' }}>
                      No recent activity
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'WIFI' && (
            <div>
              {/* WIFI SUB-NAVIGATION */}
              <div style={{
                display: 'flex',
                gap: '10px',
                padding: '15px 20px',
                borderBottom: '1px solid #222',
                background: '#0a0a0a'
              }}>
                {['NETWORKS', 'CAPTURED'].map(subTab => (
                  <button
                    key={subTab}
                    onClick={() => setWifiSubTab(subTab)}
                    className="cyber-button"
                    style={{
                      background: wifiSubTab === subTab ? 'var(--color-primary)' : 'transparent',
                      color: wifiSubTab === subTab ? '#000' : 'var(--color-primary)',
                      border: `1px solid ${wifiSubTab === subTab ? 'var(--color-primary)' : '#333'}`,
                      padding: '8px 16px',
                      fontSize: '11px',
                      fontWeight: 'bold',
                      letterSpacing: '1px'
                    }}
                  >
                    {subTab} {subTab === 'CAPTURED' && `(${capturedNetworks.length})`}
                  </button>
                ))}
              </div>

              {/* NETWORKS TAB */}
              {wifiSubTab === 'NETWORKS' && (
                <div>
                  <div style={{
                    display: 'grid',
                    gridTemplateColumns: 'minmax(180px, 2fr) 40px 60px 50px 40px 40px 50px 200px',
                    padding: '10px 20px',
                    borderBottom: '1px solid #222',
                    background: '#080808',
                    color: '#666',
                    fontSize: '12px',
                    fontWeight: 'bold',
                    position: 'sticky',
                    top: 0,
                    zIndex: 10
                  }}>
                    <div>ESSID / BSSID</div>
                    <div>CH</div>
                    <div>BAND</div>
                    <div>PWR</div>
                    <div>CLN</div>
                    <div>WPS</div>
                    <div>SEC</div>
                    <div>ACTIONS</div>
                  </div>

                  <div>
                    {networks.map(net => (
                      <div key={net.bssid} style={{
                        display: 'grid',
                        gridTemplateColumns: 'minmax(180px, 2fr) 40px 60px 50px 40px 40px 50px 200px',
                        padding: '8px 20px',
                        borderBottom: '1px solid #111',
                        alignItems: 'center',
                        background: net.is_evil_twin ? 'rgba(255, 50, 50, 0.15)' : 'transparent',
                        fontSize: '13px',
                        height: '40px'
                      }}>
                        <div>
                          <div style={{ color: net.is_evil_twin ? '#ff4444' : '#e0e0e0', fontWeight: 'bold' }}>
                            {net.is_evil_twin && "⚠️ "}{net.ssid || '<HIDDEN>'}
                          </div>
                          <div style={{ color: '#444', fontSize: '11px', fontFamily: 'monospace' }}>{net.bssid}</div>
                        </div>
                        <div style={{ color: 'var(--color-primary)' }}>{net.channel}</div>
                        <div style={{ color: '#aaa' }}>{net.band}</div>
                        <div style={{ color: net.signal > -60 ? 'var(--color-primary)' : (net.signal > -80 ? 'var(--color-warning)' : 'var(--color-danger)') }}>{net.signal}</div>
                        <div>{net.clients ? Object.keys(net.clients).length : 0}</div>
                        <div style={{ color: net.wps ? 'var(--color-primary)' : '#333' }}>{net.wps ? 'Y' : 'N'}</div>
                        <div>{net.pwned ? <b style={{ color: 'var(--color-danger)' }}>PWNED</b> : 'WPA2'}</div>
                        <div style={{ display: 'flex', gap: '5px', justifyContent: 'flex-end' }}>
                          {net.pwned && (
                            <button onClick={() => startCrack(net, 'auto')} className="cyber-button gold" style={{ fontSize: '9px', padding: '2px 6px' }}>CRACK</button>
                          )}

                          {mode === net.channel ?
                            <button onClick={() => api('/scan/start')} className="cyber-button" style={{ fontSize: '9px', padding: '2px 6px' }}>UNLOCK</button> :
                            <button onClick={() => api('/scan/target', { channel: net.channel })} className="cyber-button" style={{ fontSize: '9px', padding: '2px 6px', opacity: 0.6 }}>LOCK</button>
                          }
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* CAPTURED TAB */}
              {wifiSubTab === 'CAPTURED' && (
                <div style={{ height: 'calc(100vh - 300px)', display: 'flex', flexDirection: 'column' }}>
                  {/* Captured Networks List */}
                  <div style={{ flex: 1, overflowY: 'auto' }}>
                    {capturedNetworks.length === 0 ? (
                      <div style={{ padding: '40px', textAlign: 'center', color: '#666' }}>
                        <div style={{ fontSize: '48px', marginBottom: '10px' }}>📡</div>
                        <div style={{ fontSize: '14px' }}>No handshakes captured yet</div>
                        <div style={{ fontSize: '11px', marginTop: '5px', color: '#444' }}>Start scanning to capture handshakes</div>
                      </div>
                    ) : (
                      <div>
                        {/* Header with Clear Button */}
                        <div style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          padding: '10px 20px',
                          borderBottom: '1px solid #222',
                          background: '#0a0a0a'
                        }}>
                          <div style={{ color: '#666', fontSize: '11px', fontWeight: 'bold' }}>
                            {capturedNetworks.length} HANDSHAKE{capturedNetworks.length !== 1 ? 'S' : ''} CAPTURED
                          </div>
                          <div style={{ display: 'flex', gap: '5px' }}>
                            <button
                              onClick={() => {
                                // Deduplicate by BSSID
                                const unique = capturedNetworks.filter((net, idx, arr) =>
                                  arr.findIndex(n => n.bssid === net.bssid) === idx
                                );
                                setCapturedNetworks(unique);
                              }}
                              className="cyber-button"
                              style={{ fontSize: '9px', padding: '4px 8px' }}
                            >
                              🔄 DEDUPE
                            </button>
                            <button
                              onClick={() => {
                                if (confirm('Clear all captured handshakes?')) {
                                  setCapturedNetworks([]);
                                }
                              }}
                              className="cyber-button red"
                              style={{ fontSize: '9px', padding: '4px 8px' }}
                            >
                              🗑️ CLEAR ALL
                            </button>
                          </div>
                        </div>

                        <div style={{
                          display: 'grid',
                          gridTemplateColumns: 'minmax(180px, 2fr) 50px 50px 120px 200px',
                          padding: '10px 20px',
                          borderBottom: '1px solid #222',
                          background: '#080808',
                          color: '#666',
                          fontSize: '12px',
                          fontWeight: 'bold',
                          position: 'sticky',
                          top: 0,
                          zIndex: 10
                        }}>
                          <div>ESSID / BSSID</div>
                          <div>CH</div>
                          <div>PWR</div>
                          <div>CAPTURED</div>
                          <div>ACTIONS</div>
                        </div>

                        {capturedNetworks.map(net => (
                          <div key={net.bssid} style={{
                            display: 'grid',
                            gridTemplateColumns: 'minmax(180px, 2fr) 50px 50px 120px 200px',
                            padding: '8px 20px',
                            borderBottom: '1px solid #111',
                            alignItems: 'center',
                            background: crackTarget?.bssid === net.bssid ? 'rgba(0, 255, 255, 0.1)' : 'transparent',
                            fontSize: '13px',
                            height: '40px'
                          }}>
                            <div>
                              <div style={{ color: '#e0e0e0', fontWeight: 'bold' }}>
                                🎯 {net.ssid || '<HIDDEN>'}
                              </div>
                              <div style={{ color: '#444', fontSize: '11px', fontFamily: 'monospace' }}>{net.bssid}</div>
                            </div>
                            <div style={{ color: 'var(--color-primary)' }}>{net.channel}</div>
                            <div style={{ color: net.signal > -60 ? 'var(--color-primary)' : (net.signal > -80 ? 'var(--color-warning)' : 'var(--color-danger)') }}>{net.signal}</div>
                            <div style={{ color: '#888', fontSize: '10px' }}>
                              {new Date(net.capturedAt).toLocaleTimeString()}
                            </div>
                            <div style={{ display: 'flex', gap: '5px', justifyContent: 'flex-end' }}>
                              <button
                                onClick={() => startCrack(net, 'auto')}
                                className="cyber-button gold"
                                style={{ fontSize: '9px', padding: '2px 6px' }}
                                disabled={cracking}
                              >
                                {crackTarget?.bssid === net.bssid && cracking ? 'CRACKING...' : 'CRACK'}
                              </button>
                              <button
                                onClick={() => setCapturedNetworks(prev => prev.filter(n => n.bssid !== net.bssid))}
                                className="cyber-button"
                                style={{ fontSize: '9px', padding: '2px 6px', opacity: 0.6 }}
                              >
                                REMOVE
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Cracking now in unified CRACK tab */}
                </div>
              )}
            </div>
          )}

          {activeTab === 'BLE' && (
            <div>
              {/* BLE SUB-NAVIGATION */}
              <div style={{
                display: 'flex',
                gap: '10px',
                padding: '15px 20px',
                borderBottom: '2px solid #222',
                background: '#080808'
              }}>
                <button
                  onClick={() => setBleSubTab('SCAN')}
                  className="cyber-button"
                  style={{
                    background: bleSubTab === 'SCAN' ? 'var(--color-secondary)' : 'transparent',
                    color: bleSubTab === 'SCAN' ? '#000' : 'var(--color-secondary)',
                    borderColor: 'var(--color-secondary)',
                    fontSize: '12px',
                    padding: '8px 20px',
                    fontWeight: 'bold'
                  }}
                >
                  📡 SCAN & WATCH
                </button>
                <button
                  onClick={() => setBleSubTab('ATTACK')}
                  className="cyber-button"
                  style={{
                    background: bleSubTab === 'ATTACK' ? '#ff0000' : 'transparent',
                    color: bleSubTab === 'ATTACK' ? '#fff' : '#ff0000',
                    borderColor: '#ff0000',
                    fontSize: '12px',
                    padding: '8px 20px',
                    fontWeight: 'bold'
                  }}
                >
                  ⚔️ ATTACK
                </button>
              </div>

              {/* SCAN TAB CONTENT */}
              {bleSubTab === 'SCAN' && (
                <div>
              {/* WATCHED DEVICES SECTION */}
              {watchedDevices.size > 0 && (
                <div style={{ borderBottom: '1px solid rgba(0, 255, 255, 0.2)', marginBottom: '10px' }}>
                  <div style={{ padding: '10px 20px', background: 'rgba(0, 255, 255, 0.05)', borderBottom: '1px solid rgba(0, 255, 255, 0.15)' }}>
                    <span style={{ color: 'var(--color-primary)', fontSize: '11px', fontWeight: 'bold', letterSpacing: '1px' }}>
                      👁️ WATCHED DEVICES ({watchedDevices.size})
                    </span>
                  </div>
                  <div style={{
                    display: 'grid',
                    gridTemplateColumns: '110px 1fr 50px 55px 50px 60px 140px',
                    padding: '8px 20px',
                    borderBottom: '1px solid #333',
                    background: '#0a0a0a',
                    color: '#888',
                    fontSize: '10px',
                    fontWeight: 'bold',
                    position: 'sticky',
                    top: 0,
                    zIndex: 11
                  }}>
                    <div>MAC ADDRESS</div>
                    <div>NAME / VENDOR</div>
                    <div>RSSI</div>
                    <div>DIST</div>
                    <div>MAC</div>
                    <div>TYPE</div>
                    <div>STATUS</div>
                  </div>
                  {Array.from(watchedDevices).map((mac) => {
                    const dev = bleDevices.find(d => d.mac === mac);
                    const isInRange = !!dev;
                    const savedInfo = watchedDeviceInfo[mac];
                    const displayName = dev?.name || savedInfo?.name || 'Unknown Device';
                    const displayVendor = dev?.vendor || savedInfo?.vendor || 'Unknown';
                    const lastSeen = savedInfo?.last_seen;
                    const timeSinceLastSeen = lastSeen ? Math.floor((Date.now() - lastSeen) / 1000) : null;

                    const watchedDistance = dev?.distance ? `${dev.distance.toFixed(1)}m` : '--';
                    const isRandom = dev?.is_random_mac || false;
                    const randomConfidence = dev?.random_mac_confidence || 0;

                    return (
                      <div key={mac} style={{
                        display: 'grid',
                        gridTemplateColumns: '110px 1fr 50px 55px 50px 60px 140px',
                        padding: '8px 20px',
                        borderBottom: '1px solid #222',
                        alignItems: 'center',
                        fontSize: '13px',
                        background: isInRange ? 'rgba(0, 255, 255, 0.08)' : 'rgba(50, 50, 50, 0.3)',
                        borderLeft: '3px solid var(--color-primary)',
                        opacity: isInRange ? 1 : 0.6
                      }}>
                        <div style={{ fontFamily: 'monospace', color: 'var(--color-primary)', fontSize: '10px' }}>
                          👁️ {mac}
                        </div>
                        <div>
                          <div style={{ color: isInRange ? '#fff' : '#888', fontWeight: 'bold' }}>
                            {displayName}
                          </div>
                          <div style={{ fontSize: '9px', color: '#666' }}>
                            {displayVendor}
                            {!isInRange && timeSinceLastSeen && (
                              <span style={{ marginLeft: '5px', color: '#555' }}>
                                • Last seen {timeSinceLastSeen < 60 ? `${timeSinceLastSeen}s ago` : `${Math.floor(timeSinceLastSeen / 60)}m ago`}
                              </span>
                            )}
                          </div>
                        </div>
                        <div style={{ color: isInRange ? (dev.rssi > -70 ? 'var(--color-secondary)' : '#888') : '#444' }}>
                          {dev?.rssi || '--'}
                        </div>
                        <div style={{
                          color: dev?.distance && dev.distance < 2 ? '#0f0' :
                                 dev?.distance && dev.distance < 5 ? '#ff0' : '#444',
                          fontSize: '11px',
                          fontWeight: 'bold'
                        }}>
                          {watchedDistance}
                        </div>
                        <div style={{ fontSize: '9px' }}>
                          {isRandom && randomConfidence >= 0.5 ? (
                            <div style={{ color: '#ff9500', background: 'rgba(255,149,0,0.15)', padding: '2px 4px', borderRadius: '2px', border: '1px solid rgba(255,149,0,0.3)', display: 'inline-block' }}>
                              🔀 {(randomConfidence * 100).toFixed(0)}%
                            </div>
                          ) : (
                            <span style={{ color: '#666' }}>FIXED</span>
                          )}
                        </div>
                        <div style={{ fontSize: '16px', opacity: isInRange ? 1 : 0.3 }}>
                          {dev ? getBleIcon(dev.name, dev.vendor) : '📡'}
                        </div>
                        <div style={{ display: 'flex', gap: '5px', alignItems: 'center' }}>
                          {isInRange ? (
                            <>
                              <span style={{ fontSize: '9px', color: '#0f0', background: 'rgba(0,255,0,0.1)', padding: '2px 6px', borderRadius: '3px' }}>IN RANGE</span>
                              <button onClick={() => inspectBle(dev)} className="cyber-button blue" style={{ fontSize: '9px', padding: '2px 6px' }}>INSPECT</button>
                            </>
                          ) : (
                            <span style={{ fontSize: '9px', color: '#666', background: 'rgba(100,100,100,0.1)', padding: '2px 6px', borderRadius: '3px' }}>OUT OF RANGE</span>
                          )}
                          <button onClick={() => toggleWatch(mac)} className="cyber-button red" style={{ fontSize: '9px', padding: '2px 6px' }}>UNWATCH</button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              {/* ACTIVE DEVICES SECTION */}
              <div style={{
                display: 'grid',
                gridTemplateColumns: '110px 1fr 50px 55px 50px 60px 140px',
                padding: '10px 20px',
                borderBottom: '1px solid #222',
                background: '#080808',
                color: 'var(--color-secondary)',
                fontSize: '12px',
                fontWeight: 'bold',
                position: 'sticky',
                top: 0,
                zIndex: 10
              }}>
                <div>MAC ADDRESS</div>
                <div>NAME / VENDOR</div>
                <div>RSSI</div>
                <div>DIST</div>
                <div>MAC</div>
                <div>TYPE</div>
                <div>ACTIONS</div>
              </div>
              <div>
                {bleDevices && bleDevices.map((dev, i) => {
                  if (!dev) return null;
                  const distance = dev.distance ? `${dev.distance.toFixed(1)}m` : '?';
                  const isRandom = dev.is_random_mac || false;
                  const randomConfidence = dev.random_mac_confidence || 0;

                  return (
                    <div key={i} style={{
                      display: 'grid',
                      gridTemplateColumns: '110px 1fr 50px 55px 50px 60px 140px',
                      padding: '8px 20px',
                      borderBottom: '1px solid #111',
                      alignItems: 'center',
                      fontSize: '13px',
                      color: watchedDevices.has(dev.mac) ? '#ffd700' : '#ccc',
                      background: watchedDevices.has(dev.mac) ? 'rgba(255, 215, 0, 0.1)' : 'transparent',
                      height: '40px',
                      borderLeft: watchedDevices.has(dev.mac) ? '2px solid #ffd700' : 'none'
                    }}>
                      <div style={{ fontFamily: 'monospace', color: watchedDevices.has(dev.mac) ? '#ffd700' : '#666', fontSize: '10px' }}>
                        {watchedDevices.has(dev.mac) && "👁️ "}{dev.mac}
                      </div>
                      <div>
                        <div style={{ color: watchedDevices.has(dev.mac) ? '#fff' : '#e0e0e0', fontWeight: watchedDevices.has(dev.mac) ? 'bold' : 'normal' }}>
                          {dev.name || 'Unknown'}
                        </div>
                        <div style={{ fontSize: '9px', color: '#444' }}>{dev.vendor}</div>
                      </div>
                      <div style={{ color: dev.rssi > -70 ? 'var(--color-secondary)' : '#555' }}>
                        {dev.rssi}
                      </div>
                      <div style={{
                        color: dev.distance && dev.distance < 2 ? '#0f0' :
                               dev.distance && dev.distance < 5 ? '#ff0' : '#888',
                        fontSize: '11px',
                        fontWeight: 'bold'
                      }}>
                        {distance}
                      </div>
                      <div style={{ fontSize: '9px' }}>
                        {isRandom && randomConfidence >= 0.5 ? (
                          <div style={{ color: '#ff9500', background: 'rgba(255,149,0,0.15)', padding: '2px 4px', borderRadius: '2px', border: '1px solid rgba(255,149,0,0.3)', display: 'inline-block' }}>
                            🔀 {(randomConfidence * 100).toFixed(0)}%
                          </div>
                        ) : (
                          <span style={{ color: '#666' }}>FIXED</span>
                        )}
                      </div>
                      <div style={{ fontSize: '16px' }}>{getBleIcon(dev.name, dev.vendor)}</div>
                      <div style={{ display: 'flex', gap: '5px' }}>
                        <button onClick={() => inspectBle(dev)} className="cyber-button blue" style={{ fontSize: '9px', padding: '2px 6px' }}>INSPECT</button>
                        <button onClick={() => toggleWatch(dev.mac, dev)} className="cyber-button" style={{
                          fontSize: '9px',
                          padding: '2px 6px',
                          color: watchedDevices.has(dev.mac) ? '#000' : '#666',
                          background: watchedDevices.has(dev.mac) ? '#ffd700' : 'transparent',
                          borderColor: watchedDevices.has(dev.mac) ? '#ffd700' : '#444'
                        }}>
                          {watchedDevices.has(dev.mac) ? 'UNWATCH' : 'WATCH'}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
                </div>
              )}

              {/* ATTACK TAB CONTENT */}
              {bleSubTab === 'ATTACK' && (
                <div style={{ padding: '20px' }}>
                  <div style={{
                    background: 'rgba(255, 0, 0, 0.1)',
                    border: '2px solid #ff0000',
                    borderRadius: '8px',
                    padding: '20px',
                    marginBottom: '20px'
                  }}>
                    <h3 style={{ color: '#ff0000', marginBottom: '10px', fontSize: '16px' }}>⚠️ BLE ATTACK MODULE</h3>
                    <p style={{ color: '#888', fontSize: '11px', marginBottom: '15px' }}>
                      Automated penetration testing tools for BLE devices. Use responsibly and only on authorized devices.
                    </p>

                    {/* Attack Type Selection */}
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '15px', marginBottom: '20px' }}>
                      {/* Auto-Connect Vulnerable */}
                      <div style={{
                        background: '#0a0a0a',
                        border: '1px solid #333',
                        borderRadius: '6px',
                        padding: '15px',
                        cursor: bleAttackRunning ? 'not-allowed' : 'pointer',
                        opacity: bleAttackRunning ? 0.5 : 1,
                        transition: 'all 0.2s'
                      }}
                      onClick={() => !bleAttackRunning && startBleAttack('auto_connect')}
                      onMouseEnter={(e) => !bleAttackRunning && (e.currentTarget.style.borderColor = 'var(--color-secondary)')}
                      onMouseLeave={(e) => e.currentTarget.style.borderColor = '#333'}
                      >
                        <div style={{ fontSize: '20px', marginBottom: '8px' }}>🔍</div>
                        <div style={{ color: 'var(--color-secondary)', fontWeight: 'bold', marginBottom: '5px' }}>Auto-Connect Vulnerable</div>
                        <div style={{ fontSize: '10px', color: '#666' }}>
                          Scans and connects to devices with known vulnerable services
                        </div>
                      </div>

                      {/* PIN Bruteforce */}
                      <div style={{
                        background: '#0a0a0a',
                        border: '1px solid #333',
                        borderRadius: '6px',
                        padding: '15px',
                        cursor: bleAttackRunning || !selectedAttackTarget ? 'not-allowed' : 'pointer',
                        opacity: bleAttackRunning || !selectedAttackTarget ? 0.5 : 1,
                        transition: 'all 0.2s'
                      }}
                      onClick={() => !bleAttackRunning && selectedAttackTarget && startBleAttack('pin_bruteforce', selectedAttackTarget)}
                      onMouseEnter={(e) => !bleAttackRunning && selectedAttackTarget && (e.currentTarget.style.borderColor = '#ff0')}
                      onMouseLeave={(e) => e.currentTarget.style.borderColor = '#333'}
                      >
                        <div style={{ fontSize: '20px', marginBottom: '8px' }}>🔑</div>
                        <div style={{ color: '#ff0', fontWeight: 'bold', marginBottom: '5px' }}>PIN Bruteforce</div>
                        <div style={{ fontSize: '10px', color: '#666' }}>
                          Tests common PINs (0000, 1234, etc.) on selected device
                        </div>
                        {!selectedAttackTarget && <div style={{ fontSize: '9px', color: '#f00', marginTop: '5px' }}>⚠️ Select target first</div>}
                      </div>

                      {/* Characteristic Fuzzing */}
                      <div style={{
                        background: '#0a0a0a',
                        border: '1px solid #333',
                        borderRadius: '6px',
                        padding: '15px',
                        cursor: bleAttackRunning || !selectedAttackTarget ? 'not-allowed' : 'pointer',
                        opacity: bleAttackRunning || !selectedAttackTarget ? 0.5 : 1,
                        transition: 'all 0.2s'
                      }}
                      onClick={() => !bleAttackRunning && selectedAttackTarget && startBleAttack('fuzzing', selectedAttackTarget)}
                      onMouseEnter={(e) => !bleAttackRunning && selectedAttackTarget && (e.currentTarget.style.borderColor = '#f0f')}
                      onMouseLeave={(e) => e.currentTarget.style.borderColor = '#333'}
                      >
                        <div style={{ fontSize: '20px', marginBottom: '8px' }}>🧪</div>
                        <div style={{ color: '#f0f', fontWeight: 'bold', marginBottom: '5px' }}>Characteristic Fuzzing</div>
                        <div style={{ fontSize: '10px', color: '#666' }}>
                          Sends malformed data to find vulnerable characteristics
                        </div>
                        {!selectedAttackTarget && <div style={{ fontSize: '9px', color: '#f00', marginTop: '5px' }}>⚠️ Select target first</div>}
                      </div>

                      {/* Command Injection Test */}
                      <div style={{
                        background: '#0a0a0a',
                        border: '1px solid #333',
                        borderRadius: '6px',
                        padding: '15px',
                        cursor: bleAttackRunning || !selectedAttackTarget ? 'not-allowed' : 'pointer',
                        opacity: bleAttackRunning || !selectedAttackTarget ? 0.5 : 1,
                        transition: 'all 0.2s'
                      }}
                      onClick={() => !bleAttackRunning && selectedAttackTarget && startBleAttack('command_injection', selectedAttackTarget)}
                      onMouseEnter={(e) => !bleAttackRunning && selectedAttackTarget && (e.currentTarget.style.borderColor = '#0ff')}
                      onMouseLeave={(e) => e.currentTarget.style.borderColor = '#333'}
                      >
                        <div style={{ fontSize: '20px', marginBottom: '8px' }}>💉</div>
                        <div style={{ color: '#0ff', fontWeight: 'bold', marginBottom: '5px' }}>Command Injection Test</div>
                        <div style={{ fontSize: '10px', color: '#666' }}>
                          Tests for command injection vulnerabilities in UART services
                        </div>
                        {!selectedAttackTarget && <div style={{ fontSize: '9px', color: '#f00', marginTop: '5px' }}>⚠️ Select target first</div>}
                      </div>

                      {/* BLE Hijacking */}
                      <div style={{
                        background: '#0a0a0a',
                        border: '1px solid #333',
                        borderRadius: '6px',
                        padding: '15px',
                        cursor: bleAttackRunning || !selectedAttackTarget ? 'not-allowed' : 'pointer',
                        opacity: bleAttackRunning || !selectedAttackTarget ? 0.5 : 1,
                        transition: 'all 0.2s'
                      }}
                      onClick={() => !bleAttackRunning && selectedAttackTarget && startBleAttack('hijacking', selectedAttackTarget)}
                      onMouseEnter={(e) => !bleAttackRunning && selectedAttackTarget && (e.currentTarget.style.borderColor = '#f00')}
                      onMouseLeave={(e) => e.currentTarget.style.borderColor = '#333'}
                      >
                        <div style={{ fontSize: '20px', marginBottom: '8px' }}>🎯</div>
                        <div style={{ color: '#f00', fontWeight: 'bold', marginBottom: '5px' }}>BLE Hijacking</div>
                        <div style={{ fontSize: '10px', color: '#666' }}>
                          Intercepts and monitors all communication with target device
                        </div>
                        {!selectedAttackTarget && <div style={{ fontSize: '9px', color: '#f00', marginTop: '5px' }}>⚠️ Select target first</div>}
                      </div>

                      {/* Battery Drain Attack */}
                      <div style={{
                        background: '#0a0a0a',
                        border: '1px solid #333',
                        borderRadius: '6px',
                        padding: '15px',
                        cursor: bleAttackRunning || !selectedAttackTarget ? 'not-allowed' : 'pointer',
                        opacity: bleAttackRunning || !selectedAttackTarget ? 0.5 : 1,
                        transition: 'all 0.2s'
                      }}
                      onClick={() => !bleAttackRunning && selectedAttackTarget && startBleAttack('battery_drain', selectedAttackTarget)}
                      onMouseEnter={(e) => !bleAttackRunning && selectedAttackTarget && (e.currentTarget.style.borderColor = '#ff6600')}
                      onMouseLeave={(e) => e.currentTarget.style.borderColor = '#333'}
                      >
                        <div style={{ fontSize: '20px', marginBottom: '8px' }}>🔋</div>
                        <div style={{ color: '#ff6600', fontWeight: 'bold', marginBottom: '5px' }}>Battery Drain Attack</div>
                        <div style={{ fontSize: '10px', color: '#666' }}>
                          Drains target device battery via connection flooding and spam
                        </div>
                        {!selectedAttackTarget && <div style={{ fontSize: '9px', color: '#f00', marginTop: '5px' }}>⚠️ Select target first</div>}
                      </div>

                      {/* Beacon Spoof */}
                      <div style={{
                        background: '#0a0a0a',
                        border: '1px solid #333',
                        borderRadius: '6px',
                        padding: '15px',
                        cursor: bleAttackRunning ? 'not-allowed' : 'pointer',
                        opacity: bleAttackRunning ? 0.5 : 1,
                        transition: 'all 0.2s'
                      }}
                      onClick={() => !bleAttackRunning && setShowBeaconSpoofPanel(!showBeaconSpoofPanel)}
                      onMouseEnter={(e) => !bleAttackRunning && (e.currentTarget.style.borderColor = '#00ff88')}
                      onMouseLeave={(e) => e.currentTarget.style.borderColor = '#333'}
                      >
                        <div style={{ fontSize: '20px', marginBottom: '8px' }}>📡</div>
                        <div style={{ color: '#00ff88', fontWeight: 'bold', marginBottom: '5px' }}>Beacon Spoof</div>
                        <div style={{ fontSize: '10px', color: '#666' }}>
                          Broadcast fake BLE beacons (iBeacon, Eddystone, Name Clone, Flood)
                        </div>
                      </div>
                    </div>

                    {/* Beacon Spoof Config Panel */}
                    {showBeaconSpoofPanel && !bleAttackRunning && (
                      <div style={{ background: '#0a0a0a', border: '2px solid #00ff88', borderRadius: '8px', padding: '20px', marginBottom: '20px' }}>
                        <h4 style={{ color: '#00ff88', marginBottom: '15px', fontSize: '14px', margin: '0 0 15px 0' }}>BEACON SPOOF CONFIGURATION</h4>
                        <div style={{ display: 'flex', gap: '10px', marginBottom: '15px', flexWrap: 'wrap' }}>
                          {[
                            { id: 'ibeacon', label: 'iBeacon', color: '#00ff88' },
                            { id: 'eddystone_url', label: 'Eddystone-URL', color: '#00aaff' },
                            { id: 'name_clone', label: 'Name Clone', color: '#ff00ff' },
                            { id: 'flood', label: 'BLE Flood', color: '#ff0000' }
                          ].map(m => (
                            <button key={m.id} onClick={() => setBeaconSpoofMode(m.id)} style={{
                              padding: '8px 16px',
                              background: beaconSpoofMode === m.id ? `${m.color}22` : 'transparent',
                              border: `1px solid ${beaconSpoofMode === m.id ? m.color : '#444'}`,
                              color: beaconSpoofMode === m.id ? m.color : '#888',
                              borderRadius: '4px', cursor: 'pointer', fontSize: '11px', fontWeight: 'bold'
                            }}>{m.label}</button>
                          ))}
                        </div>

                        {beaconSpoofMode === 'ibeacon' && (
                          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                            <div style={{ gridColumn: '1 / -1' }}>
                              <label style={{ color: '#888', fontSize: '10px' }}>UUID (leave blank for random)</label>
                              <input type="text" placeholder="e.g. FDA50693-A4E2-4FB1-AFCF-C6EB07647825"
                                value={beaconSpoofConfig.uuid}
                                onChange={(e) => setBeaconSpoofConfig(p => ({...p, uuid: e.target.value}))}
                                style={{ width: '100%', padding: '8px', background: '#111', border: '1px solid #333', color: '#fff', borderRadius: '4px', fontFamily: 'monospace', fontSize: '11px', boxSizing: 'border-box' }}
                              />
                            </div>
                            <div>
                              <label style={{ color: '#888', fontSize: '10px' }}>Major</label>
                              <input type="number" value={beaconSpoofConfig.major} min={0} max={65535}
                                onChange={(e) => setBeaconSpoofConfig(p => ({...p, major: parseInt(e.target.value) || 0}))}
                                style={{ width: '100%', padding: '8px', background: '#111', border: '1px solid #333', color: '#fff', borderRadius: '4px', fontSize: '11px', boxSizing: 'border-box' }}
                              />
                            </div>
                            <div>
                              <label style={{ color: '#888', fontSize: '10px' }}>Minor</label>
                              <input type="number" value={beaconSpoofConfig.minor} min={0} max={65535}
                                onChange={(e) => setBeaconSpoofConfig(p => ({...p, minor: parseInt(e.target.value) || 0}))}
                                style={{ width: '100%', padding: '8px', background: '#111', border: '1px solid #333', color: '#fff', borderRadius: '4px', fontSize: '11px', boxSizing: 'border-box' }}
                              />
                            </div>
                          </div>
                        )}

                        {beaconSpoofMode === 'eddystone_url' && (
                          <div>
                            <label style={{ color: '#888', fontSize: '10px' }}>URL</label>
                            <input type="text" placeholder="https://example.com"
                              value={beaconSpoofConfig.url}
                              onChange={(e) => setBeaconSpoofConfig(p => ({...p, url: e.target.value}))}
                              style={{ width: '100%', padding: '8px', background: '#111', border: '1px solid #333', color: '#fff', borderRadius: '4px', fontFamily: 'monospace', fontSize: '11px', boxSizing: 'border-box' }}
                            />
                            <div style={{ color: '#666', fontSize: '9px', marginTop: '5px' }}>Short URLs only. Eddystone-URL has a 17-byte encoded limit.</div>
                          </div>
                        )}

                        {beaconSpoofMode === 'name_clone' && (
                          <div style={{ color: '#888', fontSize: '11px' }}>
                            Clones the advertised name of a target device and broadcasts it as a fake beacon.
                            {!selectedAttackTarget && <div style={{ color: '#f00', marginTop: '5px', fontSize: '10px' }}>Select a target device from the list above first.</div>}
                            {selectedAttackTarget && <div style={{ color: '#0ff', marginTop: '5px' }}>Target: {selectedAttackTarget}</div>}
                          </div>
                        )}

                        {beaconSpoofMode === 'flood' && (
                          <div>
                            <label style={{ color: '#888', fontSize: '10px' }}>Number of Unique Beacons</label>
                            <input type="number" value={beaconSpoofConfig.count} min={10} max={1000}
                              onChange={(e) => setBeaconSpoofConfig(p => ({...p, count: parseInt(e.target.value) || 100}))}
                              style={{ width: '100%', padding: '8px', background: '#111', border: '1px solid #333', color: '#fff', borderRadius: '4px', fontSize: '11px', boxSizing: 'border-box' }}
                            />
                            <div style={{ color: '#f00', fontSize: '9px', marginTop: '5px' }}>Broadcasts rapid random beacons to overwhelm nearby scanners. ~10-20 beacons/sec.</div>
                          </div>
                        )}

                        <button onClick={startBeaconSpoof}
                          disabled={beaconSpoofMode === 'name_clone' && !selectedAttackTarget}
                          className="cyber-button"
                          style={{ width: '100%', marginTop: '15px', padding: '12px', fontSize: '14px', fontWeight: 'bold', background: 'rgba(0,255,136,0.1)', borderColor: '#00ff88', color: '#00ff88' }}
                        >LAUNCH BEACON SPOOF</button>
                      </div>
                    )}

                    {/* Stop Button */}
                    {bleAttackRunning && (
                      <button
                        onClick={stopBleAttack}
                        className="cyber-button red"
                        style={{
                          width: '100%',
                          padding: '12px',
                          fontSize: '14px',
                          fontWeight: 'bold'
                        }}
                      >
                        ⛔ STOP ATTACK
                      </button>
                    )}
                  </div>

                  {/* Target Selection */}
                  <div style={{
                    background: '#0a0a0a',
                    border: '1px solid #333',
                    borderRadius: '8px',
                    padding: '15px',
                    marginBottom: '20px'
                  }}>
                    <h4 style={{ color: 'var(--color-secondary)', marginBottom: '10px', fontSize: '13px' }}>
                      🎯 TARGET SELECTION {selectedAttackTarget && `(Selected: ${selectedAttackTarget})`}
                    </h4>
                    <div style={{ maxHeight: '200px', overflowY: 'auto' }}>
                      {bleDevices && bleDevices.length > 0 ? (
                        bleDevices.map((dev, i) => (
                          <div
                            key={i}
                            onClick={() => setSelectedAttackTarget(dev.mac)}
                            style={{
                              padding: '10px',
                              marginBottom: '5px',
                              background: selectedAttackTarget === dev.mac ? 'rgba(0, 255, 255, 0.1)' : '#050505',
                              border: selectedAttackTarget === dev.mac ? '2px solid #0ff' : '1px solid #222',
                              borderRadius: '4px',
                              cursor: 'pointer',
                              transition: 'all 0.2s'
                            }}
                            onMouseEnter={(e) => e.currentTarget.style.borderColor = '#0ff'}
                            onMouseLeave={(e) => e.currentTarget.style.borderColor = selectedAttackTarget === dev.mac ? '#0ff' : '#222'}
                          >
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <div>
                                <div style={{ color: '#fff', fontSize: '12px', fontWeight: 'bold' }}>{dev.name || 'Unknown'}</div>
                                <div style={{ color: '#666', fontSize: '10px', fontFamily: 'monospace' }}>{dev.mac}</div>
                              </div>
                              <div style={{ color: '#888', fontSize: '11px' }}>
                                {dev.vendor} • RSSI: {dev.rssi}
                              </div>
                            </div>
                          </div>
                        ))
                      ) : (
                        <div style={{ textAlign: 'center', color: '#666', padding: '20px', fontSize: '11px' }}>
                          No BLE devices detected. Enable BLE scan first.
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Attack Results */}
                  {bleAttackResult && (
                    <div style={{
                      background: bleAttackResult.status === 'completed' ? 'rgba(0, 255, 0, 0.1)' :
                                 bleAttackResult.status === 'failed' ? 'rgba(255, 0, 0, 0.1)' :
                                 bleAttackResult.status === 'stopped' ? 'rgba(255, 165, 0, 0.1)' :
                                 'rgba(255, 255, 0, 0.1)',
                      border: `2px solid ${bleAttackResult.status === 'completed' ? '#0f0' :
                                          bleAttackResult.status === 'failed' ? '#f00' :
                                          bleAttackResult.status === 'stopped' ? '#ffa500' : '#ff0'}`,
                      borderRadius: '8px',
                      padding: '20px'
                    }}>
                      <h4 style={{
                        color: bleAttackResult.status === 'completed' ? '#0f0' :
                               bleAttackResult.status === 'failed' ? '#f00' :
                               bleAttackResult.status === 'stopped' ? '#ffa500' : '#ff0',
                        marginBottom: '15px',
                        fontSize: '14px'
                      }}>
                        {bleAttackResult.status === 'completed' && '✅ ATTACK COMPLETED'}
                        {bleAttackResult.status === 'failed' && '❌ ATTACK FAILED'}
                        {bleAttackResult.status === 'stopped' && '⏸️ ATTACK STOPPED'}
                        {bleAttackResult.status === 'running' && '⏳ ATTACK IN PROGRESS'}
                      </h4>

                      <div style={{ fontSize: '12px', color: '#ccc', marginBottom: '10px' }}>
                        {bleAttackResult.message}
                      </div>

                      {/* Display specific results based on attack type */}
                      {bleAttackResult.vulnerable_devices && bleAttackResult.vulnerable_devices.length > 0 && (
                        <div style={{ marginTop: '15px' }}>
                          <div style={{ color: '#f00', fontSize: '11px', fontWeight: 'bold', marginBottom: '10px' }}>
                            🚨 VULNERABLE DEVICES ({bleAttackResult.vulnerable_devices.length})
                          </div>
                          {bleAttackResult.vulnerable_devices.map((vd, i) => (
                            <div key={i} style={{
                              background: '#050505',
                              padding: '10px',
                              marginBottom: '5px',
                              borderLeft: '3px solid #f00',
                              fontSize: '10px'
                            }}>
                              <div style={{ color: '#fff', fontWeight: 'bold' }}>{vd.name || vd.mac}</div>
                              <div style={{ color: '#666', fontFamily: 'monospace' }}>{vd.mac}</div>
                              <div style={{ color: '#f00', marginTop: '5px' }}>
                                {vd.service && `Service: ${vd.service}`}
                                {vd.risk && ` • Risk: ${vd.risk}`}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}

                      {bleAttackResult.cracked_pin && (
                        <div style={{
                          background: 'rgba(0, 255, 0, 0.2)',
                          border: '2px solid #0f0',
                          padding: '15px',
                          marginTop: '15px',
                          borderRadius: '6px'
                        }}>
                          <div style={{ color: '#0f0', fontSize: '13px', fontWeight: 'bold', marginBottom: '5px' }}>
                            🔓 PIN CRACKED!
                          </div>
                          <div style={{ color: '#fff', fontSize: '20px', fontFamily: 'monospace', letterSpacing: '3px' }}>
                            {bleAttackResult.cracked_pin}
                          </div>
                          <div style={{ color: '#888', fontSize: '10px', marginTop: '5px' }}>
                            Attempts: {bleAttackResult.attempts}
                          </div>
                        </div>
                      )}

                      {bleAttackResult.vulnerable && bleAttackResult.vulnerable.length > 0 && (
                        <div style={{ marginTop: '15px' }}>
                          <div style={{ color: '#ff0', fontSize: '11px', fontWeight: 'bold', marginBottom: '10px' }}>
                            ⚠️ VULNERABLE CHARACTERISTICS ({bleAttackResult.vulnerable.length})
                          </div>
                          {bleAttackResult.vulnerable.slice(0, 5).map((vc, i) => (
                            <div key={i} style={{
                              background: '#050505',
                              padding: '8px',
                              marginBottom: '5px',
                              borderLeft: '2px solid #ff0',
                              fontSize: '9px',
                              fontFamily: 'monospace'
                            }}>
                              <div style={{ color: '#fff' }}>UUID: {vc.uuid}</div>
                              <div style={{ color: '#666' }}>Service: {vc.service}</div>
                              {vc.payload && <div style={{ color: '#888' }}>Payload: {vc.payload}</div>}
                              {vc.risk && <div style={{ color: vc.risk === 'HIGH' ? '#f00' : '#ff0' }}>Risk: {vc.risk}</div>}
                            </div>
                          ))}
                        </div>
                      )}

                      {bleAttackResult.data && bleAttackResult.data.length > 0 && (
                        <div style={{ marginTop: '15px' }}>
                          <div style={{ color: '#0ff', fontSize: '11px', fontWeight: 'bold', marginBottom: '10px' }}>
                            📦 CAPTURED DATA ({bleAttackResult.captured_characteristics} characteristics)
                          </div>
                          <div style={{
                            maxHeight: '200px',
                            overflowY: 'auto',
                            background: '#000',
                            padding: '10px',
                            borderRadius: '4px',
                            fontSize: '9px',
                            fontFamily: 'monospace'
                          }}>
                            {bleAttackResult.data.map((item, i) => (
                              <div key={i} style={{ color: '#0f0', marginBottom: '5px' }}>
                                {item.uuid}: {item.data || item.properties}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Battery Drain Attack Results */}
                      {bleAttackResult.attack_type === 'battery_drain' && bleAttackResult.connections && (
                        <div style={{ marginTop: '15px' }}>
                          <div style={{
                            background: 'rgba(255, 102, 0, 0.1)',
                            border: '1px solid #ff6600',
                            padding: '15px',
                            borderRadius: '6px'
                          }}>
                            <div style={{ color: '#ff6600', fontSize: '12px', fontWeight: 'bold', marginBottom: '10px' }}>
                              🔋 BATTERY DRAIN STATISTICS
                            </div>
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '11px' }}>
                              <div>
                                <div style={{ color: '#888', fontSize: '9px' }}>CONNECTIONS</div>
                                <div style={{ color: '#ff6600', fontWeight: 'bold', fontSize: '16px' }}>
                                  {bleAttackResult.connections}
                                </div>
                              </div>
                              <div>
                                <div style={{ color: '#888', fontSize: '9px' }}>SPAM OPERATIONS</div>
                                <div style={{ color: '#ff6600', fontWeight: 'bold', fontSize: '16px' }}>
                                  {bleAttackResult.spam_count}
                                </div>
                              </div>
                              <div>
                                <div style={{ color: '#888', fontSize: '9px' }}>DURATION</div>
                                <div style={{ color: '#fff', fontWeight: 'bold' }}>
                                  {bleAttackResult.duration}s
                                </div>
                              </div>
                              <div>
                                <div style={{ color: '#888', fontSize: '9px' }}>EST. DRAIN</div>
                                <div style={{ color: '#f00', fontWeight: 'bold' }}>
                                  {bleAttackResult.estimated_drain || 'N/A'}
                                </div>
                              </div>
                            </div>
                            <div style={{
                              marginTop: '10px',
                              padding: '8px',
                              background: 'rgba(0,0,0,0.3)',
                              borderRadius: '4px',
                              fontSize: '9px',
                              color: '#aaa'
                            }}>
                              ⚠️ This attack significantly impacts target device battery life. Use responsibly.
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Beacon Spoof Results */}
                      {bleAttackResult.mode && (
                        <div style={{ marginTop: '15px' }}>
                          <div style={{ background: 'rgba(0,255,136,0.1)', border: '1px solid #00ff88', padding: '15px', borderRadius: '6px' }}>
                            <div style={{ color: '#00ff88', fontSize: '12px', fontWeight: 'bold', marginBottom: '10px' }}>
                              BEACON SPOOF: {bleAttackResult.mode === 'ibeacon' ? 'iBeacon' : bleAttackResult.mode === 'eddystone_url' ? 'Eddystone-URL' : bleAttackResult.mode === 'name_clone' ? 'Name Clone' : bleAttackResult.mode === 'flood' ? 'BLE Flood' : bleAttackResult.mode.toUpperCase()}
                            </div>
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '11px' }}>
                              <div>
                                <div style={{ color: '#888', fontSize: '9px' }}>BEACONS</div>
                                <div style={{ color: '#00ff88', fontWeight: 'bold', fontSize: '16px' }}>{bleAttackResult.beacon_count || 0}</div>
                              </div>
                              <div>
                                <div style={{ color: '#888', fontSize: '9px' }}>DURATION</div>
                                <div style={{ color: '#fff', fontWeight: 'bold' }}>{bleAttackResult.duration || 0}s</div>
                              </div>
                            </div>
                            {bleAttackResult.mode === 'ibeacon' && bleAttackResult.uuid && (
                              <div style={{ marginTop: '10px', fontSize: '9px', fontFamily: 'monospace', color: '#888' }}>
                                UUID: {bleAttackResult.uuid}<br/>Major: {bleAttackResult.major} | Minor: {bleAttackResult.minor}
                              </div>
                            )}
                            {bleAttackResult.mode === 'eddystone_url' && bleAttackResult.url && (
                              <div style={{ marginTop: '10px', fontSize: '9px', fontFamily: 'monospace', color: '#888' }}>URL: {bleAttackResult.url}</div>
                            )}
                            {bleAttackResult.mode === 'name_clone' && bleAttackResult.cloned_name && (
                              <div style={{ marginTop: '10px', fontSize: '9px', fontFamily: 'monospace', color: '#888' }}>Cloned: {bleAttackResult.cloned_name}</div>
                            )}
                            {bleAttackResult.mode === 'flood' && bleAttackResult.beacons_per_second && (
                              <div style={{ marginTop: '10px', fontSize: '9px', color: '#f00' }}>Rate: {bleAttackResult.beacons_per_second} beacons/sec | Unique: {bleAttackResult.unique_beacons}</div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Attack Logs Panel */}
                  <div style={{
                    background: '#000',
                    border: '2px solid #333',
                    borderRadius: '8px',
                    padding: '15px',
                    marginTop: '20px'
                  }}>
                    <div style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      marginBottom: '10px'
                    }}>
                      <h4 style={{ color: '#0ff', fontSize: '13px', margin: 0 }}>
                        📋 ATTACK LOGS ({attackLogs.length})
                      </h4>
                      <button
                        onClick={() => setAttackLogs([])}
                        className="cyber-button"
                        style={{
                          fontSize: '9px',
                          padding: '4px 10px',
                          background: 'transparent',
                          color: '#666',
                          borderColor: '#444'
                        }}
                      >
                        CLEAR
                      </button>
                    </div>
                    <div style={{
                      background: '#050505',
                      border: '1px solid #222',
                      borderRadius: '4px',
                      padding: '10px',
                      maxHeight: '200px',
                      overflowY: 'auto',
                      fontFamily: 'monospace',
                      fontSize: '10px',
                      lineHeight: '1.6'
                    }}>
                      {attackLogs.length === 0 ? (
                        <div style={{ color: '#444', textAlign: 'center', padding: '20px' }}>
                          No attack logs yet. Start an attack to see logs here.
                        </div>
                      ) : (
                        attackLogs.map((log, i) => (
                          <div
                            key={i}
                            style={{
                              color: log.includes('❌') || log.includes('failed') ? '#f00' :
                                     log.includes('✅') || log.includes('complete') ? '#0f0' :
                                     log.includes('🚨') || log.includes('VULNERABLE') ? '#ff0' :
                                     log.includes('⏸️') || log.includes('stopped') ? '#ffa500' :
                                     log.includes('🔓') || log.includes('CRACKED') ? '#0ff' :
                                     '#888',
                              marginBottom: '3px',
                              paddingLeft: '5px',
                              borderLeft: log.includes('🚨') ? '2px solid #ff0' :
                                         log.includes('❌') ? '2px solid #f00' :
                                         log.includes('✅') ? '2px solid #0f0' : 'none'
                            }}
                          >
                            {log}
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ======= EVILTWIN TAB ======= */}
          {activeTab === 'EVILTWIN' && (
            <div style={{ padding: '20px' }}>
              {/* Warning Banner */}
              <div style={{
                background: 'rgba(255, 0, 0, 0.1)',
                border: '2px solid #ff0000',
                borderRadius: '8px',
                padding: '20px',
                marginBottom: '20px'
              }}>
                <h3 style={{ color: '#ff0000', marginBottom: '10px', fontSize: '16px' }}>EVIL TWIN ATTACK MODULE</h3>
                <p style={{ color: '#888', fontSize: '11px', marginBottom: '0' }}>
                  Rogue AP + Captive Portal + Credential Harvesting. Use only on networks you are authorized to test. Linux/Kali only.
                </p>
              </div>

              {/* Status Panel */}
              {eviltwinRunning && (
                <div style={{
                  background: 'rgba(255, 0, 85, 0.1)',
                  border: '1px solid var(--color-danger)',
                  borderRadius: '8px',
                  padding: '15px',
                  marginBottom: '20px'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <div style={{ color: 'var(--color-danger)', fontWeight: 'bold', fontSize: '14px', marginBottom: '5px' }}>
                        <span className="blink" style={{ marginRight: '8px' }}>●</span>
                        EVIL TWIN ACTIVE
                      </div>
                      <div style={{ fontSize: '11px', color: '#aaa' }}>
                        SSID: <span style={{ color: '#fff' }}>{eviltwinStatus.target_ssid}</span> &bull;
                        Channel: <span style={{ color: '#fff' }}>{eviltwinStatus.target_channel}</span> &bull;
                        Mode: <span style={{ color: eviltwinStatus.mode === 'internet_relay' ? '#00ffff' : '#ff0' }}>
                          {eviltwinStatus.mode === 'internet_relay' ? 'INTERNET RELAY' : 'CAPTIVE PORTAL'}
                        </span> &bull;
                        Clients: <span style={{ color: '#0f0' }}>{eviltwinStatus.client_count || 0}</span>
                        {eviltwinStatus.mode === 'captive_portal' && (
                          <> &bull; Creds: <span style={{ color: '#ff0' }}>{eviltwinStatus.credential_count || 0}</span></>
                        )}
                        {eviltwinStatus.mode === 'internet_relay' && eviltwinStatus.internet_iface && (
                          <> &bull; Uplink: <span style={{ color: '#0f0' }}>{eviltwinStatus.internet_iface}</span></>
                        )}
                      </div>
                    </div>
                    <button
                      onClick={async () => {
                        await api('/eviltwin/stop');
                        setEviltwinRunning(false);
                      }}
                      className="cyber-button red"
                      style={{ fontSize: '12px', padding: '8px 20px', fontWeight: 'bold' }}
                    >
                      STOP ATTACK
                    </button>
                  </div>
                </div>
              )}

              {/* Configuration Panel - show when NOT running */}
              {!eviltwinRunning && (
                <div className="glass-panel" style={{ padding: '20px', marginBottom: '20px' }}>
                  <h4 style={{ color: 'var(--color-secondary)', fontSize: '13px', marginBottom: '15px', borderBottom: '1px solid #222', paddingBottom: '10px' }}>
                    TARGET CONFIGURATION
                  </h4>

                  {/* Mode Selection */}
                  <div style={{ marginBottom: '15px' }}>
                    <div style={{ fontSize: '11px', color: '#888', marginBottom: '8px' }}>ATTACK MODE</div>
                    <div style={{ display: 'flex', gap: '10px' }}>
                      <button
                        onClick={() => setEviltwinMode('captive_portal')}
                        className="cyber-button"
                        style={{
                          flex: 1, padding: '12px 10px', fontSize: '11px',
                          background: eviltwinMode === 'captive_portal' ? '#111' : 'transparent',
                          borderColor: eviltwinMode === 'captive_portal' ? 'var(--color-danger)' : '#333',
                          color: eviltwinMode === 'captive_portal' ? 'var(--color-danger)' : '#666',
                          textAlign: 'left'
                        }}
                      >
                        <div style={{ fontWeight: 'bold', marginBottom: '4px' }}>CAPTIVE PORTAL</div>
                        <div style={{ fontSize: '9px', opacity: 0.7 }}>Fake login page for credential capture</div>
                      </button>
                      <button
                        onClick={() => setEviltwinMode('internet_relay')}
                        className="cyber-button"
                        style={{
                          flex: 1, padding: '12px 10px', fontSize: '11px',
                          background: eviltwinMode === 'internet_relay' ? '#111' : 'transparent',
                          borderColor: eviltwinMode === 'internet_relay' ? '#00ffff' : '#333',
                          color: eviltwinMode === 'internet_relay' ? '#00ffff' : '#666',
                          textAlign: 'left'
                        }}
                      >
                        <div style={{ fontWeight: 'bold', marginBottom: '4px' }}>INTERNET RELAY</div>
                        <div style={{ fontSize: '9px', opacity: 0.7 }}>Real internet access + MITM sniffing</div>
                      </button>
                    </div>
                  </div>

                  {/* Portal Type Selection — only for captive_portal mode */}
                  {eviltwinMode === 'captive_portal' && (
                  <div style={{ marginBottom: '15px' }}>
                    <div style={{ fontSize: '11px', color: '#888', marginBottom: '8px' }}>PORTAL TYPE</div>
                    <div style={{ display: 'flex', gap: '10px' }}>
                      {['generic', 'router'].map(type => (
                        <button
                          key={type}
                          onClick={() => setEviltwinPortalType(type)}
                          className="cyber-button"
                          style={{
                            flex: 1,
                            padding: '10px',
                            fontSize: '11px',
                            background: eviltwinPortalType === type ? '#111' : 'transparent',
                            borderColor: eviltwinPortalType === type ? 'var(--color-danger)' : '#333',
                            color: eviltwinPortalType === type ? 'var(--color-danger)' : '#666'
                          }}
                        >
                          {type === 'generic' ? 'WiFi Login Portal' : 'Router Update Portal'}
                        </button>
                      ))}
                    </div>
                  </div>
                  )}

                  {/* Custom SSID — only for internet_relay mode */}
                  {eviltwinMode === 'internet_relay' && (
                  <div style={{ marginBottom: '15px' }}>
                    <div style={{ fontSize: '11px', color: '#888', marginBottom: '8px' }}>AP NAME (SSID)</div>
                    <input
                      type="text"
                      placeholder="Custom AP name (leave empty to clone target)"
                      value={eviltwinCustomSSID}
                      onChange={e => setEviltwinCustomSSID(e.target.value)}
                      style={{
                        width: '100%', padding: '10px 12px', fontSize: '12px',
                        background: '#0a0a0a', border: '1px solid #333', borderRadius: '4px',
                        color: '#fff', fontFamily: 'monospace', boxSizing: 'border-box'
                      }}
                    />
                    <div style={{ fontSize: '9px', color: '#555', marginTop: '4px' }}>
                      Set a custom name for the rogue AP, or leave empty to clone the target network's SSID
                    </div>
                  </div>
                  )}

                  {/* Target Network Selection */}
                  <div style={{ fontSize: '11px', color: '#888', marginBottom: '8px' }}>
                    {eviltwinMode === 'internet_relay' && eviltwinCustomSSID.trim()
                      ? 'SELECT TARGET NETWORK (optional — for deauth only)'
                      : 'SELECT TARGET NETWORK'}
                  </div>
                  <div style={{
                    maxHeight: '250px',
                    overflowY: 'auto',
                    border: '1px solid #222',
                    borderRadius: '6px',
                    background: '#050505'
                  }}>
                    {networks.length === 0 ? (
                      <div style={{ padding: '30px', textAlign: 'center', color: '#444', fontSize: '11px' }}>
                        No networks detected. Start WiFi scanning first.
                      </div>
                    ) : (
                      networks.map((net, i) => (
                        <div
                          key={i}
                          onClick={() => setSelectedEviltwinTarget(net)}
                          style={{
                            display: 'grid',
                            gridTemplateColumns: '1fr 120px 50px 50px',
                            padding: '10px 15px',
                            borderBottom: '1px solid #111',
                            cursor: 'pointer',
                            background: selectedEviltwinTarget?.bssid === net.bssid ? 'rgba(255, 0, 85, 0.1)' : 'transparent',
                            borderLeft: selectedEviltwinTarget?.bssid === net.bssid ? '3px solid var(--color-danger)' : '3px solid transparent',
                            transition: 'all 0.15s'
                          }}
                          onMouseEnter={(e) => { if (selectedEviltwinTarget?.bssid !== net.bssid) e.currentTarget.style.background = 'rgba(255,255,255,0.02)'; }}
                          onMouseLeave={(e) => { if (selectedEviltwinTarget?.bssid !== net.bssid) e.currentTarget.style.background = 'transparent'; }}
                        >
                          <div>
                            <div style={{ color: '#e0e0e0', fontSize: '13px' }}>{net.ssid || '<HIDDEN>'}</div>
                            <div style={{ color: '#555', fontSize: '9px', fontFamily: 'monospace' }}>{net.bssid}</div>
                          </div>
                          <div style={{ color: '#666', fontSize: '10px', display: 'flex', alignItems: 'center' }}>
                            {net.band || '2.4GHz'}
                          </div>
                          <div style={{ color: '#888', fontSize: '11px', display: 'flex', alignItems: 'center' }}>
                            CH {net.channel}
                          </div>
                          <div style={{
                            color: net.signal > -50 ? '#0f0' : net.signal > -70 ? '#ff0' : '#f00',
                            fontSize: '11px',
                            fontWeight: 'bold',
                            display: 'flex',
                            alignItems: 'center'
                          }}>
                            {net.signal}
                          </div>
                        </div>
                      ))
                    )}
                  </div>

                  {/* Launch Button */}
                  <button
                    onClick={async () => {
                      const hasCustomSSID = eviltwinMode === 'internet_relay' && eviltwinCustomSSID.trim();
                      const hasTarget = selectedEviltwinTarget && selectedEviltwinTarget.ssid && selectedEviltwinTarget.ssid !== '<HIDDEN>';

                      if (!hasCustomSSID && !hasTarget) {
                        alert(eviltwinMode === 'internet_relay'
                          ? 'Enter a custom AP name or select a target network.'
                          : 'Cannot clone a hidden network.');
                        return;
                      }

                      const ssid = hasCustomSSID ? eviltwinCustomSSID.trim() : selectedEviltwinTarget.ssid;
                      const bssid = selectedEviltwinTarget?.bssid || 'FF:FF:FF:FF:FF:FF';
                      const channel = selectedEviltwinTarget?.channel || 6;

                      const result = await api('/eviltwin/start', {
                        ssid,
                        bssid,
                        channel,
                        portal_type: eviltwinPortalType,
                        mode: eviltwinMode
                      });
                      if (result?.status === 'success') {
                        setEviltwinRunning(true);
                      } else {
                        alert(result?.message || 'Failed to start Evil Twin');
                      }
                    }}
                    disabled={!(selectedEviltwinTarget || (eviltwinMode === 'internet_relay' && eviltwinCustomSSID.trim()))}
                    className="cyber-button red"
                    style={{
                      width: '100%',
                      marginTop: '15px',
                      padding: '14px',
                      fontSize: '14px',
                      fontWeight: 'bold',
                      opacity: (selectedEviltwinTarget || (eviltwinMode === 'internet_relay' && eviltwinCustomSSID.trim())) ? 1 : 0.4,
                      cursor: (selectedEviltwinTarget || (eviltwinMode === 'internet_relay' && eviltwinCustomSSID.trim())) ? 'pointer' : 'not-allowed'
                    }}
                  >
                    {eviltwinMode === 'internet_relay' && eviltwinCustomSSID.trim()
                      ? `LAUNCH EVIL TWIN — ${eviltwinCustomSSID.trim()}`
                      : selectedEviltwinTarget
                        ? `LAUNCH EVIL TWIN — ${selectedEviltwinTarget.ssid}`
                        : 'SELECT A TARGET NETWORK'}
                  </button>
                </div>
              )}

              {/* Credentials Panel */}
              <div className="glass-panel" style={{ padding: '20px' }}>
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: '15px',
                  borderBottom: '1px solid #222',
                  paddingBottom: '10px'
                }}>
                  <h4 style={{ color: '#ff0', fontSize: '13px', margin: 0 }}>
                    CAPTURED CREDENTIALS ({eviltwinCreds.length})
                  </h4>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button
                      onClick={async () => {
                        const res = await fetch('http://localhost:8000/eviltwin/creds');
                        const data = await res.json();
                        if (data.credentials) setEviltwinCreds(data.credentials);
                      }}
                      className="cyber-button"
                      style={{ fontSize: '9px', padding: '4px 10px', background: 'transparent', color: '#888', borderColor: '#444' }}
                    >
                      REFRESH
                    </button>
                    <button
                      onClick={async () => {
                        await api('/eviltwin/creds/clear');
                        setEviltwinCreds([]);
                      }}
                      className="cyber-button"
                      style={{ fontSize: '9px', padding: '4px 10px', background: 'transparent', color: '#666', borderColor: '#444' }}
                    >
                      CLEAR
                    </button>
                  </div>
                </div>

                {eviltwinCreds.length === 0 ? (
                  <div style={{ padding: '30px', textAlign: 'center', color: '#444', fontSize: '11px' }}>
                    No credentials captured yet. Start an Evil Twin attack and wait for clients to connect.
                  </div>
                ) : (
                  <div style={{
                    maxHeight: '300px',
                    overflowY: 'auto',
                    border: '1px solid #222',
                    borderRadius: '6px',
                    background: '#050505'
                  }}>
                    {/* Header */}
                    <div style={{
                      display: 'grid',
                      gridTemplateColumns: '70px 1fr 1fr 100px',
                      padding: '8px 12px',
                      borderBottom: '1px solid #333',
                      background: '#0a0a0a',
                      fontSize: '10px',
                      color: 'var(--color-secondary)',
                      fontWeight: 'bold'
                    }}>
                      <div>TIME</div>
                      <div>SSID</div>
                      <div>PASSWORD</div>
                      <div>CLIENT IP</div>
                    </div>
                    {eviltwinCreds.map((cred, i) => (
                      <div key={i} style={{
                        display: 'grid',
                        gridTemplateColumns: '70px 1fr 1fr 100px',
                        padding: '10px 12px',
                        borderBottom: '1px solid #111',
                        fontSize: '12px',
                        background: 'rgba(255, 255, 0, 0.02)'
                      }}>
                        <div style={{ color: '#666', fontSize: '10px' }}>{cred.time}</div>
                        <div style={{ color: '#aaa' }}>{cred.ssid}</div>
                        <div style={{ color: '#0f0', fontFamily: 'monospace', fontWeight: 'bold' }}>{cred.password}</div>
                        <div style={{ color: '#555', fontSize: '10px', fontFamily: 'monospace' }}>{cred.client_ip}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ======= MITM TAB ======= */}
          {activeTab === 'MITM' && (
            <div style={{ padding: '20px' }}>
              {/* Banner */}
              <div style={{
                background: 'rgba(0, 255, 255, 0.06)',
                border: '2px solid #00ffff',
                borderRadius: '8px',
                padding: '15px 20px',
                marginBottom: '20px'
              }}>
                <h3 style={{ color: '#00ffff', marginBottom: '5px', fontSize: '14px' }}>MITM MODULE</h3>
                <p style={{ color: '#888', fontSize: '10px', marginBottom: '0' }}>
                  Man-in-the-Middle — Packet Sniffer + DNS Spoofing. Requires Evil Twin running in Internet Relay mode.
                </p>
              </div>

              {/* ET not running warning */}
              {!eviltwinRunning && (
                <div style={{
                  background: 'rgba(255, 165, 0, 0.1)',
                  border: '1px solid #ff8c00',
                  borderRadius: '6px',
                  padding: '12px 15px',
                  marginBottom: '15px',
                  fontSize: '11px',
                  color: '#ff8c00'
                }}>
                  Evil Twin must be running (Internet Relay mode) before starting MITM attacks.
                </div>
              )}

              {/* Sub-tabs */}
              <div style={{ display: 'flex', gap: '8px', marginBottom: '20px' }}>
                {['SNIFFER', 'DNS SPOOF'].map(sub => (
                  <button
                    key={sub}
                    onClick={() => setMitmSubTab(sub)}
                    className="cyber-button"
                    style={{
                      background: mitmSubTab === sub ? '#00ffff' : 'transparent',
                      color: mitmSubTab === sub ? '#000' : '#00ffff',
                      border: `1px solid ${mitmSubTab === sub ? '#00ffff' : '#333'}`,
                      padding: '8px 20px',
                      fontSize: '11px',
                      fontWeight: 'bold',
                      letterSpacing: '1px'
                    }}
                  >
                    {sub}
                  </button>
                ))}
              </div>

              {/* ===== SNIFFER SUB-TAB ===== */}
              {mitmSubTab === 'SNIFFER' && (
                <div>
                  {/* Controls */}
                  <div style={{ display: 'flex', gap: '10px', marginBottom: '15px', alignItems: 'center' }}>
                    <button
                      onClick={async () => {
                        if (mitmSnifferRunning) {
                          await api('/mitm/sniffer/stop');
                        } else {
                          await api('/mitm/sniffer/start', { filter_mode: 'all' });
                        }
                      }}
                      disabled={!eviltwinRunning}
                      className={`cyber-button ${mitmSnifferRunning ? 'red' : ''}`}
                      style={{
                        padding: '10px 25px',
                        fontSize: '12px',
                        fontWeight: 'bold',
                        borderColor: mitmSnifferRunning ? 'var(--color-danger)' : '#00ffff',
                        color: mitmSnifferRunning ? 'var(--color-danger)' : '#00ffff',
                        opacity: eviltwinRunning ? 1 : 0.4
                      }}
                    >
                      {mitmSnifferRunning ? 'STOP SNIFFER' : 'START SNIFFER'}
                    </button>

                    <button
                      onClick={async () => {
                        try {
                          const response = await fetch('http://localhost:8000/mitm/sniffer/export', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: '{}'
                          });
                          const contentType = response.headers.get('content-type') || '';
                          if (contentType.includes('application/json')) {
                            const data = await response.json();
                            if (data.status === 'error') alert(data.message);
                          } else {
                            const blob = await response.blob();
                            const url = URL.createObjectURL(blob);
                            const a = document.createElement('a');
                            a.href = url;
                            const disp = response.headers.get('content-disposition') || '';
                            const match = disp.match(/filename="?([^"]+)"?/);
                            a.download = match ? match[1] : 'mitm_capture.pcap';
                            document.body.appendChild(a);
                            a.click();
                            a.remove();
                            URL.revokeObjectURL(url);
                          }
                        } catch (e) {
                          alert('Export failed: ' + e.message);
                        }
                      }}
                      disabled={!mitmSnifferRunning && mitmPackets.length === 0}
                      className="cyber-button"
                      style={{ padding: '10px 15px', fontSize: '10px', color: '#888', borderColor: '#444' }}
                    >
                      EXPORT PCAP
                    </button>
                  </div>

                  {/* Stats */}
                  <div style={{
                    display: 'flex',
                    gap: '20px',
                    marginBottom: '15px',
                    fontSize: '11px',
                    color: '#888'
                  }}>
                    <span>Total: <span style={{ color: '#fff', fontWeight: 'bold' }}>{mitmSnifferStats.total_packets || 0}</span></span>
                    <span>HTTP: <span style={{ color: '#00ffff', fontWeight: 'bold' }}>{mitmSnifferStats.http_requests || 0}</span></span>
                    <span>DNS: <span style={{ color: '#0f0', fontWeight: 'bold' }}>{mitmSnifferStats.dns_queries || 0}</span></span>
                    <span>Creds: <span style={{ color: '#ff0', fontWeight: 'bold' }}>{mitmSnifferStats.credentials || 0}</span></span>
                    {mitmSnifferStats.elapsed_seconds > 0 && (
                      <span>Elapsed: <span style={{ color: '#aaa' }}>
                        {Math.floor(mitmSnifferStats.elapsed_seconds / 60)}m {mitmSnifferStats.elapsed_seconds % 60}s
                      </span></span>
                    )}
                  </div>

                  {/* Filter buttons */}
                  <div style={{ display: 'flex', gap: '6px', marginBottom: '15px' }}>
                    {['all', 'http', 'dns', 'credential'].map(f => (
                      <button
                        key={f}
                        onClick={() => setMitmPacketFilter(f)}
                        className="cyber-button"
                        style={{
                          padding: '5px 12px',
                          fontSize: '10px',
                          background: mitmPacketFilter === f ? 'rgba(0,255,255,0.15)' : 'transparent',
                          borderColor: mitmPacketFilter === f ? '#00ffff' : '#333',
                          color: mitmPacketFilter === f ? '#00ffff' : '#666',
                          textTransform: 'uppercase'
                        }}
                      >
                        {f}
                      </button>
                    ))}
                  </div>

                  {/* Packet table */}
                  <div className="glass-panel" style={{ padding: 0 }}>
                    {/* Header */}
                    <div style={{
                      display: 'grid',
                      gridTemplateColumns: '80px 70px 120px 1fr',
                      padding: '8px 12px',
                      borderBottom: '1px solid #333',
                      background: '#0a0a0a',
                      fontSize: '10px',
                      color: '#00ffff',
                      fontWeight: 'bold'
                    }}>
                      <div>TIME</div>
                      <div>TYPE</div>
                      <div>SOURCE</div>
                      <div>INFO</div>
                    </div>

                    {/* Rows */}
                    <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
                      {mitmPackets.length === 0 ? (
                        <div style={{ padding: '30px', textAlign: 'center', color: '#444', fontSize: '11px' }}>
                          {mitmSnifferRunning ? 'Waiting for packets...' : 'Start the sniffer to capture traffic.'}
                        </div>
                      ) : (
                        mitmPackets.map((pkt, i) => (
                          <div key={i}>
                            <div
                              onClick={() => pkt.detail ? setMitmExpandedPacket(mitmExpandedPacket === i ? null : i) : null}
                              style={{
                                display: 'grid',
                                gridTemplateColumns: '80px 70px 120px 1fr',
                                padding: '6px 12px',
                                borderBottom: '1px solid #111',
                                fontSize: '11px',
                                background: pkt.type === 'credential' ? 'rgba(255,255,0,0.05)' : 'transparent',
                                cursor: pkt.detail ? 'pointer' : 'default'
                              }}
                            >
                              <div style={{ color: '#555', fontSize: '10px', fontFamily: 'monospace' }}>{pkt.time}</div>
                              <div style={{
                                color: pkt.type === 'dns' ? '#0f0' : pkt.type === 'http' ? '#00ffff' : '#ff0',
                                fontWeight: 'bold',
                                fontSize: '10px',
                                textTransform: 'uppercase'
                              }}>{pkt.type}</div>
                              <div style={{ color: '#888', fontFamily: 'monospace', fontSize: '10px' }}>{pkt.src}</div>
                              <div style={{ color: '#ccc', fontSize: '10px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {pkt.info}
                                {pkt.detail && <span style={{ color: '#555', marginLeft: '8px' }}>{mitmExpandedPacket === i ? '▼' : '▶'}</span>}
                              </div>
                            </div>
                            {mitmExpandedPacket === i && pkt.detail && (
                              <div style={{
                                padding: '8px 12px 8px 82px',
                                background: pkt.type === 'credential' ? 'rgba(255,255,0,0.08)' : 'rgba(0,255,255,0.03)',
                                borderBottom: '1px solid #222',
                                fontSize: '10px',
                                fontFamily: 'monospace'
                              }}>
                                {pkt.detail.method && <div><span style={{ color: '#666' }}>Method:</span> <span style={{ color: '#fff' }}>{pkt.detail.method}</span></div>}
                                {pkt.detail.host && <div><span style={{ color: '#666' }}>Host:</span> <span style={{ color: '#00ffff' }}>{pkt.detail.host}</span></div>}
                                {pkt.detail.path && <div><span style={{ color: '#666' }}>Path:</span> <span style={{ color: '#fff' }}>{pkt.detail.path}</span></div>}
                                {pkt.detail.query && <div><span style={{ color: '#666' }}>Query:</span> <span style={{ color: '#0f0' }}>{pkt.detail.query}</span></div>}
                                {pkt.detail.qtype && <div><span style={{ color: '#666' }}>Type:</span> <span style={{ color: '#888' }}>{pkt.detail.qtype}</span></div>}
                                {pkt.detail.body_snippet && (
                                  <div style={{ marginTop: '4px', padding: '6px 8px', background: '#0a0a0a', borderRadius: '3px', border: '1px solid #333' }}>
                                    <div style={{ color: '#ff0', marginBottom: '4px', fontWeight: 'bold' }}>CAPTURED DATA:</div>
                                    <div style={{ color: '#fff', wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>{pkt.detail.body_snippet}</div>
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* ===== DNS SPOOF SUB-TAB ===== */}
              {mitmSubTab === 'DNS SPOOF' && (
                <div>
                  {/* Add entry form */}
                  <div className="glass-panel" style={{ padding: '15px', marginBottom: '15px' }}>
                    <div style={{ fontSize: '11px', color: '#888', marginBottom: '10px' }}>ADD SPOOF ENTRY</div>
                    <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                      <input
                        type="text"
                        placeholder="Domain (e.g. example.com)"
                        value={mitmNewDomain}
                        onChange={e => setMitmNewDomain(e.target.value)}
                        style={{
                          flex: 2, padding: '8px 12px', fontSize: '12px',
                          background: '#0a0a0a', border: '1px solid #333', borderRadius: '4px',
                          color: '#fff', fontFamily: 'monospace'
                        }}
                      />
                      <span style={{ color: '#444' }}>&rarr;</span>
                      <input
                        type="text"
                        placeholder="IP (e.g. 192.168.4.1)"
                        value={mitmNewIP}
                        onChange={e => setMitmNewIP(e.target.value)}
                        style={{
                          flex: 1, padding: '8px 12px', fontSize: '12px',
                          background: '#0a0a0a', border: '1px solid #333', borderRadius: '4px',
                          color: '#fff', fontFamily: 'monospace'
                        }}
                      />
                      <button
                        onClick={async () => {
                          if (!mitmNewDomain.trim()) return;
                          await api('/mitm/dns-spoof/add', { domain: mitmNewDomain.trim(), ip: mitmNewIP.trim() });
                          setMitmNewDomain('');
                          // Refresh entries
                          const res = await fetch('http://localhost:8000/mitm/dns-spoof/list');
                          const d = await res.json();
                          if (d.entries) setMitmDnsSpoofEntries(d.entries);
                        }}
                        className="cyber-button"
                        style={{ padding: '8px 20px', fontSize: '11px', color: '#00ffff', borderColor: '#00ffff' }}
                      >
                        ADD
                      </button>
                    </div>
                  </div>

                  {/* Active entries */}
                  <div className="glass-panel" style={{ padding: '15px', marginBottom: '15px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                      <div style={{ fontSize: '11px', color: '#888' }}>SPOOF ENTRIES ({mitmDnsSpoofEntries.length})</div>
                      <button
                        onClick={async () => {
                          if (mitmDnsSpoofActive) {
                            await api('/mitm/dns-spoof/stop');
                          } else {
                            await api('/mitm/dns-spoof/start');
                          }
                        }}
                        disabled={!eviltwinRunning || mitmDnsSpoofEntries.length === 0}
                        className={`cyber-button ${mitmDnsSpoofActive ? 'red' : ''}`}
                        style={{
                          padding: '6px 15px',
                          fontSize: '10px',
                          fontWeight: 'bold',
                          borderColor: mitmDnsSpoofActive ? 'var(--color-danger)' : '#00ffff',
                          color: mitmDnsSpoofActive ? 'var(--color-danger)' : '#00ffff',
                          opacity: eviltwinRunning && mitmDnsSpoofEntries.length > 0 ? 1 : 0.4
                        }}
                      >
                        {mitmDnsSpoofActive ? 'STOP SPOOFING' : 'START SPOOFING'}
                      </button>
                    </div>

                    {mitmDnsSpoofEntries.length === 0 ? (
                      <div style={{ padding: '20px', textAlign: 'center', color: '#444', fontSize: '11px' }}>
                        No spoof entries. Add a domain above.
                      </div>
                    ) : (
                      <div style={{ border: '1px solid #222', borderRadius: '6px', background: '#050505' }}>
                        {mitmDnsSpoofEntries.map((entry, i) => (
                          <div key={i} style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            padding: '10px 12px',
                            borderBottom: '1px solid #111',
                            fontSize: '12px'
                          }}>
                            <div>
                              <span style={{ color: '#00ffff', fontFamily: 'monospace' }}>{entry.domain}</span>
                              <span style={{ color: '#444', margin: '0 8px' }}>&rarr;</span>
                              <span style={{ color: '#0f0', fontFamily: 'monospace' }}>{entry.ip}</span>
                            </div>
                            <button
                              onClick={async () => {
                                await api('/mitm/dns-spoof/remove', { domain: entry.domain });
                                const res = await fetch('http://localhost:8000/mitm/dns-spoof/list');
                                const d = await res.json();
                                if (d.entries) setMitmDnsSpoofEntries(d.entries);
                              }}
                              className="cyber-button"
                              style={{ padding: '3px 10px', fontSize: '9px', color: '#f55', borderColor: '#f55' }}
                            >
                              REMOVE
                            </button>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ======= PMKID TAB ======= */}
          {activeTab === 'PMKID' && (
            <div>
              {/* Banner */}
              <div style={{
                background: 'rgba(0, 212, 255, 0.06)',
                border: '2px solid #00d4ff',
                borderRadius: '8px',
                padding: '15px 20px',
                margin: '15px 20px 0'
              }}>
                <h3 style={{ color: '#00d4ff', marginBottom: '5px', fontSize: '14px' }}>PMKID CAPTURE MODULE</h3>
                <p style={{ color: '#888', fontSize: '10px', marginBottom: '0' }}>
                  PMKID hash capture via hcxdumptool. Captures WPA/WPA2 PMKID without full handshake. Linux/Kali only.
                </p>
              </div>

              {/* Sub-tab buttons */}
              <div style={{ display: 'flex', gap: '8px', padding: '15px 20px 10px' }}>
                {['NETWORKS', 'CAPTURED'].map(subTab => (
                  <button
                    key={subTab}
                    onClick={() => setPmkidSubTab(subTab)}
                    className="cyber-button"
                    style={{
                      background: pmkidSubTab === subTab ? '#00d4ff' : 'transparent',
                      color: pmkidSubTab === subTab ? '#000' : '#00d4ff',
                      border: `1px solid ${pmkidSubTab === subTab ? '#00d4ff' : '#333'}`,
                      padding: '8px 16px',
                      fontSize: '11px',
                      fontWeight: 'bold',
                      letterSpacing: '1px'
                    }}
                  >
                    {subTab} {subTab === 'CAPTURED' && `(${pmkidResults.length})`}
                  </button>
                ))}
              </div>

              {/* ===== NETWORKS SUB-TAB ===== */}
              {pmkidSubTab === 'NETWORKS' && (
                <div style={{ padding: '10px 20px 20px' }}>
                  {/* Status Panel - when running */}
                  {pmkidRunning && (
                    <div style={{
                      background: 'rgba(0, 212, 255, 0.08)',
                      border: '1px solid #00d4ff',
                      borderRadius: '8px',
                      padding: '15px',
                      marginBottom: '20px'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                        <div>
                          <div style={{ color: '#00d4ff', fontWeight: 'bold', fontSize: '14px', marginBottom: '5px' }}>
                            <span className="blink" style={{ marginRight: '8px' }}>●</span>
                            PMKID CAPTURE ACTIVE
                          </div>
                          <div style={{ fontSize: '11px', color: '#aaa' }}>
                            SSID: <span style={{ color: '#fff' }}>{pmkidStatus.target_ssid}</span> &bull;
                            BSSID: <span style={{ color: '#888', fontFamily: 'monospace' }}>{pmkidStatus.target_bssid}</span> &bull;
                            Channel: <span style={{ color: '#fff' }}>{pmkidStatus.target_channel}</span> &bull;
                            Elapsed: <span style={{ color: '#ff0' }}>{pmkidStatus.elapsed_seconds || 0}s</span> &bull;
                            PMKIDs: <span style={{ color: '#0f0' }}>{pmkidStatus.pmkid_count || 0}</span>
                          </div>
                        </div>
                        <button
                          onClick={async () => {
                            await api('/pmkid/stop');
                            setPmkidRunning(false);
                            const res = await fetch('http://localhost:8000/pmkid/results');
                            const data = await res.json();
                            if (data.results) {
                              setPmkidResults(data.results);
                              if (data.results.length > 0) setPmkidSubTab('CAPTURED');
                            }
                          }}
                          className="cyber-button"
                          style={{ fontSize: '12px', padding: '8px 20px', fontWeight: 'bold', borderColor: '#00d4ff', color: '#00d4ff' }}
                        >
                          STOP CAPTURE
                        </button>
                      </div>
                      {pmkidStatus.output_lines && pmkidStatus.output_lines.length > 0 && (
                        <div style={{
                          background: '#050505',
                          border: '1px solid #222',
                          borderRadius: '4px',
                          padding: '8px 10px',
                          fontFamily: 'monospace',
                          fontSize: '10px',
                          maxHeight: '100px',
                          overflowY: 'auto',
                          lineHeight: '1.5'
                        }}>
                          {pmkidStatus.output_lines.map((line, i) => (
                            <div key={i} style={{ color: line.includes('PMKID') || line.includes('pmkid') ? '#0f0' : '#666' }}>
                              {line}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Configuration Panel - when NOT running */}
                  {!pmkidRunning && (
                    <div className="glass-panel" style={{ padding: '20px' }}>
                      <h4 style={{ color: '#00d4ff', fontSize: '13px', marginBottom: '15px', borderBottom: '1px solid #222', paddingBottom: '10px' }}>
                        TARGET CONFIGURATION
                      </h4>
                      <div style={{ marginBottom: '15px' }}>
                        <div style={{ fontSize: '11px', color: '#888', marginBottom: '8px' }}>
                          CAPTURE TIMEOUT: <span style={{ color: '#00d4ff', fontWeight: 'bold' }}>{pmkidTimeout}s</span>
                        </div>
                        <input type="range" min="30" max="120" step="10" value={pmkidTimeout}
                          onChange={(e) => setPmkidTimeout(parseInt(e.target.value))}
                          style={{ width: '100%', accentColor: '#00d4ff', background: 'transparent' }}
                        />
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '9px', color: '#555' }}>
                          <span>30s</span><span>120s</span>
                        </div>
                      </div>
                      <div style={{ fontSize: '11px', color: '#888', marginBottom: '8px' }}>SELECT TARGET NETWORK</div>
                      <div style={{ maxHeight: '250px', overflowY: 'auto', border: '1px solid #222', borderRadius: '6px', background: '#050505' }}>
                        {networks.length === 0 ? (
                          <div style={{ padding: '30px', textAlign: 'center', color: '#444', fontSize: '11px' }}>
                            No networks detected. Start WiFi scanning first.
                          </div>
                        ) : (
                          networks.map((net, i) => (
                            <div key={i} onClick={() => setSelectedPmkidTarget(net)} style={{
                              display: 'grid', gridTemplateColumns: '1fr 120px 50px 50px',
                              padding: '10px 15px', borderBottom: '1px solid #111', cursor: 'pointer',
                              background: selectedPmkidTarget?.bssid === net.bssid ? 'rgba(0, 212, 255, 0.1)' : 'transparent',
                              borderLeft: selectedPmkidTarget?.bssid === net.bssid ? '3px solid #00d4ff' : '3px solid transparent',
                              transition: 'all 0.15s'
                            }}
                              onMouseEnter={(e) => { if (selectedPmkidTarget?.bssid !== net.bssid) e.currentTarget.style.background = 'rgba(255,255,255,0.02)'; }}
                              onMouseLeave={(e) => { if (selectedPmkidTarget?.bssid !== net.bssid) e.currentTarget.style.background = 'transparent'; }}
                            >
                              <div>
                                <div style={{ color: '#e0e0e0', fontSize: '13px' }}>{net.ssid || '<HIDDEN>'}</div>
                                <div style={{ color: '#555', fontSize: '9px', fontFamily: 'monospace' }}>{net.bssid}</div>
                              </div>
                              <div style={{ color: '#666', fontSize: '10px', display: 'flex', alignItems: 'center' }}>{net.band || '2.4GHz'}</div>
                              <div style={{ color: '#888', fontSize: '11px', display: 'flex', alignItems: 'center' }}>CH {net.channel}</div>
                              <div style={{ color: net.signal > -50 ? '#0f0' : net.signal > -70 ? '#ff0' : '#f00', fontSize: '11px', fontWeight: 'bold', display: 'flex', alignItems: 'center' }}>
                                {net.signal}
                              </div>
                            </div>
                          ))
                        )}
                      </div>
                      <button
                        onClick={async () => {
                          if (!selectedPmkidTarget) return;
                          const result = await api('/pmkid/start', {
                            bssid: selectedPmkidTarget.bssid,
                            ssid: selectedPmkidTarget.ssid || 'Unknown',
                            channel: selectedPmkidTarget.channel,
                            timeout: pmkidTimeout
                          });
                          if (result?.status === 'success') {
                            setPmkidRunning(true);
                          } else {
                            alert(result?.message || 'Failed to start PMKID capture');
                          }
                        }}
                        disabled={!selectedPmkidTarget}
                        className="cyber-button"
                        style={{
                          width: '100%', marginTop: '15px', padding: '14px', fontSize: '14px', fontWeight: 'bold',
                          borderColor: selectedPmkidTarget ? '#00d4ff' : '#333',
                          color: selectedPmkidTarget ? '#00d4ff' : '#555',
                          background: selectedPmkidTarget ? 'rgba(0, 212, 255, 0.08)' : 'transparent',
                          opacity: selectedPmkidTarget ? 1 : 0.4,
                          cursor: selectedPmkidTarget ? 'pointer' : 'not-allowed'
                        }}
                      >
                        {selectedPmkidTarget
                          ? `START PMKID CAPTURE — ${selectedPmkidTarget.ssid || selectedPmkidTarget.bssid}`
                          : 'SELECT A TARGET NETWORK'}
                      </button>
                    </div>
                  )}
                </div>
              )}

              {/* ===== CAPTURED SUB-TAB ===== */}
              {pmkidSubTab === 'CAPTURED' && (
                <div style={{ height: 'calc(100vh - 300px)', display: 'flex', flexDirection: 'column' }}>
                  <div style={{ flex: 1, overflowY: 'auto' }}>
                    {pmkidResults.length === 0 ? (
                      <div style={{ padding: '40px', textAlign: 'center', color: '#666' }}>
                        <div style={{ fontSize: '48px', marginBottom: '10px' }}>🔐</div>
                        <div style={{ fontSize: '14px' }}>No PMKID hashes captured yet</div>
                        <div style={{ fontSize: '11px', marginTop: '5px', color: '#444' }}>Go to NETWORKS tab to capture PMKID hashes</div>
                      </div>
                    ) : (
                      <div>
                        {/* Header */}
                        <div style={{
                          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                          padding: '10px 20px', borderBottom: '1px solid #222', background: '#0a0a0a'
                        }}>
                          <div style={{ color: '#666', fontSize: '11px', fontWeight: 'bold' }}>
                            {pmkidResults.length} PMKID HASH{pmkidResults.length !== 1 ? 'ES' : ''} CAPTURED
                          </div>
                          <button
                            onClick={async () => {
                              const res = await fetch('http://localhost:8000/pmkid/results');
                              const data = await res.json();
                              if (data.results) setPmkidResults(data.results);
                            }}
                            className="cyber-button"
                            style={{ fontSize: '9px', padding: '4px 8px' }}
                          >
                            REFRESH
                          </button>
                        </div>

                        {/* Column headers */}
                        <div style={{
                          display: 'grid',
                          gridTemplateColumns: 'minmax(160px, 2fr) 70px 1fr 70px 180px',
                          padding: '10px 20px', borderBottom: '1px solid #222', background: '#080808',
                          color: '#00d4ff', fontSize: '10px', fontWeight: 'bold', position: 'sticky', top: 0, zIndex: 10
                        }}>
                          <div>SSID / BSSID</div>
                          <div>TYPE</div>
                          <div>HASH</div>
                          <div>TIME</div>
                          <div>ACTIONS</div>
                        </div>

                        {/* Rows */}
                        {pmkidResults.map((result, i) => (
                          <div key={i} style={{
                            display: 'grid',
                            gridTemplateColumns: 'minmax(160px, 2fr) 70px 1fr 70px 180px',
                            padding: '8px 20px', borderBottom: '1px solid #111', alignItems: 'center',
                            background: crackTarget?.bssid === result.bssid ? 'rgba(255, 196, 0, 0.1)' : 'transparent',
                            fontSize: '12px'
                          }}>
                            <div>
                              <div style={{ color: '#e0e0e0', fontWeight: 'bold' }}>{result.ssid}</div>
                              <div style={{ color: '#444', fontSize: '10px', fontFamily: 'monospace' }}>{result.bssid}</div>
                            </div>
                            <div style={{
                              color: result.hash_type === 'PMKID' ? '#00d4ff' : '#ff0',
                              fontSize: '10px', fontWeight: 'bold'
                            }}>
                              {result.hash_type}
                            </div>
                            <div style={{ color: '#0f0', fontFamily: 'monospace', fontSize: '10px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {result.hash}
                            </div>
                            <div style={{ color: '#666', fontSize: '10px' }}>{result.time}</div>
                            <div style={{ display: 'flex', gap: '5px', justifyContent: 'flex-end' }}>
                              <button
                                onClick={() => startCrack({ bssid: result.bssid, ssid: result.ssid }, 'pmkid')}
                                className="cyber-button gold"
                                style={{ fontSize: '9px', padding: '2px 8px' }}
                                disabled={cracking}
                              >
                                {crackTarget?.bssid === result.bssid && cracking ? 'CRACKING...' : 'CRACK'}
                              </button>
                              <button
                                onClick={() => setPmkidResults(prev => prev.filter((_, idx) => idx !== i))}
                                className="cyber-button"
                                style={{ fontSize: '9px', padding: '2px 6px', opacity: 0.6 }}
                              >
                                REMOVE
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Cracking now in unified CRACK tab */}
                </div>
              )}
            </div>
          )}

          {/* ========== WPS TAB ========== */}
          {activeTab === 'WPS' && (
            <div>
              {/* WPS BANNER */}
              <div style={{
                background: 'rgba(255, 136, 0, 0.06)',
                border: '2px solid #ff8800',
                borderRadius: '8px',
                padding: '15px 20px',
                margin: '15px 20px 0'
              }}>
                <h3 style={{ color: '#ff8800', marginBottom: '5px', fontSize: '14px' }}>
                  WPS ATTACK MODULE
                </h3>
                <p style={{ color: '#888', fontSize: '10px', marginBottom: '0' }}>
                  WPS PIN Recovery via Reaver. Pixie Dust (offline, fast) + PIN Bruteforce (online, slow). Linux/Kali only.
                </p>
              </div>

              {/* WPS SUB-TABS */}
              <div style={{ display: 'flex', gap: '8px', padding: '15px 20px 10px' }}>
                {['NETWORKS', 'RESULTS'].map(subTab => (
                  <button
                    key={subTab}
                    onClick={() => setWpsSubTab(subTab)}
                    className="cyber-button"
                    style={{
                      background: wpsSubTab === subTab ? '#ff8800' : 'transparent',
                      color: wpsSubTab === subTab ? '#000' : '#ff8800',
                      border: `1px solid ${wpsSubTab === subTab ? '#ff8800' : '#333'}`,
                      padding: '8px 16px',
                      fontSize: '11px',
                      fontWeight: 'bold',
                      letterSpacing: '1px'
                    }}
                  >
                    {subTab} {subTab === 'RESULTS' && `(${wpsResults.length})`}
                  </button>
                ))}
              </div>

              {/* ===== NETWORKS SUB-TAB ===== */}
              {wpsSubTab === 'NETWORKS' && (
                <div style={{ padding: '0 20px 20px' }}>

                  {/* Running Status */}
                  {wpsRunning && (
                    <div style={{
                      background: 'rgba(255, 136, 0, 0.08)',
                      border: '1px solid #ff8800',
                      borderRadius: '8px',
                      padding: '15px',
                      marginBottom: '20px'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div>
                          <div style={{ color: '#ff8800', fontWeight: 'bold', fontSize: '14px', marginBottom: '5px' }}>
                            <span className="blink" style={{ marginRight: '8px' }}>●</span>
                            WPS ATTACK ACTIVE
                          </div>
                          <div style={{ fontSize: '11px', color: '#aaa' }}>
                            SSID: <span style={{ color: '#fff' }}>{wpsStatus.target_ssid}</span> {' '}
                            BSSID: <span style={{ color: '#888', fontFamily: 'monospace' }}>{wpsStatus.target_bssid}</span> {' '}
                            CH: <span style={{ color: '#fff' }}>{wpsStatus.target_channel}</span> {' '}
                            Type: <span style={{ color: '#ff8800' }}>{wpsStatus.attack_type === 'pixie_dust' ? 'PIXIE DUST' : 'PIN BRUTEFORCE'}</span> {' '}
                            Elapsed: <span style={{ color: '#ff0' }}>{wpsStatus.elapsed_seconds || 0}s</span>
                          </div>
                        </div>
                        <button
                          onClick={async () => {
                            await api('/wps/stop');
                            setWpsRunning(false);
                          }}
                          className="cyber-button"
                          style={{ fontSize: '12px', padding: '8px 20px', borderColor: '#ff8800', color: '#ff8800' }}
                        >
                          STOP ATTACK
                        </button>
                      </div>
                    </div>
                  )}

                  {/* WPS-Enabled Networks List */}
                  <div className="glass-panel" style={{ padding: '15px', marginBottom: '20px' }}>
                    <h4 style={{ color: '#ff8800', marginBottom: '12px', fontSize: '12px', letterSpacing: '1px' }}>
                      WPS-ENABLED NETWORKS ({networks.filter(n => n.wps).length})
                    </h4>

                    {networks.filter(n => n.wps).length === 0 ? (
                      <div style={{ color: '#555', fontSize: '11px', padding: '20px', textAlign: 'center' }}>
                        No WPS-enabled networks detected. Start a WiFi scan first.
                      </div>
                    ) : (
                      <>
                        <div style={{
                          display: 'grid',
                          gridTemplateColumns: '1fr 120px 50px 50px',
                          padding: '8px 15px',
                          borderBottom: '1px solid #222',
                          color: '#666',
                          fontSize: '10px',
                          fontWeight: 'bold',
                          letterSpacing: '1px'
                        }}>
                          <div>SSID / BSSID</div>
                          <div>BAND</div>
                          <div>CH</div>
                          <div>SIGNAL</div>
                        </div>
                        <div style={{ maxHeight: '250px', overflowY: 'auto' }}>
                          {networks.filter(n => n.wps).map((net, i) => (
                            <div
                              key={i}
                              onClick={() => setSelectedWpsTarget(net)}
                              style={{
                                display: 'grid',
                                gridTemplateColumns: '1fr 120px 50px 50px',
                                padding: '10px 15px',
                                borderBottom: '1px solid #111',
                                cursor: 'pointer',
                                background: selectedWpsTarget?.bssid === net.bssid ? 'rgba(255, 136, 0, 0.1)' : 'transparent',
                                borderLeft: selectedWpsTarget?.bssid === net.bssid ? '3px solid #ff8800' : '3px solid transparent',
                                transition: 'all 0.15s'
                              }}
                              onMouseEnter={(e) => { if (selectedWpsTarget?.bssid !== net.bssid) e.currentTarget.style.background = 'rgba(255,255,255,0.02)'; }}
                              onMouseLeave={(e) => { if (selectedWpsTarget?.bssid !== net.bssid) e.currentTarget.style.background = 'transparent'; }}
                            >
                              <div>
                                <div style={{ color: '#e0e0e0', fontSize: '13px' }}>{net.ssid || '<HIDDEN>'}</div>
                                <div style={{ color: '#555', fontSize: '9px', fontFamily: 'monospace' }}>{net.bssid}</div>
                              </div>
                              <div style={{ color: '#666', fontSize: '10px', display: 'flex', alignItems: 'center' }}>
                                {net.band || '2.4GHz'}
                              </div>
                              <div style={{ color: '#888', fontSize: '11px', display: 'flex', alignItems: 'center' }}>
                                {net.channel}
                              </div>
                              <div style={{
                                color: net.signal > -50 ? '#0f0' : net.signal > -70 ? '#ff0' : '#f00',
                                fontSize: '11px',
                                fontWeight: 'bold',
                                display: 'flex',
                                alignItems: 'center'
                              }}>
                                {net.signal}
                              </div>
                            </div>
                          ))}
                        </div>
                      </>
                    )}
                  </div>

                  {/* Configuration Panel */}
                  <div className="glass-panel" style={{ padding: '15px', marginBottom: '20px' }}>
                    <h4 style={{ color: '#ff8800', marginBottom: '12px', fontSize: '12px', letterSpacing: '1px' }}>
                      ATTACK CONFIGURATION
                    </h4>

                    {/* Attack Type Selection */}
                    <div style={{ marginBottom: '15px' }}>
                      <div style={{ color: '#888', fontSize: '10px', marginBottom: '8px', letterSpacing: '1px' }}>ATTACK TYPE</div>
                      <div style={{ display: 'flex', gap: '8px' }}>
                        {[
                          { id: 'pixie_dust', label: 'PIXIE DUST', desc: 'Fast offline PIN recovery' },
                          { id: 'pin_bruteforce', label: 'PIN BRUTEFORCE', desc: 'All PIN combinations (slow)' }
                        ].map(t => (
                          <button
                            key={t.id}
                            onClick={() => setWpsAttackType(t.id)}
                            className="cyber-button"
                            style={{
                              flex: 1,
                              padding: '10px',
                              background: wpsAttackType === t.id ? 'rgba(255, 136, 0, 0.15)' : 'transparent',
                              borderColor: wpsAttackType === t.id ? '#ff8800' : '#333',
                              color: wpsAttackType === t.id ? '#ff8800' : '#666',
                              textAlign: 'center'
                            }}
                          >
                            <div style={{ fontSize: '12px', fontWeight: 'bold', marginBottom: '4px' }}>{t.label}</div>
                            <div style={{ fontSize: '9px', opacity: 0.7 }}>{t.desc}</div>
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Start Button */}
                    <button
                      onClick={async () => {
                        if (!selectedWpsTarget) return;
                        setWpsLogs([]);
                        const result = await api('/wps/start', {
                          bssid: selectedWpsTarget.bssid,
                          ssid: selectedWpsTarget.ssid || 'Unknown',
                          channel: selectedWpsTarget.channel,
                          attack_type: wpsAttackType
                        });
                        if (result?.status === 'success') {
                          setWpsRunning(true);
                        } else {
                          alert(result?.message || 'Failed to start WPS attack');
                        }
                      }}
                      disabled={!selectedWpsTarget || wpsRunning}
                      className="cyber-button"
                      style={{
                        width: '100%',
                        padding: '14px',
                        fontSize: '14px',
                        fontWeight: 'bold',
                        borderColor: selectedWpsTarget && !wpsRunning ? '#ff8800' : '#333',
                        color: selectedWpsTarget && !wpsRunning ? '#ff8800' : '#555',
                        background: selectedWpsTarget && !wpsRunning ? 'rgba(255, 136, 0, 0.08)' : 'transparent',
                        opacity: selectedWpsTarget && !wpsRunning ? 1 : 0.4,
                        cursor: selectedWpsTarget && !wpsRunning ? 'pointer' : 'not-allowed'
                      }}
                    >
                      {wpsRunning
                        ? 'WPS ATTACK RUNNING...'
                        : selectedWpsTarget
                          ? `START WPS ATTACK — ${selectedWpsTarget.ssid || selectedWpsTarget.bssid}`
                          : 'SELECT A WPS-ENABLED NETWORK'}
                    </button>
                  </div>

                  {/* Attack Console */}
                  {wpsLogs.length > 0 && (
                    <div style={{
                      border: '2px solid #ff8800',
                      borderRadius: '8px',
                      overflow: 'hidden',
                      display: 'flex',
                      flexDirection: 'column',
                      height: '280px'
                    }}>
                      {/* Console Header */}
                      <div style={{
                        padding: '10px 20px',
                        borderBottom: '1px solid #222',
                        background: '#080808',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center'
                      }}>
                        <span style={{ color: '#ff8800', fontSize: '11px', letterSpacing: '1px' }}>
                          WPS ATTACK: {wpsStatus.target_ssid} ({wpsStatus.target_bssid}) — {wpsStatus.attack_type === 'pixie_dust' ? 'PIXIE DUST' : 'PIN BRUTEFORCE'}
                        </span>
                        {wpsRunning && (
                          <button
                            onClick={async () => {
                              await api('/wps/stop');
                              setWpsRunning(false);
                            }}
                            className="cyber-button"
                            style={{ fontSize: '10px', padding: '4px 8px', borderColor: '#ff8800', color: '#ff8800' }}
                          >
                            STOP
                          </button>
                        )}
                      </div>

                      {/* Console Body */}
                      <div style={{
                        flex: 1,
                        background: '#000',
                        padding: '15px 20px',
                        fontFamily: 'monospace',
                        fontSize: '11px',
                        color: '#eee',
                        overflowY: 'auto'
                      }}>
                        {wpsLogs.map((L, i) => (
                          <div key={i} style={{
                            marginBottom: '4px',
                            borderBottom: '1px solid #111',
                            paddingBottom: '2px',
                            color: L.includes('WPS PIN') || L.includes('WPA PSK') || L.includes('SUCCESS') ? '#0f0' :
                                   L.includes('WARNING') || L.includes('rate limiting') ? '#ff0' :
                                   L.includes('FAILED') || L.includes('ERROR') || L.includes('failed') ? '#f00' : '#eee'
                          }}>
                            {L}
                          </div>
                        ))}
                        <div ref={wpsLogEndRef} />
                      </div>

                      {/* Console Footer */}
                      <div style={{ padding: '8px 20px', background: '#080808', borderTop: '1px solid #222', display: 'flex', alignItems: 'center', gap: '10px', fontSize: '10px' }}>
                        <div style={{ color: '#666', fontWeight: 'bold' }}>TYPE:</div>
                        <div style={{ flex: 1, color: '#ff8800', fontSize: '10px' }}>
                          {wpsAttackType === 'pixie_dust' ? 'Pixie Dust (Offline PIN Recovery)' : 'PIN Bruteforce (Online, All Combinations)'}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ===== RESULTS SUB-TAB ===== */}
              {wpsSubTab === 'RESULTS' && (
                <div style={{ padding: '0 20px 20px' }}>
                  <div className="glass-panel" style={{ padding: '20px' }}>
                    <div style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      marginBottom: '15px',
                      borderBottom: '1px solid #222',
                      paddingBottom: '10px'
                    }}>
                      <h4 style={{ color: '#ff8800', fontSize: '13px', margin: 0, letterSpacing: '1px' }}>
                        {wpsResults.length} WPS PIN(S) RECOVERED
                      </h4>
                    </div>

                    {wpsResults.length === 0 ? (
                      <div style={{ color: '#555', fontSize: '11px', padding: '30px', textAlign: 'center' }}>
                        No WPS PINs recovered yet. Go to NETWORKS tab and start an attack.
                      </div>
                    ) : (
                      <>
                        {/* Table Header */}
                        <div style={{
                          display: 'grid',
                          gridTemplateColumns: '1fr 100px 1fr 100px 130px 70px',
                          padding: '8px 12px',
                          borderBottom: '1px solid #333',
                          color: '#666',
                          fontSize: '10px',
                          fontWeight: 'bold',
                          letterSpacing: '1px'
                        }}>
                          <div>SSID / BSSID</div>
                          <div>PIN</div>
                          <div>PASSWORD</div>
                          <div>TYPE</div>
                          <div>TIME</div>
                          <div>ACTIONS</div>
                        </div>

                        {/* Table Rows */}
                        {wpsResults.map((r, i) => (
                          <div key={i} style={{
                            display: 'grid',
                            gridTemplateColumns: '1fr 100px 1fr 100px 130px 70px',
                            padding: '12px',
                            borderBottom: '1px solid #111',
                            alignItems: 'center'
                          }}>
                            <div>
                              <div style={{ color: '#e0e0e0', fontSize: '12px' }}>{r.ssid || 'Unknown'}</div>
                              <div style={{ color: '#555', fontSize: '9px', fontFamily: 'monospace' }}>{r.bssid}</div>
                            </div>
                            <div style={{ color: '#0f0', fontSize: '12px', fontFamily: 'monospace', fontWeight: 'bold' }}>
                              {r.pin}
                            </div>
                            <div style={{ color: '#0f0', fontSize: '12px', fontFamily: 'monospace', fontWeight: 'bold' }}>
                              {r.psk}
                            </div>
                            <div style={{ color: '#ff8800', fontSize: '10px' }}>
                              {r.attack_type === 'pixie_dust' ? 'PIXIE' : 'BRUTE'}
                            </div>
                            <div style={{ color: '#666', fontSize: '10px' }}>
                              {r.time}
                            </div>
                            <div>
                              <button
                                onClick={() => {
                                  navigator.clipboard.writeText(r.psk !== 'N/A' ? r.psk : r.pin);
                                }}
                                className="cyber-button"
                                style={{ fontSize: '9px', padding: '3px 8px', borderColor: '#ff8800', color: '#ff8800' }}
                              >
                                COPY
                              </button>
                            </div>
                          </div>
                        ))}
                      </>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'FLOOD' && (
            <div>
              {/* Banner */}
              <div style={{
                padding: '15px 20px',
                background: 'linear-gradient(135deg, rgba(255, 0, 85, 0.1), transparent)',
                borderBottom: '1px solid #ff0055',
                display: 'flex', alignItems: 'center', gap: '10px'
              }}>
                <span style={{ color: '#ff0055', fontWeight: 'bold', fontSize: '14px', letterSpacing: '2px' }}>BEACON FLOOD MODULE</span>
                <span style={{ color: '#666', fontSize: '11px' }}>Beacon Flood via mdk4. Broadcast fake SSIDs. Linux/Kali only.</span>
              </div>

              {/* Active Status Panel */}
              {floodRunning && (
                <div style={{
                  margin: '15px 20px',
                  padding: '15px',
                  background: 'rgba(255, 0, 85, 0.05)',
                  border: '1px solid #ff0055',
                  borderRadius: '8px'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <div style={{
                        width: '8px', height: '8px', borderRadius: '50%',
                        background: '#ff0055',
                        animation: 'pulse 1s infinite'
                      }}></div>
                      <span style={{ color: '#ff0055', fontWeight: 'bold', fontSize: '12px', letterSpacing: '1px' }}>BEACON FLOOD ACTIVE</span>
                    </div>
                    <button onClick={() => fetch('http://localhost:8000/flood/stop', { method: 'POST' })}
                      style={{
                        padding: '6px 20px', background: '#ff0055', color: '#000',
                        border: 'none', borderRadius: '4px', cursor: 'pointer',
                        fontWeight: 'bold', fontSize: '11px'
                      }}>STOP FLOOD</button>
                  </div>
                  <div style={{ marginTop: '10px', fontSize: '11px', color: '#888' }}>
                    Mode: <span style={{ color: '#fff' }}>{(floodStatus.mode || 'random').toUpperCase()}</span>{' '}
                    Channel: <span style={{ color: '#fff' }}>{floodStatus.target_channel || 'ALL'}</span>{' '}
                    Speed: <span style={{ color: '#ff0055' }}>{floodStatus.speed || 50} pps</span>{' '}
                    SSIDs: <span style={{ color: '#ff0' }}>{floodStatus.ssid_count || 'Random'}</span>{' '}
                    Elapsed: <span style={{ color: '#ff0' }}>{floodStatus.elapsed_seconds || 0}s</span>
                  </div>
                </div>
              )}

              {/* Configuration Panel — hidden when running */}
              {!floodRunning && (
                <div style={{ padding: '20px' }}>
                  {/* SSID Source Selection */}
                  <div style={{ marginBottom: '20px' }}>
                    <div style={{ color: '#888', fontSize: '10px', letterSpacing: '1px', marginBottom: '8px' }}>SSID SOURCE</div>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      {[
                        { id: 'random', label: 'RANDOM', desc: 'mdk4 generates random SSIDs' },
                        { id: 'manual', label: 'MANUAL', desc: 'Type SSIDs manually' },
                        { id: 'file', label: 'FILE', desc: 'Upload .txt file' }
                      ].map(m => (
                        <button key={m.id} onClick={() => setFloodMode(m.id)}
                          style={{
                            flex: 1, padding: '12px', background: floodMode === m.id ? 'rgba(255, 0, 85, 0.15)' : 'transparent',
                            border: `1px solid ${floodMode === m.id ? '#ff0055' : '#333'}`,
                            borderRadius: '6px', cursor: 'pointer', textAlign: 'left'
                          }}>
                          <div style={{ color: floodMode === m.id ? '#ff0055' : '#888', fontWeight: 'bold', fontSize: '12px' }}>{m.label}</div>
                          <div style={{ color: '#555', fontSize: '10px', marginTop: '4px' }}>{m.desc}</div>
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Manual SSID Textarea */}
                  {floodMode === 'manual' && (
                    <div style={{ marginBottom: '20px' }}>
                      <textarea
                        value={floodManualSSIDs}
                        onChange={(e) => setFloodManualSSIDs(e.target.value)}
                        placeholder={"Enter SSIDs, one per line...\nFBI Surveillance Van\nFree WiFi\nLoading..."}
                        style={{
                          width: '100%', minHeight: '120px', background: '#0a0a0a',
                          border: '1px solid #333', borderRadius: '6px', color: '#fff',
                          fontFamily: 'monospace', fontSize: '12px', padding: '10px',
                          resize: 'vertical', outline: 'none'
                        }}
                      />
                      <div style={{ color: '#666', fontSize: '10px', marginTop: '4px' }}>
                        {floodManualSSIDs.split('\n').filter(l => l.trim()).length} SSIDs entered
                      </div>
                    </div>
                  )}

                  {/* File Upload */}
                  {floodMode === 'file' && (
                    <div style={{ marginBottom: '20px' }}>
                      <input
                        ref={floodFileInputRef}
                        type="file"
                        accept=".txt"
                        style={{ display: 'none' }}
                        onChange={(e) => {
                          const file = e.target.files[0];
                          if (!file) return;
                          setFloodFileName(file.name);
                          const reader = new FileReader();
                          reader.onload = (ev) => {
                            const lines = ev.target.result.split('\n').map(l => l.trim()).filter(l => l.length > 0);
                            setFloodFileSSIDs(lines);
                          };
                          reader.readAsText(file);
                        }}
                      />
                      <button
                        onClick={() => floodFileInputRef.current?.click()}
                        style={{
                          padding: '12px 24px', background: 'transparent',
                          border: '1px dashed #ff0055', borderRadius: '6px',
                          color: '#ff0055', cursor: 'pointer', fontSize: '12px',
                          width: '100%'
                        }}>
                        {floodFileName ? floodFileName : 'Click to upload .txt file'}
                      </button>
                      {floodFileSSIDs.length > 0 && (
                        <div style={{ color: '#ff0055', fontSize: '11px', marginTop: '6px' }}>
                          {floodFileSSIDs.length} SSIDs loaded from {floodFileName}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Channel + Speed */}
                  <div style={{ display: 'flex', gap: '20px', marginBottom: '20px' }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ color: '#888', fontSize: '10px', letterSpacing: '1px', marginBottom: '6px' }}>CHANNEL (0 = ALL)</div>
                      <input
                        type="number" min="0" max="14" value={floodChannel}
                        onChange={(e) => setFloodChannel(parseInt(e.target.value) || 0)}
                        style={{
                          width: '100%', padding: '8px 12px', background: '#0a0a0a',
                          border: '1px solid #333', borderRadius: '4px', color: '#fff',
                          fontFamily: 'monospace', fontSize: '13px', outline: 'none'
                        }}
                      />
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ color: '#888', fontSize: '10px', letterSpacing: '1px', marginBottom: '6px' }}>
                        SPEED: <span style={{ color: '#ff0055' }}>{floodSpeed === 0 ? 'MAX' : `${floodSpeed} pps`}</span>
                      </div>
                      <input
                        type="range" min="0" max="1000" step="50" value={floodSpeed}
                        onChange={(e) => setFloodSpeed(parseInt(e.target.value))}
                        style={{ width: '100%', accentColor: '#ff0055' }}
                      />
                      <div style={{ display: 'flex', justifyContent: 'space-between', color: '#444', fontSize: '9px' }}>
                        <span>MAX</span><span>1000</span>
                      </div>
                    </div>
                  </div>

                  {/* START Button */}
                  <button
                    onClick={() => {
                      let ssidList = [];
                      if (floodMode === 'manual') {
                        ssidList = floodManualSSIDs.split('\n').map(l => l.trim()).filter(l => l);
                        if (ssidList.length === 0) return alert('Enter at least one SSID');
                      } else if (floodMode === 'file') {
                        ssidList = floodFileSSIDs;
                        if (ssidList.length === 0) return alert('Upload a .txt file first');
                      }
                      setFloodLogs([]);
                      fetch('http://localhost:8000/flood/start', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                          ssid_list: ssidList,
                          channel: floodChannel,
                          speed: floodSpeed,
                          mode: floodMode
                        })
                      }).then(r => r.json()).then(d => {
                        if (d.status !== 'success') alert(d.message);
                      });
                    }}
                    style={{
                      width: '100%', padding: '14px', background: '#ff0055', color: '#000',
                      border: 'none', borderRadius: '6px', cursor: 'pointer',
                      fontWeight: 'bold', fontSize: '13px', letterSpacing: '2px'
                    }}>
                    START BEACON FLOOD
                  </button>
                </div>
              )}

              {/* Flood Console */}
              {floodLogs.length > 0 && (
                <div style={{
                  margin: '0 20px 20px',
                  border: `1px solid ${floodRunning ? '#ff0055' : '#333'}`,
                  borderRadius: '8px',
                  overflow: 'hidden'
                }}>
                  <div style={{
                    padding: '10px 15px',
                    background: floodRunning ? 'rgba(255, 0, 85, 0.1)' : '#111',
                    borderBottom: '1px solid #222',
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center'
                  }}>
                    <span style={{ color: floodRunning ? '#ff0055' : '#666', fontSize: '11px', fontWeight: 'bold', letterSpacing: '1px' }}>
                      {floodRunning ? 'BEACON FLOOD ACTIVE' : 'FLOOD LOG'}
                    </span>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      {floodRunning && (
                        <button onClick={() => fetch('http://localhost:8000/flood/stop', { method: 'POST' })}
                          style={{
                            padding: '4px 12px', background: '#ff0055', color: '#000',
                            border: 'none', borderRadius: '3px', cursor: 'pointer',
                            fontSize: '10px', fontWeight: 'bold'
                          }}>STOP</button>
                      )}
                      {!floodRunning && (
                        <button onClick={() => setFloodLogs([])}
                          style={{
                            padding: '4px 12px', background: 'transparent', color: '#666',
                            border: '1px solid #333', borderRadius: '3px', cursor: 'pointer',
                            fontSize: '10px'
                          }}>CLEAR</button>
                      )}
                    </div>
                  </div>
                  <div style={{
                    maxHeight: '300px', overflowY: 'auto', padding: '10px 15px',
                    background: '#050505', fontFamily: 'monospace', fontSize: '11px'
                  }}>
                    {floodLogs.map((log, i) => (
                      <div key={i} style={{
                        color: log.includes('ERROR') ? '#ff0000' :
                               log.includes('SUCCESS') || log.includes('CMD:') ? '#ff0055' :
                               log.includes('STOPPED') ? '#ff8800' : '#888',
                        marginBottom: '2px', wordBreak: 'break-all'
                      }}>{log}</div>
                    ))}
                    <div ref={floodLogEndRef} />
                  </div>
                  <div style={{
                    padding: '8px 15px', borderTop: '1px solid #222',
                    background: '#0a0a0a', fontSize: '10px', color: '#555'
                  }}>
                    Mode: {(floodStatus.mode || floodMode).toUpperCase()} | Channel: {floodStatus.target_channel || 'ALL'} | Speed: {floodStatus.speed || floodSpeed} pps
                    {floodStatus.ssid_count > 0 && ` | SSIDs: ${floodStatus.ssid_count}`}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'CLIENTS' && (() => {
            const connectedCount = wifiClients ? wifiClients.filter(c => c && c.connected_to).length : 0;
            const probingCount = wifiClients ? wifiClients.filter(c => c && !c.connected_to).length : 0;
            const sortedClients = wifiClients ? [...wifiClients].filter(Boolean).sort((a, b) => {
              if (a.connected_to && !b.connected_to) return -1;
              if (!a.connected_to && b.connected_to) return 1;
              return (b.signal || -100) - (a.signal || -100);
            }) : [];
            const bssidToSSID = {};
            networks.forEach(n => { if (n.bssid && n.ssid) bssidToSSID[n.bssid] = n.ssid; });

            // === PROBE ANALYZER DATA ===
            const allProbes = [];
            const ssidProbeCount = {};
            const ssidClients = {};
            const clientProfiles = [];
            const nearbySSIDs = new Set(networks.map(n => n.ssid).filter(Boolean));
            const vulnerableNetworks = ['linksys', 'netgear', 'default', 'dlink', 'SETUP', 'xfinitywifi', 'attwifi',
              'FreeWifi', 'Free WiFi', 'Free_WiFi', 'PUBLIC', 'Guest', 'GUEST', 'hotel', 'Hotel', 'Airport',
              'Starbucks', 'McDonalds WiFi', 'AndroidAP', 'iPhone', 'DIRECT-', 'HP-Print', 'ASUS', 'TP-Link',
              'Vodafone', 'SKY', 'BTHub', 'virginmedia', 'TALKTALK', 'EE-BrightBox', 'plusnet'];

            (wifiClients || []).filter(Boolean).forEach(client => {
              if (client.probes && client.probes.length > 0) {
                const profile = {
                  mac: client.mac,
                  vendor: client.vendor || 'Unknown',
                  signal: client.signal,
                  connected_to: client.connected_to,
                  probes: client.probes,
                  nearbyMatches: [],
                  vulnerableProbes: []
                };
                client.probes.forEach(ssid => {
                  if (!ssid) return;
                  ssidProbeCount[ssid] = (ssidProbeCount[ssid] || 0) + 1;
                  if (!ssidClients[ssid]) ssidClients[ssid] = [];
                  ssidClients[ssid].push(client.mac);
                  allProbes.push({ ssid, mac: client.mac, vendor: client.vendor });
                  if (nearbySSIDs.has(ssid)) profile.nearbyMatches.push(ssid);
                  if (vulnerableNetworks.some(v => ssid.toLowerCase().includes(v.toLowerCase()))) {
                    profile.vulnerableProbes.push(ssid);
                  }
                });
                clientProfiles.push(profile);
              }
            });

            // Sort SSIDs by probe count
            const sortedSSIDs = Object.entries(ssidProbeCount).sort((a, b) => b[1] - a[1]);
            // Shared networks: SSIDs probed by 2+ clients
            const sharedNetworks = Object.entries(ssidClients).filter(([, macs]) => macs.length >= 2)
              .sort((a, b) => b[1].length - a[1].length);
            // Vulnerable clients
            const vulnerableClients = clientProfiles.filter(p => p.vulnerableProbes.length > 0);
            // Nearby matches
            const nearbyMatches = [];
            Object.entries(ssidClients).forEach(([ssid, macs]) => {
              if (nearbySSIDs.has(ssid)) nearbyMatches.push({ ssid, clients: macs });
            });

            return (
            <div>
              {/* Sub-tab navigation */}
              <div style={{
                display: 'flex', borderBottom: '1px solid #222', background: '#080808'
              }}>
                {['CLIENT LIST', 'PROBE ANALYZER'].map(tab => (
                  <button key={tab} onClick={() => setClientsSubTab(tab)} style={{
                    padding: '10px 24px', background: 'none', border: 'none',
                    color: clientsSubTab === tab ? '#0f0' : '#555', cursor: 'pointer',
                    borderBottom: clientsSubTab === tab ? '2px solid #0f0' : '2px solid transparent',
                    fontSize: '11px', fontWeight: 'bold', letterSpacing: '1px',
                    transition: 'all 0.2s'
                  }}>{tab}</button>
                ))}
                <div style={{ flex: 1 }} />
                <div style={{ display: 'flex', gap: '16px', padding: '10px 20px', fontSize: '11px' }}>
                  <span style={{ color: '#888' }}>Total: <span style={{ color: '#fff', fontWeight: 'bold' }}>{sortedClients.length}</span></span>
                  <span style={{ color: '#888' }}>Connected: <span style={{ color: '#0f0', fontWeight: 'bold' }}>{connectedCount}</span></span>
                  <span style={{ color: '#888' }}>Probing: <span style={{ color: '#666', fontWeight: 'bold' }}>{probingCount}</span></span>
                  <span style={{ color: '#888' }}>Probes: <span style={{ color: '#ff0', fontWeight: 'bold' }}>{allProbes.length}</span></span>
                </div>
              </div>

              {/* ========== CLIENT LIST SUB-TAB ========== */}
              {clientsSubTab === 'CLIENT LIST' && (
                <div>
                  <div style={{
                    display: 'grid',
                    gridTemplateColumns: '110px 1fr 50px 55px 80px 1fr',
                    padding: '10px 20px',
                    borderBottom: '1px solid #222',
                    background: '#080808',
                    color: 'var(--color-secondary)',
                    fontSize: '12px',
                    fontWeight: 'bold',
                    position: 'sticky',
                    top: 0,
                    zIndex: 10
                  }}>
                    <div>MAC ADDRESS</div>
                    <div>VENDOR</div>
                    <div>RSSI</div>
                    <div>DIST</div>
                    <div>STATUS</div>
                    <div>ASSOCIATED AP / PROBES</div>
                  </div>
                  <div>
                    {sortedClients.length === 0 && (
                      <div style={{ padding: '40px 20px', textAlign: 'center', color: '#444', fontSize: '12px' }}>
                        No WiFi clients detected yet. Start scanning to detect devices...
                      </div>
                    )}
                    {sortedClients.map((client, i) => {
                      const isConnected = client.connected_to !== null;
                      const signalColor = client.signal > -50 ? '#0f0' : client.signal > -70 ? '#ff0' : '#f00';
                      const distance = client.distance ? `${client.distance}m` : '?';
                      const apSSID = isConnected ? (bssidToSSID[client.connected_to] || null) : null;

                      return (
                        <div key={client.mac} style={{
                          display: 'grid',
                          gridTemplateColumns: '110px 1fr 50px 55px 80px 1fr',
                          padding: '12px 20px',
                          borderBottom: '1px solid #111',
                          alignItems: 'center',
                          fontSize: '13px',
                          background: isConnected ? 'rgba(0, 255, 0, 0.05)' : 'transparent',
                          borderLeft: isConnected ? '2px solid #0f0' : 'none'
                        }}>
                          <div style={{ fontFamily: 'monospace', color: '#666', fontSize: '10px' }}>
                            {client.mac}
                          </div>
                          <div>
                            <div style={{ color: '#e0e0e0' }}>
                              {client.vendor !== 'Unknown' ? client.vendor : `Unknown (${client.mac.substring(0, 8)})`}
                            </div>
                            <div style={{ fontSize: '9px', color: '#444' }}>
                              Last seen: {new Date(client.last_seen * 1000).toLocaleTimeString()}
                            </div>
                          </div>
                          <div style={{ color: signalColor, fontWeight: 'bold' }}>
                            {client.signal}
                          </div>
                          <div style={{
                            color: client.distance && client.distance < 2 ? '#0f0' :
                                   client.distance && client.distance < 5 ? '#ff0' : '#888',
                            fontSize: '11px',
                            fontWeight: 'bold'
                          }}>
                            {distance}
                          </div>
                          <div>
                            {isConnected ? (
                              <span style={{ color: '#0f0', fontSize: '10px', background: 'rgba(0,255,0,0.1)', padding: '2px 6px', borderRadius: '3px' }}>
                                CONNECTED
                              </span>
                            ) : (
                              <span style={{ color: '#666', fontSize: '10px' }}>
                                PROBING
                              </span>
                            )}
                          </div>
                          <div>
                            {isConnected && (
                              <div style={{ marginBottom: client.probes?.length > 0 ? '4px' : 0 }}>
                                <span style={{ fontSize: '10px', color: '#0f0' }}>
                                  {apSSID ? apSSID : 'Unknown AP'}
                                </span>
                                <span style={{ fontSize: '9px', color: '#444', fontFamily: 'monospace', marginLeft: '6px' }}>
                                  {client.connected_to}
                                </span>
                              </div>
                            )}
                            {client.probes && client.probes.length > 0 ? (
                              <div style={{ fontSize: '10px', color: '#aaa' }}>
                                {client.probes.slice(0, 5).map((ssid, idx) => (
                                  <span key={idx} style={{
                                    display: 'inline-block',
                                    background: '#1a1a1a',
                                    padding: '2px 6px',
                                    marginRight: '4px',
                                    marginBottom: '2px',
                                    borderRadius: '3px',
                                    border: '1px solid #333'
                                  }}>
                                    {ssid}
                                  </span>
                                ))}
                                {client.probes.length > 5 && (
                                  <span style={{ color: '#666', fontSize: '9px' }}>
                                    +{client.probes.length - 5} more
                                  </span>
                                )}
                              </div>
                            ) : (
                              !isConnected && <span style={{ color: '#444', fontSize: '10px' }}>No probes detected</span>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* ========== PROBE ANALYZER SUB-TAB ========== */}
              {clientsSubTab === 'PROBE ANALYZER' && (
                <div style={{ padding: '0' }}>
                  {allProbes.length === 0 ? (
                    <div style={{ padding: '60px 20px', textAlign: 'center' }}>
                      <div style={{ fontSize: '36px', marginBottom: '12px', opacity: 0.3 }}>?</div>
                      <div style={{ color: '#555', fontSize: '13px', marginBottom: '6px' }}>No probe requests captured yet</div>
                      <div style={{ color: '#333', fontSize: '11px' }}>Start scanning to collect client probe data for analysis</div>
                    </div>
                  ) : (
                    <div>
                      {/* Summary bar */}
                      <div style={{
                        display: 'flex', gap: '24px', padding: '14px 20px',
                        borderBottom: '1px solid #222', background: '#080808', fontSize: '11px'
                      }}>
                        <span style={{ color: '#888' }}>Unique SSIDs: <span style={{ color: '#ff0', fontWeight: 'bold' }}>{sortedSSIDs.length}</span></span>
                        <span style={{ color: '#888' }}>Probing Clients: <span style={{ color: '#fff', fontWeight: 'bold' }}>{clientProfiles.length}</span></span>
                        <span style={{ color: '#888' }}>Shared Networks: <span style={{ color: '#0ff', fontWeight: 'bold' }}>{sharedNetworks.length}</span></span>
                        <span style={{ color: '#888' }}>Nearby Matches: <span style={{ color: '#0f0', fontWeight: 'bold' }}>{nearbyMatches.length}</span></span>
                        <span style={{ color: '#888' }}>Vulnerable: <span style={{ color: '#f00', fontWeight: 'bold' }}>{vulnerableClients.length}</span></span>
                      </div>

                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0' }}>
                        {/* TOP LEFT: Most Probed SSIDs */}
                        <div style={{ borderRight: '1px solid #1a1a1a', borderBottom: '1px solid #1a1a1a' }}>
                          <div style={{
                            padding: '12px 16px', borderBottom: '1px solid #1a1a1a',
                            fontSize: '11px', fontWeight: 'bold', color: '#ff0', letterSpacing: '1px'
                          }}>
                            MOST PROBED SSIDs
                            <span style={{ color: '#444', fontWeight: 'normal', marginLeft: '8px' }}>({sortedSSIDs.length})</span>
                          </div>
                          <div style={{ maxHeight: '280px', overflow: 'auto' }}>
                            {sortedSSIDs.slice(0, 20).map(([ssid, count], idx) => {
                              const isNearby = nearbySSIDs.has(ssid);
                              const isVuln = vulnerableNetworks.some(v => ssid.toLowerCase().includes(v.toLowerCase()));
                              const maxCount = sortedSSIDs[0]?.[1] || 1;
                              const barWidth = Math.max(8, (count / maxCount) * 100);
                              return (
                                <div key={ssid} style={{
                                  display: 'flex', alignItems: 'center', gap: '10px',
                                  padding: '8px 16px', borderBottom: '1px solid #0a0a0a',
                                  background: idx % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)'
                                }}>
                                  <div style={{ width: '20px', fontSize: '10px', color: '#333', textAlign: 'right' }}>{idx + 1}</div>
                                  <div style={{ flex: 1, minWidth: 0 }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                      <span style={{
                                        fontSize: '12px', color: isNearby ? '#0f0' : isVuln ? '#f66' : '#ccc',
                                        whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis'
                                      }}>
                                        {ssid}
                                      </span>
                                      {isNearby && <span style={{ fontSize: '8px', background: 'rgba(0,255,0,0.15)', color: '#0f0', padding: '1px 4px', borderRadius: '2px' }}>NEARBY</span>}
                                      {isVuln && <span style={{ fontSize: '8px', background: 'rgba(255,0,0,0.15)', color: '#f66', padding: '1px 4px', borderRadius: '2px' }}>COMMON</span>}
                                    </div>
                                    <div style={{
                                      height: '3px', borderRadius: '2px', marginTop: '4px',
                                      background: '#111', width: '100%'
                                    }}>
                                      <div style={{
                                        height: '100%', borderRadius: '2px',
                                        width: `${barWidth}%`,
                                        background: isNearby ? '#0f0' : isVuln ? '#f44' : '#ff0',
                                        opacity: 0.6
                                      }} />
                                    </div>
                                  </div>
                                  <div style={{ fontSize: '11px', color: '#888', fontWeight: 'bold', minWidth: '30px', textAlign: 'right' }}>
                                    {count} <span style={{ color: '#444', fontSize: '9px', fontWeight: 'normal' }}>client{count > 1 ? 's' : ''}</span>
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        </div>

                        {/* TOP RIGHT: Shared Networks */}
                        <div style={{ borderBottom: '1px solid #1a1a1a' }}>
                          <div style={{
                            padding: '12px 16px', borderBottom: '1px solid #1a1a1a',
                            fontSize: '11px', fontWeight: 'bold', color: '#0ff', letterSpacing: '1px'
                          }}>
                            SHARED NETWORKS
                            <span style={{ color: '#444', fontWeight: 'normal', marginLeft: '8px' }}>
                              ({sharedNetworks.length} SSIDs probed by 2+ clients)
                            </span>
                          </div>
                          <div style={{ maxHeight: '280px', overflow: 'auto' }}>
                            {sharedNetworks.length === 0 ? (
                              <div style={{ padding: '30px 16px', textAlign: 'center', color: '#333', fontSize: '11px' }}>
                                No shared networks detected yet
                              </div>
                            ) : sharedNetworks.slice(0, 15).map(([ssid, macs], idx) => (
                              <div key={ssid} style={{
                                padding: '10px 16px', borderBottom: '1px solid #0a0a0a',
                                background: idx % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)'
                              }}>
                                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                                  <span style={{ fontSize: '12px', color: '#0ff', fontWeight: 'bold' }}>{ssid}</span>
                                  <span style={{
                                    fontSize: '10px', background: 'rgba(0,255,255,0.1)', color: '#0ff',
                                    padding: '2px 8px', borderRadius: '3px'
                                  }}>
                                    {macs.length} clients
                                  </span>
                                </div>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                                  {macs.map((mac, mi) => {
                                    const cl = (wifiClients || []).find(c => c && c.mac === mac);
                                    return (
                                      <span key={mi} style={{
                                        fontSize: '9px', fontFamily: 'monospace', color: '#666',
                                        background: '#111', padding: '2px 6px', borderRadius: '2px'
                                      }}>
                                        {cl && cl.vendor !== 'Unknown' ? cl.vendor.substring(0, 15) : mac.substring(0, 8)}
                                      </span>
                                    );
                                  })}
                                </div>
                                {nearbySSIDs.has(ssid) && (
                                  <div style={{ fontSize: '9px', color: '#0f0', marginTop: '3px' }}>
                                    This network is active nearby — these clients likely came from the same location
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>

                        {/* BOTTOM LEFT: Nearby Matches */}
                        <div style={{ borderRight: '1px solid #1a1a1a' }}>
                          <div style={{
                            padding: '12px 16px', borderBottom: '1px solid #1a1a1a',
                            fontSize: '11px', fontWeight: 'bold', color: '#0f0', letterSpacing: '1px'
                          }}>
                            NEARBY MATCHES
                            <span style={{ color: '#444', fontWeight: 'normal', marginLeft: '8px' }}>
                              (probed SSID = active AP nearby)
                            </span>
                          </div>
                          <div style={{ maxHeight: '280px', overflow: 'auto' }}>
                            {nearbyMatches.length === 0 ? (
                              <div style={{ padding: '30px 16px', textAlign: 'center', color: '#333', fontSize: '11px' }}>
                                No matches between probed SSIDs and nearby APs
                              </div>
                            ) : nearbyMatches.map(({ ssid, clients: macs }, idx) => {
                              const matchedNetwork = networks.find(n => n.ssid === ssid);
                              return (
                                <div key={ssid} style={{
                                  padding: '10px 16px', borderBottom: '1px solid #0a0a0a',
                                  background: idx % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)'
                                }}>
                                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                                    <div>
                                      <span style={{ fontSize: '12px', color: '#0f0', fontWeight: 'bold' }}>{ssid}</span>
                                      {matchedNetwork && (
                                        <span style={{ fontSize: '9px', color: '#444', fontFamily: 'monospace', marginLeft: '8px' }}>
                                          CH {matchedNetwork.channel} | {matchedNetwork.encryption || '?'}
                                        </span>
                                      )}
                                    </div>
                                    <span style={{ fontSize: '10px', color: '#0f0' }}>{macs.length} seeking</span>
                                  </div>
                                  <div style={{ fontSize: '9px', color: '#666', marginTop: '4px' }}>
                                    Clients searching for this network: {macs.map(m => m.substring(9, 17)).join(', ')}
                                  </div>
                                  <div style={{
                                    fontSize: '9px', color: '#ff0', marginTop: '3px', padding: '3px 8px',
                                    background: 'rgba(255,255,0,0.05)', borderRadius: '3px', display: 'inline-block'
                                  }}>
                                    Evil Twin target — these clients will auto-connect to a matching SSID
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        </div>

                        {/* BOTTOM RIGHT: Vulnerable Clients */}
                        <div>
                          <div style={{
                            padding: '12px 16px', borderBottom: '1px solid #1a1a1a',
                            fontSize: '11px', fontWeight: 'bold', color: '#f44', letterSpacing: '1px'
                          }}>
                            VULNERABLE CLIENTS
                            <span style={{ color: '#444', fontWeight: 'normal', marginLeft: '8px' }}>
                              (probing common/default SSIDs)
                            </span>
                          </div>
                          <div style={{ maxHeight: '280px', overflow: 'auto' }}>
                            {vulnerableClients.length === 0 ? (
                              <div style={{ padding: '30px 16px', textAlign: 'center', color: '#333', fontSize: '11px' }}>
                                No vulnerable clients detected
                              </div>
                            ) : vulnerableClients.map((profile, idx) => (
                              <div key={profile.mac} style={{
                                padding: '10px 16px', borderBottom: '1px solid #0a0a0a',
                                background: idx % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)'
                              }}>
                                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                                  <div>
                                    <span style={{ fontSize: '11px', color: '#e0e0e0', fontWeight: 'bold' }}>
                                      {profile.vendor !== 'Unknown' ? profile.vendor : profile.mac}
                                    </span>
                                    <span style={{ fontSize: '9px', color: '#444', fontFamily: 'monospace', marginLeft: '8px' }}>
                                      {profile.mac}
                                    </span>
                                  </div>
                                  <span style={{
                                    fontSize: '9px', background: 'rgba(255,0,0,0.15)', color: '#f66',
                                    padding: '2px 6px', borderRadius: '3px'
                                  }}>
                                    {profile.vulnerableProbes.length} vuln SSID{profile.vulnerableProbes.length > 1 ? 's' : ''}
                                  </span>
                                </div>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '4px' }}>
                                  {profile.vulnerableProbes.map((ssid, si) => (
                                    <span key={si} style={{
                                      fontSize: '10px', background: 'rgba(255,68,68,0.1)', color: '#f66',
                                      padding: '2px 8px', borderRadius: '3px', border: '1px solid rgba(255,68,68,0.2)'
                                    }}>
                                      {ssid}
                                    </span>
                                  ))}
                                </div>
                                <div style={{ fontSize: '9px', color: '#555', marginTop: '3px' }}>
                                  Karma attack target — device will connect to any AP matching these SSIDs
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>

                      {/* CLIENT PROFILES — Full width below the grid */}
                      <div>
                        <div style={{
                          padding: '12px 16px', borderBottom: '1px solid #1a1a1a', borderTop: '1px solid #1a1a1a',
                          fontSize: '11px', fontWeight: 'bold', color: '#c0c0c0', letterSpacing: '1px'
                        }}>
                          CLIENT PROFILES
                          <span style={{ color: '#444', fontWeight: 'normal', marginLeft: '8px' }}>
                            ({clientProfiles.length} clients with probe data)
                          </span>
                        </div>
                        <div style={{ maxHeight: '300px', overflow: 'auto' }}>
                          {clientProfiles.sort((a, b) => b.probes.length - a.probes.length).map((profile, idx) => (
                            <div key={profile.mac} style={{
                              padding: '10px 16px', borderBottom: '1px solid #0a0a0a',
                              display: 'grid', gridTemplateColumns: '200px 1fr',
                              gap: '12px', alignItems: 'start',
                              background: idx % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)'
                            }}>
                              <div>
                                <div style={{ fontSize: '11px', color: '#e0e0e0', fontWeight: 'bold' }}>
                                  {profile.vendor !== 'Unknown' ? profile.vendor : 'Unknown Device'}
                                </div>
                                <div style={{ fontSize: '9px', color: '#555', fontFamily: 'monospace' }}>{profile.mac}</div>
                                <div style={{ display: 'flex', gap: '8px', marginTop: '4px', fontSize: '9px' }}>
                                  <span style={{ color: '#666' }}>RSSI: <span style={{ color: profile.signal > -50 ? '#0f0' : profile.signal > -70 ? '#ff0' : '#f00' }}>{profile.signal || '?'}</span></span>
                                  <span style={{ color: '#666' }}>Probes: <span style={{ color: '#ff0' }}>{profile.probes.length}</span></span>
                                </div>
                                {profile.connected_to && (
                                  <div style={{ fontSize: '9px', color: '#0f0', marginTop: '2px' }}>
                                    Connected to: {bssidToSSID[profile.connected_to] || profile.connected_to}
                                  </div>
                                )}
                                <div style={{ display: 'flex', gap: '4px', marginTop: '4px', flexWrap: 'wrap' }}>
                                  {profile.nearbyMatches.length > 0 && (
                                    <span style={{ fontSize: '8px', background: 'rgba(0,255,0,0.1)', color: '#0f0', padding: '1px 5px', borderRadius: '2px' }}>
                                      {profile.nearbyMatches.length} NEARBY
                                    </span>
                                  )}
                                  {profile.vulnerableProbes.length > 0 && (
                                    <span style={{ fontSize: '8px', background: 'rgba(255,0,0,0.1)', color: '#f66', padding: '1px 5px', borderRadius: '2px' }}>
                                      {profile.vulnerableProbes.length} VULN
                                    </span>
                                  )}
                                </div>
                              </div>
                              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', alignContent: 'start' }}>
                                {profile.probes.map((ssid, si) => {
                                  const isN = nearbySSIDs.has(ssid);
                                  const isV = vulnerableNetworks.some(v => ssid.toLowerCase().includes(v.toLowerCase()));
                                  return (
                                    <span key={si} style={{
                                      display: 'inline-block', fontSize: '10px',
                                      padding: '3px 8px', borderRadius: '3px',
                                      background: isN ? 'rgba(0,255,0,0.08)' : isV ? 'rgba(255,68,68,0.08)' : '#111',
                                      color: isN ? '#0f0' : isV ? '#f66' : '#888',
                                      border: `1px solid ${isN ? 'rgba(0,255,0,0.2)' : isV ? 'rgba(255,68,68,0.2)' : '#222'}`
                                    }}>
                                      {ssid}
                                    </span>
                                  );
                                })}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
            );
          })()}

        </div>

        {/* INSPECTION MODAL */}
        {inspectionResult && (
          <div style={{
            position: 'absolute', top: 0, left: 0, right: 0, bottom: 0,
            background: 'rgba(0,0,0,0.8)', zIndex: 100,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            backdropFilter: 'blur(5px)'
          }}>
            <div className="glass-panel" style={{
              width: '600px',
              maxHeight: '80vh',
              padding: '20px',
              background: '#0a0a0a',
              border: '1px solid var(--color-secondary)',
              overflowY: 'auto'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px', borderBottom: '1px solid #333', paddingBottom: '10px' }}>
                <b style={{ color: 'var(--color-secondary)', letterSpacing: '1px' }}>🔍 BLE DEVICE INSPECTOR</b>
                <button onClick={closeInspector} style={{ background: 'transparent', border: 'none', color: '#666', cursor: 'pointer', fontSize: '14px' }}>✕</button>
              </div>

              <div style={{ marginBottom: '20px' }}>
                <div style={{ fontSize: '10px', color: '#666' }}>TARGET DEVICE</div>
                <div style={{ fontSize: '1.2rem', color: '#fff', fontFamily: 'monospace' }}>{inspectionResult.mac}</div>
              </div>

              {inspectionResult.status === 'pending' && (
                <div style={{ textAlign: 'center', padding: '20px', color: '#aaa', fontSize: '0.9rem' }}>
                  <div className="blink" style={{ marginBottom: '10px', color: 'var(--color-secondary)' }}>● CONNECTING...</div>
                  <div style={{ fontSize: '0.7rem' }}>Using Bleak HCI Interface</div>
                </div>
              )}

              {inspectionResult.status === 'failed' && (
                <div style={{ textAlign: 'center', padding: '20px', color: 'red' }}>
                  CONNECTION FAILED
                  <div style={{ fontSize: '0.7rem', marginTop: '5px', color: '#666' }}>Device may be out of range or rejecting connection.</div>
                </div>
              )}

              {inspectionResult.status === 'connected' && (
                <div>
                  {/* Basic Info Grid */}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px', marginBottom: '20px' }}>
                    <div>
                      <div style={{ fontSize: '10px', color: '#666' }}>MANUFACTURER</div>
                      <div style={{ color: '#eee' }}>{inspectionResult.details.manufacturer || 'N/A'}</div>
                    </div>
                    <div>
                      <div style={{ fontSize: '10px', color: '#666' }}>MODEL</div>
                      <div style={{ color: '#eee' }}>{inspectionResult.details.model || 'N/A'}</div>
                    </div>
                    <div>
                      <div style={{ fontSize: '10px', color: '#666' }}>BATTERY LEVEL</div>
                      <div style={{ color: inspectionResult.details.battery ? 'var(--color-primary)' : '#888', fontWeight: 'bold' }}>
                        {inspectionResult.details.battery ? `${inspectionResult.details.battery}%` : 'N/A'}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: '10px', color: '#666' }}>DEVICE TYPE</div>
                      <div style={{ color: '#eee' }}>{inspectionResult.details.type || 'Unknown'}</div>
                    </div>
                    <div>
                      <div style={{ fontSize: '10px', color: '#666' }}>FIRMWARE</div>
                      <div style={{ color: '#eee', fontSize: '11px' }}>{inspectionResult.details.firmware || 'N/A'}</div>
                    </div>
                    <div>
                      <div style={{ fontSize: '10px', color: '#666' }}>HARDWARE</div>
                      <div style={{ color: '#eee', fontSize: '11px' }}>{inspectionResult.details.hardware || 'N/A'}</div>
                    </div>
                    <div>
                      <div style={{ fontSize: '10px', color: '#666' }}>SERIAL NUMBER</div>
                      <div style={{ color: '#888', fontSize: '10px', fontFamily: 'monospace' }}>{inspectionResult.details.serial || 'N/A'}</div>
                    </div>
                    <div>
                      <div style={{ fontSize: '10px', color: '#666' }}>MTU SIZE</div>
                      <div style={{ color: '#eee', fontSize: '11px' }}>{inspectionResult.details.mtu ? `${inspectionResult.details.mtu} bytes` : 'N/A'}</div>
                    </div>
                  </div>

                  {/* GATT Services Section */}
                  {inspectionResult.details.services && inspectionResult.details.services.length > 0 && (
                    <div style={{ marginTop: '20px', borderTop: '1px solid #333', paddingTop: '15px' }}>
                      <div style={{ fontSize: '12px', color: 'var(--color-secondary)', marginBottom: '10px', fontWeight: 'bold' }}>
                        📡 GATT SERVICES ({inspectionResult.details.service_count})
                      </div>
                      <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
                        {inspectionResult.details.services.map((service, idx) => (
                          <details key={idx} style={{ marginBottom: '10px', background: '#111', padding: '10px', borderRadius: '4px', border: '1px solid #222' }}>
                            <summary style={{ cursor: 'pointer', color: 'var(--color-primary)', fontSize: '11px', fontWeight: 'bold' }}>
                              {service.description}
                            </summary>
                            <div style={{ marginTop: '8px', paddingLeft: '10px' }}>
                              <div style={{ fontSize: '9px', color: '#666', fontFamily: 'monospace', marginBottom: '8px' }}>
                                UUID: {service.uuid}
                              </div>
                              {service.characteristics && service.characteristics.length > 0 && (
                                <div>
                                  <div style={{ fontSize: '10px', color: '#888', marginBottom: '5px' }}>
                                    Characteristics ({service.characteristics.length}):
                                  </div>
                                  {service.characteristics.map((char, cidx) => (
                                    <div key={cidx} style={{ fontSize: '9px', color: '#aaa', marginLeft: '10px', marginBottom: '4px', paddingLeft: '8px', borderLeft: '2px solid #333' }}>
                                      <div style={{ color: '#ddd' }}>{char.description}</div>
                                      <div style={{ color: '#555', fontFamily: 'monospace' }}>{char.uuid}</div>
                                      <div style={{ color: '#666', fontSize: '8px' }}>
                                        Props: {char.properties ? char.properties.join(', ') : 'N/A'}
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          </details>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {inspectionResult.details.error && (
                <div style={{ marginTop: '20px', padding: '10px', background: 'rgba(255,0,0,0.1)', border: '1px solid red', color: 'red', fontSize: '10px', fontFamily: 'monospace' }}>
                  ERROR: {inspectionResult.details.error}
                </div>
              )}
            </div>
          </div>
        )}



        {/* =================================================================================
            TAB: CRACK (Unified)
           ================================================================================= */}
        {activeTab === 'CRACK' && (() => {
          // Compute merged crackable targets
          const crackableTargets = (() => {
            const targets = [];
            const seen = new Set();
            // Add from capturedNetworks (handshake captures)
            capturedNetworks.forEach(net => {
              if (!seen.has(net.bssid)) {
                seen.add(net.bssid);
                targets.push({ ...net, source_type: 'handshake' });
              }
            });
            // Add from pmkidResults
            (pmkidResults || []).forEach(result => {
              if (!seen.has(result.bssid)) {
                seen.add(result.bssid);
                targets.push({
                  bssid: result.bssid,
                  ssid: result.ssid,
                  source_type: 'pmkid',
                  capturedAt: result.time || Date.now()
                });
              } else {
                // Mark existing as also having pmkid
                const existing = targets.find(t => t.bssid === result.bssid);
                if (existing) existing.has_pmkid = true;
              }
            });
            return targets;
          })();

          return (
          <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

            {/* BANNER */}
            <div style={{
              background: 'rgba(255, 196, 0, 0.06)',
              border: '2px solid #ffc400',
              borderRadius: '8px',
              padding: '15px 20px',
              margin: '15px 20px 0',
              flexShrink: 0
            }}>
              <h3 style={{ color: '#ffc400', marginBottom: '5px', fontSize: '14px', fontFamily: 'var(--font-display)', letterSpacing: '2px' }}>
                CRACK MODULE
              </h3>
              <p style={{ color: '#888', fontSize: '10px', marginBottom: '0' }}>
                Unified password cracking via aircrack-ng. Supports handshake captures and PMKID hashes.
              </p>
            </div>

            {/* WORDLIST CONFIG (inline) */}
            <div style={{
              display: 'flex', gap: '10px', alignItems: 'center',
              padding: '10px 20px',
              borderBottom: '1px solid #222',
              position: 'relative',
              flexShrink: 0
            }}>
              <div style={{ color: '#ffc400', fontSize: '10px', fontWeight: 'bold', whiteSpace: 'nowrap', fontFamily: 'var(--font-display)', letterSpacing: '1px' }}>
                WORDLIST:
              </div>
              <input
                type="text"
                value={customWordlist}
                onChange={(e) => { setCustomWordlist(e.target.value); setShowWordlistPicker(false); }}
                placeholder="Default: wordlists/wordlist.txt"
                style={{
                  flex: 1, background: '#111', border: '1px solid #333',
                  color: '#ccc', fontSize: '11px', padding: '6px 10px', borderRadius: '4px',
                  fontFamily: 'var(--font-mono)'
                }}
              />
              <button onClick={() => {
                if (showWordlistPicker) { setShowWordlistPicker(false); return; }
                fetch('http://localhost:8000/crack/wordlists')
                  .then(r => r.json())
                  .then(d => { if (d.wordlists) setAvailableWordlists(d.wordlists); setShowWordlistPicker(true); })
                  .catch(() => {});
              }} className="cyber-button gold"
                style={{ fontSize: '10px', padding: '6px 12px' }}>
                BROWSE
              </button>
              {showWordlistPicker && availableWordlists.length > 0 && (
                <div style={{
                  position: 'absolute', top: '100%', right: '20px', zIndex: 100,
                  background: '#111', border: '1px solid #ffc400', borderRadius: '4px',
                  minWidth: '300px', maxHeight: '200px', overflowY: 'auto',
                  boxShadow: '0 4px 20px rgba(255,196,0,0.2)'
                }}>
                  {availableWordlists.map((wl, i) => (
                    <div key={i} onClick={() => { setCustomWordlist(wl.path); setShowWordlistPicker(false); }}
                      style={{
                        padding: '8px 12px', cursor: 'pointer', borderBottom: '1px solid #222',
                        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                        fontSize: '11px', color: '#ccc', fontFamily: 'var(--font-mono)'
                      }}
                      onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,196,0,0.15)'}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                    >
                      <span style={{ color: '#ffc400' }}>{wl.name}</span>
                      <span style={{ color: '#666', fontSize: '9px' }}>
                        {wl.size > 1048576 ? (wl.size / 1048576).toFixed(1) + ' MB' : (wl.size / 1024).toFixed(1) + ' KB'}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* MAIN CONTENT: Targets + History side-by-side */}
            <div style={{ flex: 1, display: 'flex', gap: '0', overflow: 'hidden', minHeight: crackTarget ? '120px' : 0 }}>

              {/* LEFT: Crackable Targets */}
              <div style={{ flex: 3, borderRight: '1px solid #222', display: 'flex', flexDirection: 'column' }}>
                <div style={{
                  padding: '10px 20px', borderBottom: '1px solid #222',
                  background: '#080808', color: '#ffc400', fontSize: '11px',
                  fontWeight: 'bold', letterSpacing: '1px', fontFamily: 'var(--font-display)'
                }}>
                  CRACKABLE TARGETS ({crackableTargets.length})
                </div>
                <div style={{ flex: 1, overflowY: 'auto' }}>
                  {crackableTargets.length === 0 && (
                    <div style={{ padding: '30px 20px', textAlign: 'center', color: '#444', fontSize: '11px' }}>
                      No captures yet. Capture handshakes or PMKID hashes first.
                    </div>
                  )}
                  {crackableTargets.map((target, i) => (
                    <div key={i} style={{
                      padding: '10px 20px', borderBottom: '1px solid #111',
                      display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                      background: crackTarget?.bssid === target.bssid ? 'rgba(255, 196, 0, 0.05)' : 'transparent'
                    }}>
                      <div style={{ flex: 1 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span style={{ color: '#e0e0e0', fontWeight: 'bold', fontSize: '12px' }}>
                            {target.ssid || 'Hidden'}
                          </span>
                          <span style={{
                            fontSize: '8px', padding: '1px 5px', borderRadius: '3px',
                            background: target.source_type === 'pmkid' ? 'rgba(0, 212, 255, 0.15)' : 'rgba(255, 0, 85, 0.15)',
                            color: target.source_type === 'pmkid' ? '#00d4ff' : '#ff0055',
                            border: `1px solid ${target.source_type === 'pmkid' ? '#00d4ff' : '#ff0055'}`,
                            fontWeight: 'bold'
                          }}>
                            {target.source_type === 'pmkid' ? 'PMKID' : 'HS'}
                          </span>
                          {target.has_pmkid && (
                            <span style={{
                              fontSize: '8px', padding: '1px 5px', borderRadius: '3px',
                              background: 'rgba(0, 212, 255, 0.15)', color: '#00d4ff',
                              border: '1px solid #00d4ff', fontWeight: 'bold'
                            }}>
                              +PMKID
                            </span>
                          )}
                        </div>
                        <div style={{ color: '#555', fontSize: '9px', fontFamily: 'monospace', marginTop: '2px' }}>
                          {target.bssid}
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: '5px' }}>
                        <button
                          onClick={() => startCrack(target, target.has_pmkid ? 'auto' : target.source_type)}
                          className="cyber-button gold"
                          style={{ fontSize: '10px', padding: '4px 12px' }}
                          disabled={cracking}
                        >
                          {crackTarget?.bssid === target.bssid && cracking ? 'CRACKING...' : 'CRACK'}
                        </button>
                        <button
                          onClick={() => {
                            if (!confirm(`Delete ${target.ssid || target.bssid}?`)) return;
                            fetch('http://localhost:8000/crack/targets/delete', {
                              method: 'POST', headers: { 'Content-Type': 'application/json' },
                              body: JSON.stringify({ bssid: target.bssid })
                            }).then(r => r.json()).then(d => {
                              const files = d.deleted?.length ? d.deleted.join(', ') : 'no files';
                              setLogs(p => [...p, `[CRACK] Removed ${target.ssid || target.bssid} (${files})`]);
                            }).catch(() => {});
                            setCapturedNetworks(prev => prev.filter(n => n.bssid !== target.bssid));
                            setPmkidResults(prev => prev.filter(r => r.bssid !== target.bssid));
                          }}
                          className="cyber-button red"
                          style={{ fontSize: '10px', padding: '4px 8px', opacity: 0.6 }}
                          disabled={cracking && crackTarget?.bssid === target.bssid}
                        >
                          X
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* RIGHT: Crack History */}
              <div style={{ flex: 2, display: 'flex', flexDirection: 'column' }}>
                <div style={{
                  padding: '10px 20px', borderBottom: '1px solid #222',
                  background: '#080808', color: '#ffc400', fontSize: '11px',
                  fontWeight: 'bold', letterSpacing: '1px', fontFamily: 'var(--font-display)',
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center'
                }}>
                  <span>CRACK HISTORY ({crackHistory.length})</span>
                  {crackHistory.length > 0 && (
                    <button
                      onClick={() => {
                        setCrackHistory([]);
                        fetch('http://localhost:8000/crack/history/clear', { method: 'POST' }).catch(() => {});
                      }}
                      className="cyber-button"
                      style={{ fontSize: '9px', padding: '2px 8px', opacity: 0.6 }}
                    >
                      CLEAR
                    </button>
                  )}
                </div>
                <div style={{ flex: 1, overflowY: 'auto' }}>
                  {crackHistory.length === 0 && (
                    <div style={{ padding: '30px 20px', textAlign: 'center', color: '#444', fontSize: '11px' }}>
                      No crack attempts yet.
                    </div>
                  )}
                  {[...crackHistory].reverse().map((entry, i) => (
                    <div key={i} style={{
                      padding: '8px 15px', borderBottom: '1px solid #111', fontSize: '11px'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ color: '#e0e0e0', fontWeight: 'bold' }}>{entry.ssid || 'Unknown'}</span>
                        <span style={{
                          color: entry.status === 'success' ? '#0f0' :
                                 entry.status === 'failed' ? '#f44' : '#888',
                          fontWeight: 'bold', fontSize: '10px'
                        }}>
                          {entry.status === 'success' ? 'CRACKED' :
                           entry.status === 'failed' ? 'FAILED' : 'STOPPED'}
                        </span>
                      </div>
                      <div style={{ color: '#444', fontSize: '9px', fontFamily: 'monospace' }}>
                        {entry.bssid}
                      </div>
                      {entry.key && (
                        <div style={{ color: '#0f0', fontSize: '11px', marginTop: '2px', fontFamily: 'monospace' }}>
                          KEY: {entry.key}
                        </div>
                      )}
                      <div style={{ color: '#333', fontSize: '9px', marginTop: '2px' }}>
                        {entry.timestamp ? new Date(entry.timestamp * 1000).toLocaleString() : ''}
                        {entry.source_type ? ` | ${entry.source_type.toUpperCase()}` : ''}
                        {entry.progress && entry.progress.keys_tested > 0 &&
                          ` | ${entry.progress.keys_tested.toLocaleString()} keys @ ${entry.progress.keys_per_sec} k/s`
                        }
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* BOTTOM: Active Crack Console */}
            {crackTarget && (
              <div style={{
                flexShrink: 0, height: '220px', borderTop: '2px solid #ffc400',
                display: 'flex', flexDirection: 'column'
              }}>
                {/* Header */}
                <div style={{
                  padding: '8px 20px', borderBottom: '1px solid #222',
                  background: '#080808', display: 'flex',
                  justifyContent: 'space-between', alignItems: 'center'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <span style={{ color: '#ffc400', fontSize: '11px', letterSpacing: '1px', fontFamily: 'var(--font-display)' }}>
                      CRACKING: {crackTarget.ssid} ({crackTarget.bssid})
                    </span>
                    <span style={{
                      fontSize: '8px', padding: '1px 5px', borderRadius: '3px',
                      background: crackTarget.source_type === 'pmkid' ? 'rgba(0, 212, 255, 0.15)' : 'rgba(255, 0, 85, 0.15)',
                      color: crackTarget.source_type === 'pmkid' ? '#00d4ff' : '#ff0055',
                      border: `1px solid ${crackTarget.source_type === 'pmkid' ? '#00d4ff' : '#ff0055'}`,
                      fontWeight: 'bold'
                    }}>
                      {(crackTarget.source_type || 'auto').toUpperCase()}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span style={{ color: '#888', fontSize: '10px', fontFamily: 'monospace' }}>
                      {crackProgress.elapsed}
                    </span>
                    {cracking ? (
                      <button onClick={stopCrack} className="cyber-button gold"
                        style={{ fontSize: '10px', padding: '4px 8px' }}>
                        STOP
                      </button>
                    ) : (
                      <button onClick={() => { setCrackTarget(null); setCrackLogs([]); }} className="cyber-button"
                        style={{ fontSize: '10px', padding: '4px 8px', opacity: 0.7 }}>
                        CLOSE
                      </button>
                    )}
                  </div>
                </div>

                {/* Progress Bar */}
                {crackProgress.total_keys > 0 && (
                  <div style={{ padding: '5px 20px', background: '#060606' }}>
                    <div style={{
                      display: 'flex', justifyContent: 'space-between',
                      fontSize: '9px', color: '#888', marginBottom: '3px'
                    }}>
                      <span>{crackProgress.keys_tested.toLocaleString()} / {crackProgress.total_keys.toLocaleString()} keys</span>
                      <span>{crackProgress.keys_per_sec} k/s</span>
                      <span>{crackProgress.percentage}%</span>
                    </div>
                    <div style={{
                      height: '4px', background: '#222', borderRadius: '2px', overflow: 'hidden'
                    }}>
                      <div style={{
                        height: '100%', width: `${Math.min(crackProgress.percentage, 100)}%`,
                        background: 'linear-gradient(90deg, #ffc400, #ff8800)',
                        borderRadius: '2px', transition: 'width 0.5s ease'
                      }} />
                    </div>
                  </div>
                )}

                {/* Log Output */}
                <div style={{
                  flex: 1, background: '#000', padding: '10px 20px',
                  fontFamily: 'monospace', fontSize: '11px', color: '#eee', overflowY: 'auto'
                }}>
                  {crackLogs.length === 0 && (
                    <div style={{ color: '#444' }}>Initializing crack process...</div>
                  )}
                  {crackLogs.map((L, i) => (
                    <div key={i} style={{
                      marginBottom: '3px', borderBottom: '1px solid #111', paddingBottom: '2px',
                      color: L.includes('KEY FOUND') || L.includes('SUCCESS') ? '#0f0' :
                             L.includes('FAILED') || L.includes('ERROR') ? '#f44' :
                             L.includes('keys tested') ? '#ffc400' : '#eee'
                    }}>
                      {L}
                    </div>
                  ))}
                  <div ref={crackLogEndRef} />
                </div>
              </div>
            )}
          </div>
          );
        })()}


        {/* =================================================================================
            TAB: SETTINGS
           ================================================================================= */}
        {activeTab === 'SETTINGS' && (
          <div style={{ padding: '40px', height: '100%', overflowY: 'auto' }}>
            <div style={{ maxWidth: '800px', margin: '0 auto' }}>

              {/* Header */}
              <div style={{ marginBottom: '30px' }}>
                <h2 style={{ color: 'var(--color-primary)', margin: 0, fontSize: '1.5rem', letterSpacing: '2px' }}>⚙️ SETTINGS</h2>
                <div style={{ color: '#666', fontSize: '12px', marginTop: '5px' }}>Application Configuration & Preferences</div>
              </div>

              {/* Alert Settings */}
              <div className="glass-panel" style={{ padding: '20px', marginBottom: '20px' }}>
                <div style={{ fontSize: '14px', color: '#0f0', marginBottom: '15px', fontWeight: 'bold', borderBottom: '1px solid #222', paddingBottom: '10px' }}>
                  🔔 ALERT SETTINGS
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                  <div>
                    <div style={{ fontSize: '12px', color: '#fff', marginBottom: '5px' }}>BLE Watch Alerts</div>
                    <div style={{ fontSize: '10px', color: '#666' }}>Get notified when watched devices come into range</div>
                  </div>
                  <label className="switch" style={{ width: '36px', height: '18px' }}>
                    <input type="checkbox" checked={alertsEnabled} onChange={() => setAlertsEnabled(!alertsEnabled)} />
                    <span className="slider green"></span>
                  </label>
                </div>
                <div style={{ fontSize: '10px', color: '#888', marginTop: '10px', padding: '10px', background: '#0a0a0a', borderRadius: '4px', border: '1px solid #222' }}>
                  <b style={{ color: '#0ff' }}>Alert Types:</b><br />
                  • Sound notification<br />
                  • Browser notification (requires permission)<br />
                  • Visual banner on screen
                </div>
              </div>

              {/* System Management */}
              <div className="glass-panel" style={{ padding: '20px', marginBottom: '20px' }}>
                <div style={{ fontSize: '14px', color: '#ff4444', marginBottom: '15px', fontWeight: 'bold', borderBottom: '1px solid #222', paddingBottom: '10px' }}>
                  🛠️ SYSTEM MANAGEMENT
                </div>
                <div style={{ display: 'flex', gap: '10px', flexDirection: 'column' }}>
                  <button
                    onClick={async () => {
                      if (confirm("Reset WiFi Adapter? This kills all background processes.")) {
                        api('/system/wifi_reset');
                      }
                    }}
                    className="cyber-button"
                    style={{ fontSize: '11px', padding: '12px', background: '#111', borderColor: '#555' }}
                  >
                    🔄 RESET WIFI ADAPTER
                  </button>
                  <button
                    onClick={factoryReset}
                    className="cyber-button red"
                    style={{ fontSize: '11px', padding: '12px' }}
                  >
                    ⚠️ FACTORY RESET APPLICATION
                  </button>
                </div>
                <div style={{ fontSize: '10px', color: '#666', marginTop: '10px', padding: '10px', background: '#0a0a0a', borderRadius: '4px', border: '1px solid #222' }}>
                  <b style={{ color: '#ff4444' }}>Warning:</b> Factory reset will delete all captures, logs, settings, and watch lists. The application will restart.
                </div>
              </div>

              {/* Application Info */}
              <div className="glass-panel" style={{ padding: '20px' }}>
                <div style={{ fontSize: '14px', color: '#888', marginBottom: '15px', fontWeight: 'bold', borderBottom: '1px solid #222', paddingBottom: '10px' }}>
                  ℹ️ APPLICATION INFO
                </div>
                <div style={{ fontSize: '11px', color: '#666', lineHeight: '1.8' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '150px 1fr', gap: '8px' }}>
                    <div style={{ color: '#888' }}>Application:</div>
                    <div style={{ color: '#fff', fontWeight: 'bold' }}>ARCH WIFI HUNTER</div>

                    <div style={{ color: '#888' }}>Version:</div>
                    <div style={{ color: '#fff' }}>v2.0.0</div>

                    <div style={{ color: '#888' }}>Backend Status:</div>
                    <div style={{ color: status === 'connected' ? 'var(--color-primary)' : 'red' }}>
                      {status === 'connected' ? '● ONLINE' : '● OFFLINE'}
                    </div>

                    <div style={{ color: '#888' }}>Mode:</div>
                    <div style={{ color: '#fff' }}>{mode}</div>

                    <div style={{ color: '#888' }}>Platform:</div>
                    <div style={{ color: '#fff' }}>Kali Linux (root)</div>

                    <div style={{ color: '#888' }}>Backend:</div>
                    <div style={{ color: '#fff' }}>FastAPI + WebSocket</div>

                    <div style={{ color: '#888' }}>Frontend:</div>
                    <div style={{ color: '#fff' }}>React + Vite</div>
                  </div>
                </div>

                <div style={{ marginTop: '15px', paddingTop: '15px', borderTop: '1px solid #222' }}>
                  <div style={{ fontSize: '11px', color: '#666', marginBottom: '10px', fontWeight: 'bold' }}>MODULES</div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px' }}>
                    {[
                      { name: 'WiFi Scanner', desc: 'Dual-band scan + deauth', color: '#0f0' },
                      { name: 'BLE Radar', desc: '7-attack suite + GATT', color: '#00bfff' },
                      { name: 'Evil Twin', desc: 'Portal + Internet Relay', color: '#ff0055' },
                      { name: 'MITM', desc: 'Sniffer + DNS Spoof', color: '#00ffff' },
                      { name: 'PMKID', desc: 'Clientless hash capture', color: '#f80' },
                      { name: 'WPS', desc: 'Pixie Dust + PIN attack', color: '#ff0' },
                      { name: 'Beacon Flood', desc: 'mdk4 flood attack', color: '#f0f' },
                      { name: 'Crack', desc: 'Handshake + PMKID crack', color: '#ff4444' },
                      { name: 'Hunter Mode', desc: 'Auto target + capture', color: 'var(--color-danger)' },
                      { name: 'Client Tracker', desc: 'Probe + association', color: '#ffa500' },
                    ].map(mod => (
                      <div key={mod.name} style={{
                        padding: '6px 10px', borderRadius: '4px',
                        background: '#0a0a0a', border: '1px solid #1a1a1a',
                        display: 'flex', alignItems: 'center', gap: '8px'
                      }}>
                        <div style={{ width: '4px', height: '20px', borderRadius: '2px', background: mod.color }}/>
                        <div>
                          <div style={{ fontSize: '10px', color: '#ddd', fontWeight: 'bold' }}>{mod.name}</div>
                          <div style={{ fontSize: '8px', color: '#555' }}>{mod.desc}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
