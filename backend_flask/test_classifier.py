import sys
sys.path.insert(0, '/Users/ziauddin/Documents/GitHub/CyberMind/backend_flask')

from app.services.rf_classifier import RFClassifier
clf = RFClassifier.get()
print("Model loaded/trained OK\n")

import random
rng = random.Random(1)

# Build realistic macOS background traffic
mac_traffic = []
for i in range(400):
    roll = rng.random()
    if roll < 0.3:
        mac_traffic.append({'pkt_len': rng.randint(50,80), 'src_port': rng.randint(1024,65535),
            'dst_port': 53, 'protocol': 17, 'tcp_flags': 0, 'ttl': 64,
            'inter_arrival_ms': rng.uniform(5, 300), 'payload_len': rng.randint(20,60)})
    elif roll < 0.5:
        mac_traffic.append({'pkt_len': rng.randint(60,120), 'src_port': 5353,
            'dst_port': 5353, 'protocol': 17, 'tcp_flags': 0, 'ttl': 255,
            'inter_arrival_ms': rng.uniform(1000, 10000), 'payload_len': rng.randint(30,80)})
    elif roll < 0.7:
        mac_traffic.append({'pkt_len': rng.randint(60,1400), 'src_port': rng.randint(1024,65535),
            'dst_port': 443, 'protocol': 6, 'tcp_flags': 0x10, 'ttl': 64,
            'inter_arrival_ms': rng.uniform(20, 500), 'payload_len': rng.randint(0, 1300)})
    elif roll < 0.85:
        mac_traffic.append({'pkt_len': rng.randint(100,800), 'src_port': rng.randint(1024,65535),
            'dst_port': 80, 'protocol': 6, 'tcp_flags': 0x18, 'ttl': 64,
            'inter_arrival_ms': rng.uniform(50, 2000), 'payload_len': rng.randint(50,700)})
    else:
        mac_traffic.append({'pkt_len': 90, 'src_port': 123, 'dst_port': 123,
            'protocol': 17, 'tcp_flags': 0, 'ttl': 64,
            'inter_arrival_ms': rng.uniform(30000, 60000), 'payload_len': 48})

nmap_pkts = [{'pkt_len': 44, 'src_port': 40000+i, 'dst_port': i+1,
              'protocol': 6, 'tcp_flags': 0x02, 'ttl': 52,
              'inter_arrival_ms': 20.0, 'payload_len': 0} for i in range(100)]

flood_pkts = [{'pkt_len': 54, 'src_port': i%65534+1, 'dst_port': 8080,
               'protocol': 6, 'tcp_flags': 0x02, 'ttl': 40,
               'inter_arrival_ms': 0.3, 'payload_len': 0} for i in range(150)]

tests = [
    ("A: macOS idle (NO attack)", mac_traffic, 'safe'),
    ("B: 300 safe + 100 nmap SYN", mac_traffic[:300] + nmap_pkts, 'port_scan'),
    ("C: 200 safe + 150 hping3 flood", mac_traffic[:200] + flood_pkts, ('ddos','port_scan')),
    ("D: 100 nmap SYN only", nmap_pkts, 'port_scan'),
]

passed = 0
for name, pkts, expected in tests:
    r = clf.predict(pkts)
    ok = r['label'] == expected if isinstance(expected, str) else r['label'] in expected
    status = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    print(f"TEST {name}")
    print(f"  -> {r['label'].upper()} | conf={r['confidence']} | threat={r['threat_detected']}")
    print(f"  breakdown: safe={r['breakdown'].get('safe',0)}% port_scan={r['breakdown'].get('port_scan',0)}% ddos={r['breakdown'].get('ddos',0)}%")
    print(f"  [{status}]\n")

print(f"RESULT: {passed}/{len(tests)} passed", "ALL GOOD - Demo ready!" if passed == len(tests) else "NEEDS FIX")
