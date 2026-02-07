#!/usr/bin/env bash
set -euo pipefail

echo "[0] Install port-knocking rules on HOST (Option C: iptables recent)"
sudo python3 port_knocking/knock_server.py --install

echo "[1] BEFORE KNOCK: webapp -> secret_ssh:2222 should be BLOCKED"
docker exec -it 2_network_webapp sh -lc "python3 - <<'PY'
import socket
ip, port = '172.20.0.20', 2222
s=socket.socket(); s.settimeout(2)
try:
  s.connect((ip,port)); print('BEFORE KNOCK: UNEXPECTED CONNECT')
except Exception as e:
  print('BEFORE KNOCK: EXPECTED BLOCK ->', e)
finally:
  s.close()
PY"

echo "[2] Send knock sequence from webapp -> port_knocking host (172.20.0.40)"
docker exec -it 2_network_webapp sh -lc "python3 - <<'PY'
import socket, time
target='172.20.0.40'
seq=[1234,5678,9012]
for p in seq:
  s=socket.socket(); s.settimeout(1)
  try: s.connect((target,p))
  except Exception: pass
  finally: s.close()
  time.sleep(0.3)
print('KNOCKS SENT:', seq)
PY"

echo "[3] AFTER KNOCK: webapp -> secret_ssh:2222 should CONNECT (for ~30s)"
docker exec -it 2_network_webapp sh -lc "python3 - <<'PY'
import socket
ip, port = '172.20.0.20', 2222
s=socket.socket(); s.settimeout(2)
try:
  s.connect((ip,port)); print('AFTER KNOCK: CONNECTED (expected)')
except Exception as e:
  print('AFTER KNOCK: STILL BLOCKED (unexpected) ->', e)
finally:
  s.close()
PY"

echo "[4] Wait 35s for TTL to expire"
sleep 35

echo "[5] AFTER TTL: should be BLOCKED again"
docker exec -it 2_network_webapp sh -lc "python3 - <<'PY'
import socket
ip, port = '172.20.0.20', 2222
s=socket.socket(); s.settimeout(2)
try:
  s.connect((ip,port)); print('AFTER TTL: UNEXPECTED CONNECT')
except Exception as e:
  print('AFTER TTL: EXPECTED BLOCK ->', e)
finally:
  s.close()
PY"
