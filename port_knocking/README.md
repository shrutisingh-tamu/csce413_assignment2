# Port Knocking Implementation

## Implementation Approach
This implementation uses **iptables `recent` module** (Option C) for stateless port knocking.

## How It Works
1. All traffic to `172.20.0.20:2222` (SSH) is blocked by default
2. Client must knock on ports `1234 → 5678 → 9012` in sequence
3. Each knock must occur within 10 seconds of the previous one
4. After completing the sequence, the client's IP is granted access for 30 seconds
5. Uses iptables `recent` module to track knock state per source IP

## Architecture
```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Client    │ Knock → │ Knock Server │ Rules → │  SSH Server │
│ 172.20.0.X  │  Ports  │ 172.20.0.40  │         │172.20.0.20  │
└─────────────┘  1234   └──────────────┘         └─────────────┘
                 5678         iptables                 :2222
                 9012         recent
```

## Files
- `knock_setup.sh` - Sets up iptables rules for port knocking
- `knock_client.sh` - Client script to perform knock sequence
- `demo.sh` - End-to-end demonstration
- `Dockerfile` - Container setup (if needed)

## Usage

### Setup (run once)
```bash
chmod +x knock_setup.sh knock_client.sh demo.sh
sudo ./knock_setup.sh
```

### Perform knock
```bash
./knock_client.sh 172.20.0.40
```

### Run demo
```bash
./demo.sh
```

### Manual knock (for testing)
```bash
nc 172.20.0.40 1234 -w 1
nc 172.20.0.40 5678 -w 1
nc 172.20.0.40 9012 -w 1
ssh sshuser@172.20.0.20 -p 2222
```

## Security Features
- **Stateless**: Uses kernel's `recent` module, no daemon needed
- **IP-specific**: Only the knocking client gets access
- **Time-limited**: Access expires after 30 seconds
- **Sequence timeout**: Must complete within 10-second windows

## Advantages of iptables `recent` Approach
- No separate daemon process required
- Kernel-level tracking (very fast)
- Minimal resource usage
- Survives process crashes
- Works at network layer

## Limitations
- Knock sequence visible in network traffic
- No encryption of knock sequence
- Vulnerable to replay attacks
- Should be combined with strong SSH authentication
- Requires root/privileged access to configure

## Testing
Tested scenarios:
1. SSH blocked before knocking
2. Knock sequence 1234→5678→9012
3. SSH accessible after successful knock
4. Access expires after 30 seconds
5. Wrong sequence doesn't grant access
6. Timeout between knocks resets sequence

## Future Improvements
- Add encryption to knock packets
- Implement one-time knock sequences
- Add logging of knock attempts
- Integrate with intrusion detection
