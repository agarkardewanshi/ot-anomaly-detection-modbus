# Data

Put the tshark CSV exports here. Every file uses the same six columns:

```
frame.time_epoch, ip.src, ip.dst, modbus.func_code, modbus.reference_num, modbus.regval_uint16
```

| File | Contents | Rows |
|---|---|---|
| `baseline_normal.csv` | Normal polling traffic from `baseline_poll.py`, no attacks | 1,200 |
| `attack1_writes.csv` | False data injection capture | 20 |
| `replay_writes.csv` | Replay attack capture | 20 |
| `protocol_abuse_writes.csv` | Protocol abuse capture | 4 |

Each request and its response are separate rows, so 10 attack writes produce 20 rows.

## Capturing your own

With OpenPLC running, start tshark on the loopback interface, run one script, then stop the capture:

```bash
sudo tshark -i lo -f "tcp port 502" -w /tmp/capture.pcap
python3 attacks/false_data_injection.py

tshark -r /tmp/capture.pcap -Y modbus -T fields -E header=y -E separator=, \
  -e frame.time_epoch -e ip.src -e ip.dst \
  -e modbus.func_code -e modbus.reference_num -e modbus.regval_uint16 \
  > data/attack1_writes.csv
```

Capture the baseline first, before any attack has been run.
