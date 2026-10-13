"""
baseline_poll.py

MSc Cybersecurity Dissertation
Evaluating Machine Learning Approaches for Anomaly Detection in OT Network Traffic
Dewanshi Manoj Agarkar

------------------------------------------------------------------------------
PURPOSE
------------------------------------------------------------------------------
Generates baseline (normal, non-attack) Modbus TCP traffic against the
OpenPLC testbed, captured separately by tshark into baseline_normal.csv.
This traffic is used for two purposes: measuring the rule-based detector's
false-positive rate on genuinely normal traffic, and training the
Isolation Forest model on what normal traffic looks like statistically
(see Section 6.2 and 6.5).

Runs for DURATION_SECONDS at INTERVAL_SECONDS between reads, issuing a
Modbus read request each cycle.

------------------------------------------------------------------------------
USAGE
------------------------------------------------------------------------------
Run this BEFORE any attack scripts, with tshark capturing on the loopback
interface, so the baseline is never contaminated by attack traffic:

    python3 attacks/baseline_poll.py

------------------------------------------------------------------------------
"""

from pymodbus.client import ModbusTcpClient
import time

PLC_IP = "127.0.0.1"
PLC_PORT = 502
DURATION_SECONDS = 600  # 10 minutes
INTERVAL_SECONDS = 2


def main():
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
    if not client.connect():
        print(f"Failed to connect to PLC at {PLC_IP}:{PLC_PORT}")
        return

    start = time.time()
    count = 0
    while time.time() - start < DURATION_SECONDS:
        client.read_holding_registers(0, count=1)
        count += 1
        time.sleep(INTERVAL_SECONDS)

    client.close()
    print(f"Done. Sent {count} read requests over {DURATION_SECONDS} seconds.")


if __name__ == "__main__":
    main()
