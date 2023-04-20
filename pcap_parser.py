import os
import sys
from collections import Counter
from time import time

import pyshark
from rich.console import Console
from rich.status import Status
from rich.table import Table


def pcap_info(pcap: str):
    packets = pyshark.FileCapture(pcap)
    file_stats = os.stat(pcap)
    size = file_stats.st_size
    status = Status(
        f"Parsing {pcap} ({size} bytes) - Please be patient...", spinner="shark"
    )
    status.start()
    start_time = time()
    highest_layer = [p.highest_layer for p in packets]
    finish_time = time()
    status.stop()
    packet_count = Counter(sorted(highest_layer))

    table = Table()
    table.show_lines = True
    table.add_column("PROTOCOL", justify="left", style="blue")
    table.add_column("PACKET COUNT", justify="left", style="blue")

    for proto, count in packet_count.items():
        table.add_row(proto, str(count))

    console = Console(record=True)
    console.print(table)

    print(f"Total packets: {len(highest_layer)}")
    print(f"File size: {size} bytes")
    print(f"Elapsed time: {finish_time - start_time:.2f} seconds")


def main():
    pcap_file = input("Enter the name of a PCAP file to parse: ")
    try:
        pcap_info(pcap_file)
    except FileNotFoundError:
        print(f"'{pcap_file}' was not found. Exiting with Code 1...")
        sys.exit(1)


if __name__ == "__main__":
    main()
