import click
import csv
import json
import logging
import os
from glob import glob

from concurrent.futures import ProcessPoolExecutor, wait, FIRST_COMPLETED
# from pyfiglet import Figlet
from subprocess import Popen, PIPE
from time import time

from dpkt.ip import IP_PROTO_TCP, IP_PROTO_UDP

from flow import Flow
from util import F, NAME


@click.command()
@click.option("-c", "--config", "conf",
              help="",
              default="config.json", show_default=True)
@click.option("-j", "--jobs", "jobs",
              help="Number of jobs to run simultaneously",
              default=1, show_default=True)
def main(conf, jobs):
    """ CIC Flow Meter """

    # Check config file exists
    logging.debug("Config: %s", conf)
    if not os.path.isfile(conf):
        click_fail("The config file does not exist!")

    # Read configuration file
    with open(conf, "r") as f:
        config = json.load(f)

    # Check read dir exists
    logging.debug("Input Directory: %s", config["read-dir"])
    if not os.path.isdir(config["read-dir"]):
        click_fail("The read dir does not exist!")

    # Create wite dir
    os.makedirs(config["write-dir"], exist_ok=True)

    # Check write dir exists
    logging.debug("Output Directory: %s", config["write-dir"])
    if not os.path.isdir(config["write-dir"]):
        click_fail("The write dir does not exist!")

    # Threading
    not_done = []
    with ProcessPoolExecutor(max_workers=jobs) as executor:
        # Read pcap files
        for key, val in config["pcap"].items():
            # Check 'enable' (default: False)
            if "enable" in val and not val["enable"]:
                continue

            if "label" in val:
                for f in glob(os.path.join(config["read-dir"], key)):
                    basename = os.path.basename(os.path.splitext(f)[0])
                    not_done.append(executor.submit(worker,
                                                    f,
                                                    val["label"],
                                                    os.path.join(config["write-dir"], basename + ".csv")))
            else:
                # Check 'index'
                if "index" not in val:
                    val["index"] = {}

                # Check 'tcp/udp index'
                for tl in ["tcp", "udp"]:
                    if tl not in val["index"]:
                        val["index"][tl] = []
                    elif ".txt" in val["index"][tl]:  # Using txt file
                        with open(os.path.join(config["read-dir"], val["index"][tl]), "r") as txt:
                            val["index"][tl] = get_index_from_str(txt.read())
                    else:  # Using string
                        val["index"][tl] = get_index_from_str(val["index"][tl])

                logging.debug("file: %s", key)

                # Submit jobs
                not_done.append(executor.submit(worker,
                                                os.path.join(config["read-dir"], key),
                                                val["index"],
                                                os.path.join(config["write-dir"], val["output"])))

        while not_done:
            done, not_done = wait(not_done, return_when=FIRST_COMPLETED)
            # logging.debug("time: %s", done.pop().result())


def click_fail(msg):
    with click.Context(main) as context:
        context.fail(msg)


def get_index_from_str(string):
    return sum(((list(range(*[int(b) + c
                              for c, b in enumerate(a.split('-'))]))
                 if '-' in a else [int(a)]) for a in string.split(',')), [])


def worker(src, index, dst):
    logging.debug("file: %s", src)

    # Count time
    t = time()

    # Tshark
    tshark = Popen(
        ["tshark", "-n",
         "-r", src,
         "-Y", "(eth.type == 0x0800) and (tcp or udp) and (not icmp)", # sll.etype, eth.type
         "-o", "ip.decode_tos_as_diffserv:FALSE",
         "-o", "ip.summary_in_tree:FALSE",
         "-o", "ip.tso_support:FALSE",
         "-o", "ip.use_geoip:FALSE",
         "-o", "tcp.summary_in_tree:FALSE",
         "-o", "tcp.track_bytes_in_flight:FALSE",
         "-o", "tcp.relative_sequence_numbers:FALSE",
         "-o", "tcp.dissect_experimental_options_with_magic:FALSE",
         "-o", "udp.summary_in_tree:FALSE",
         "-o", "http.decompress_body:FALSE",
         "-T", "fields",
         "-E", "separator=,",
         "-e", "frame.number",
         "-e", "frame.time_relative",
         "-e", "ip.src",
         "-e", "ip.dst",
         "-e", "tcp.srcport",
         "-e", "udp.srcport",
         "-e", "tcp.dstport",
         "-e", "udp.dstport",
         "-e", "ip.proto",
         "-e", "_ws.col.Protocol",
         "-e", "tcp.stream",
         "-e", "tcp.len",
         "-e", "tcp.hdr_len",
         "-e", "tcp.flags",
         "-e", "tcp.window_size_value",
         "-e", "udp.stream",
         "-e", "udp.length",
         "-e", "tcp.analysis.duplicate_ack_num",
         "-e", "tcp.analysis.initial_rtt",
         "-e", "tcp.analysis.reused_ports",
         "-e", "tcp.analysis.retransmission",
         "-e", "tcp.analysis.fast_retransmission",
         "-e", "tcp.analysis.spurious_retransmission",
         "-e", "tcp.analysis.window_full",
         "-e", "tcp.analysis.window_update",
         ], stdout=PIPE, bufsize=65536)

    # Flow variable
    flows = {
        IP_PROTO_TCP: {},
        IP_PROTO_UDP: {}
    }

    data = [NAME]
    j = 0  # Count timeout
    k = 0  # Count consecutive poll()

    while True:
        line = tshark.stdout.readline().rstrip(b"\n").decode().split(",")
        if len(line) != len(F):
            if tshark.poll() == 0:
                break
            else:
                k += 1
                if k == 200:
                    logging.debug("tshark.poll() != 0 %s", src)
                    # logging.debug("The capture file appears to be damaged or corrupt")
                    # logging.debug("The capture file appears to have been cut short in the middle of a packet")
                    break
                continue

        # poll() reset
        k = 0

        # Process line
        p = int(line[F.IP_PRO])
        q = "TCP" if p == IP_PROTO_TCP else "UDP"
        stream = int(line[F[f"{q}_STREAM"]])
        ts = float(line[F.TIME_RELATIVE])

        if stream not in flows[p]:  # First Packet in Flow
            flows[p][stream] = Flow(line[F.NO], ts,
                                    line[F.SRC], line[F[f"{q}_SRCPORT"]],
                                    line[F.DST], line[F[f"{q}_DSTPORT"]],
                                    p, line[F.APP_PRO],
                                    stream, os.path.basename(os.path.splitext(src)[0]), line)
        elif ts - flows[p][stream].time > 600:  # timeout
            # Generate data sample
            if isinstance(index, int):
                data.append(flows[p][stream].to_list(index))
            elif stream in index["tcp" if p == IP_PROTO_TCP else "udp"]:  # ATTACK
                data.append(flows[p][stream].to_list(1))
            else:  # BENIGN
                data.append(flows[p][stream].to_list(0))

            # Create new flow
            flows[p][stream] = Flow(line[F.NO], ts,
                                    line[F.SRC], line[F[f"{q}_SRCPORT"]],
                                    line[F.DST], line[F[f"{q}_DSTPORT"]],
                                    p, line[F.APP_PRO],
                                    stream, os.path.basename(os.path.splitext(src)[0]), line)
            j += 1
        else:  # Update Flow statistics
            flows[p][stream].upd_flow(ts, q, line)

    # print("{} prepare to write".format(src))
    # print(len(flows[IP_PROTO_TCP]), len(flows[IP_PROTO_UDP]), j)

    for proto in [IP_PROTO_TCP, IP_PROTO_UDP]:
        p = "tcp" if proto == IP_PROTO_TCP else "udp"
        for idx, flow in flows[proto].items():
            if isinstance(index, int):
                data.append(flow.to_list(index))
            elif idx in index[p]:  # ATTACK
                data.append(flow.to_list(1))
            else:  # BENIGN
                data.append(flow.to_list(0))

    if len(data) - 1 > 0:
        # csv_id = 1
        # while os.path.exists(f"{dst}{csv_id}"):
        #     csv_id += 1
        # {csv_id}
        with open(f"{dst}", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerows(data)
            print("{}: {} lines".format(src, len(data) - 1))
    else:
        print("len(data) - 1 <= 0")
    return (time() - t) / 60.0


if __name__ == "__main__":
    # Figlet
    # f = Figlet(font="standard")
    # print(f.renderText("CICFlowMeter"))

    # logging
    logging.getLogger().setLevel(logging.DEBUG)

    # Click CLI
    main()
