#!/usr/bin/env python3

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from base64 import b64decode
import logging
import logging.handlers
from scapy.all import sniff
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import TCP, IP
from scapy.packet import Packet
from sys import stdout

log = logging.getLogger('auth_sniffer')


def main():
    args = parse_arguments()
    # setup_logger(args['log_level'])
    # sniff(iface=args['interface'], filter='tcp port 80', prn=packet_callback, store=0, count=0)
    setup_logger('DEBUG')
    sniff(iface='lxdbr0', filter='tcp port 80', prn=packet_callback, store=0, count=0)


def parse_arguments():
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter, description='Capture HTTP Authorization Header field')
    parser.add_argument('-l', '--log_level', help='minimum Log level',
                        type=str,
                        required=False,
                        default='INFO',
                        dest='log_level')
    parser.add_argument('-i', '--interface', help='target capture interface',
                        type=str,
                        required=True,
                        dest='interface')
    arguments = parser.parse_args()
    settings = {
        'log_level': arguments.log_level,
        'interface': arguments.interface
    }
    return settings


def setup_logger(lvl='INFO'):
    if lvl == 'DEBUG':
        log.addHandler(logging.StreamHandler(stdout))

    log.addHandler(logging.handlers.SysLogHandler(address='/dev/log'))

    logging.basicConfig(format='%(asctime)-15s %(name)s %(levelname)-8s %(message)s')
    log.setLevel(getattr(logging, lvl))


def packet_callback(packet: Packet):
    if packet[TCP].dport == 80 and packet.haslayer(HTTPRequest) and packet[HTTPRequest].Authorization:
        # check request path ??
        auth_field = packet[HTTPRequest].Authorization.decode()
        credentials = b64decode(auth_field.split(' ')[-1]).decode('utf-8')
        log.info('authentication attempt: HOST: {} CREDENTIALS: {}'.format(packet[IP].src, credentials))
    elif packet[TCP].sport == 80 and packet.haslayer(HTTPResponse) and packet[HTTPResponse].Status_Code.decode(
            'utf-8') in ['304', '200']:
        status_code = packet[HTTPResponse].Status_Code.decode('utf-8')
        log.info('credentials accepted for: HOST: {} STATUS_CODE: {}'.format(packet[IP].dst, status_code))


if __name__ == '__main__':
    main()
