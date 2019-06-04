import re
import os
import logging
from datetime import datetime
from dnslib import DNSLabel, QTYPE, RD, RR
from dnslib import A, AAAA, CNAME, MX, NS, SOA, TXT
from dnslib.server import DNSServer, DNSHandler
from localstack import config
from localstack.utils.common import in_docker, run, is_root, load_file

LOG = logging.getLogger(__name__)

EPOCH = datetime(1970, 1, 1)
SERIAL = int((datetime.utcnow() - EPOCH).total_seconds())

RCODE_REFUSED = 5

SERVERS = []

DNS_PORT = 53

TYPE_LOOKUP = {
    A: QTYPE.A,
    AAAA: QTYPE.AAAA,
    CNAME: QTYPE.CNAME,
    MX: QTYPE.MX,
    NS: QTYPE.NS,
    SOA: QTYPE.SOA,
    TXT: QTYPE.TXT,
}


class Record(object):

    def __init__(self, rdata_type, *args, **kwargs):
        rtype = kwargs.get('rtype')
        rname = kwargs.get('rname')
        ttl = kwargs.get('ttl')

        if isinstance(rdata_type, RD):
            # actually an instance, not a type
            self._rtype = TYPE_LOOKUP[rdata_type.__class__]
            rdata = rdata_type
        else:
            self._rtype = TYPE_LOOKUP[rdata_type]
            if rdata_type == SOA and len(args) == 2:
                # add sensible times to SOA
                args += ((
                    SERIAL,  # serial number
                    60 * 60 * 1,  # refresh
                    60 * 60 * 3,  # retry
                    60 * 60 * 24,  # expire
                    60 * 60 * 1,  # minimum
                ),)
            rdata = rdata_type(*args)

        if rtype:
            self._rtype = rtype
        self._rname = rname
        self.kwargs = dict(
            rdata=rdata,
            ttl=self.sensible_ttl() if ttl is None else ttl,
            **kwargs
        )

    def try_rr(self, q):
        if q.qtype == QTYPE.ANY or q.qtype == self._rtype:
            return self.as_rr(q.qname)

    def as_rr(self, alt_rname):
        return RR(rname=self._rname or alt_rname, rtype=self._rtype, **self.kwargs)

    def sensible_ttl(self):
        if self._rtype in (QTYPE.NS, QTYPE.SOA):
            return 60 * 60 * 24
        else:
            return 300

    @property
    def is_soa(self):
        return self._rtype == QTYPE.SOA

    def __str__(self):
        return '{} {}'.format(QTYPE[self._rtype], self.kwargs)


class NonLoggingHandler(DNSHandler, object):
    """ subclass of DNSHandler that avoids logging to stdout on error """

    def __init__(self, *args, **kwargs):
        super(NonLoggingHandler, self).__init__(*args, **kwargs)

    def handle(self, *args, **kwargs):
        try:
            return super(NonLoggingHandler, self).handle(*args, **kwargs)
        except Exception:
            pass


class NoopLogger(object):

    def __init__(self, *args, **kwargs):
        pass

    def log_pass(self, *args, **kwargs):
        pass

    def log_prefix(self, *args, **kwargs):
        pass

    def log_recv(self, *args, **kwargs):
        pass

    def log_send(self, *args, **kwargs):
        pass

    def log_request(self, *args, **kwargs):
        pass

    def log_reply(self, *args, **kwargs):
        pass

    def log_truncated(self, *args, **kwargs):
        pass

    def log_error(self, *args, **kwargs):
        pass

    def log_data(self, *args, **kwargs):
        pass


ZONES = {
    '.*.amazonaws.com': [
        Record(A, '127.0.0.1'),
        Record(CNAME, 'localhost')
    ],
    'abc.def': [
        Record(A, '127.0.0.1'),
        Record(CNAME, 'localhost')
    ]
}


class Resolver:
    def __init__(self):
        self.zones = {DNSLabel(k): v for k, v in ZONES.items()}

    def resolve(self, request, handler):
        reply = request.reply()
        zone = self.zones.get(request.q.qname)
        if zone is not None:
            for zone_records in zone:
                rr = zone_records.try_rr(request.q)
                rr and reply.add_answer(rr)
        else:
            # no direct zone so look for an SOA record for a higher level zone
            for zone_label, zone_records in self.zones.items():
                # try regex match
                if re.match(str(zone_label), str(request.q.qname)):
                    for record in zone_records:
                        rr = record.try_rr(request.q)
                        rr and reply.add_answer(rr)
                # try suffix match
                elif request.q.qname.matchSuffix(zone_label):
                    try:
                        soa_record = next(r for r in zone_records if r.is_soa)
                    except StopIteration:
                        continue
                    else:
                        reply.add_answer(soa_record.as_rr(zone_label))
                        break

        if not reply.rr:
            # setting this return code will cause commands like 'host' to try the next nameserver
            # reply.header.set_rcode(RCODE.SERVFAIL)
            return None
        return reply


def can_use_sudo():
    try:
        run('echo | sudo -S echo', print_error=False)
        return True
    except Exception:
        return False


def ensure_can_use_sudo():
    if not is_root() and not can_use_sudo():
        print('Please enter your sudo password (required to configure local network):')
        run('sudo echo', stdin=True)


def setup_network_configuration():
    # set up interfaces
    create_network_interfaces()

    # add entry to /etc/resolv.conf
    if config.DNS_ADDRESS != '0.0.0.0':
        resolv_conf = '/etc/resolv.conf'
        if os.path.exists(resolv_conf):
            content = load_file(resolv_conf)

            comment = '# The following line is required by LocalStack'
            line = 'nameserver %s' % config.DNS_ADDRESS
            if line not in content:

                sudo_cmd = '' if is_root() else 'sudo'
                ensure_can_use_sudo()

                for new_line in ('', line, comment):
                    # Surprisingly hard to find a reliable cross-platform shell
                    # solution to prepend text to a file, hence we use python here.
                    run(('%s python -c "import sys; f=open(sys.argv[1]).read();' +
                        ' open(sys.argv[1], \'w\').write(\'%s\\n\' + f)" %s') %
                        (sudo_cmd, new_line, resolv_conf))


def create_network_interfaces():

    if in_docker():
        config.DNS_ADDRESS = '0.0.0.0'
        return

    try:
        run('ifconfig | grep {addr}'.format(addr=config.DNS_ADDRESS), print_error=False)
        # already exists -> nothing to do
        return
    except Exception:
        pass

    sudo_cmd = '' if is_root() else 'sudo'
    ensure_can_use_sudo()

    # create network interface alias
    try:
        # try for Mac OS
        run('{sudo_cmd} ifconfig en0 alias {addr}'.
            format(sudo_cmd=sudo_cmd, addr=config.DNS_ADDRESS), print_error=False)
    except Exception:
        try:
            # try for Linux
            run('{sudo_cmd} ifconfig eth0:0 {addr} netmask 255.255.255.0 up'.
                format(sudo_cmd=sudo_cmd, addr=config.DNS_ADDRESS), print_error=False)
        except Exception:
            # fall back to localhost as bind address
            config.DNS_ADDRESS = '0.0.0.0'


def start_servers():
    global SERVERS

    try:
        LOG.info('Starting DNS servers (tcp/udp port %s on %s)...' % (DNS_PORT, config.DNS_ADDRESS))
        resolver = Resolver()
        nlh = NonLoggingHandler
        SERVERS = [
            DNSServer(resolver, handler=nlh, logger=NoopLogger(),
                port=DNS_PORT, address=config.DNS_ADDRESS, tcp=False),
            DNSServer(resolver, handler=nlh, logger=NoopLogger(),
                port=DNS_PORT, address=config.DNS_ADDRESS, tcp=True)
        ]
        for s in SERVERS:
            s.start_thread()
    except Exception as e:
        LOG.warning('Unable to start DNS server: %s' % e)


def stop_servers():
    # TODO: delete alias:
    # ifconfig en0 -alias 192.168.55.55
    for s in SERVERS:
        s.stop()
