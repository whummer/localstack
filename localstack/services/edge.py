import os
import sys
import json
import logging
from requests.models import Response
from localstack import config
from localstack.utils.common import run, is_root, TMP_THREADS
from localstack.utils.common import safe_requests as requests
from localstack.services.generic_proxy import ProxyListener, GenericProxy
from localstack.services import dns_server

# Header to indicate that the process should kill itself. This is required because if
# this process is started as root, then we cannot kill it from the other non-root process
HEADER_KILL_SIGNAL = 'x-localstack-kill'


class ProxyListenerEdge(ProxyListener):

    def forward_request(self, method, path, data, headers):
        # print(method, path)
        # print(headers)

        # kill the process if we receive this header
        headers.get(HEADER_KILL_SIGNAL) and os._exit(0)

        target = headers.get('x-amz-target', '')
        host = headers.get('host', '')

        port = None
        if target.startswith('Kinesis_20131202') and host.startswith('kinesis.'):
            port = config.PORT_KINESIS
        elif path.startswith('/2015-03-31/') and host.startswith('lambda.'):
            port = config.PORT_LAMBDA
        elif host.startswith('s3'):
            port = config.PORT_S3
        elif host.startswith('queue.'):
            port = config.PORT_SQS
        elif host.startswith('sns.'):
            port = config.PORT_SNS
        elif host.startswith('apigateway.'):
            port = config.PORT_APIGATEWAY
        elif host.startswith('cloudformation.'):
            port = config.PORT_CLOUDFORMATION
        elif host.startswith('firehose.'):
            port = config.PORT_FIREHOSE
        elif host.startswith('dynamodb.'):
            port = config.PORT_DYNAMODB
        elif host.startswith('streams.dynamodb.'):
            port = config.PORT_DYNAMODBSTREAMS

        if not port:
            response = Response()
            response.status_code = 404
            response._content = '{}'
            return response

        use_ssl = config.USE_SSL

        url = 'http%s://%s:%s%s' % ('s' if use_ssl else '', config.HOSTNAME, port, path)
        function = getattr(requests, method.lower())
        if isinstance(data, dict):
            data = json.dumps(data)

        response = function(url, data=data, headers=headers)
        return response


def do_start_dns():
    # start local DNS servers
    dns_server.start_servers()


def do_start_edge(port, use_ssl, asynchronous=False):
    # start local DNS server
    do_start_dns()
    # get port and start Edge
    print('Starting edge router (http%s port %s)...' % ('s' if use_ssl else '', port))
    proxy = GenericProxy(port, ssl=use_ssl, update_listener=ProxyListenerEdge())
    proxy.start()
    if not asynchronous:
        proxy.join()
    return proxy


def start_edge(port=None, asynchronous=False):
    if not port:
        port = config.PORT_EDGE
    use_ssl = True  # config.USE_SSL
    if port > 1024 or is_root():
        return do_start_edge(port, use_ssl, asynchronous=asynchronous)
    if not port:
        port = config.PORT_EDGE
    root_path = os.path.realpath(os.path.join(os.path.dirname(__file__), '..', '..'))
    # make sure we can run sudo commands
    dns_server.ensure_can_use_sudo()
    sudo_cmd = (is_root() and ' ') or 'sudo '

    class Terminator(object):

        def stop(self, quiet=True):
            try:
                url = 'http%s://localhost:%s' % ('s' if use_ssl else '', port)
                requests.verify_ssl = False
                requests.post(url, headers={HEADER_KILL_SIGNAL: 'kill'})
            except Exception:
                pass

    # register a signal handler to terminate the sudo process later on
    TMP_THREADS.append(Terminator())

    # start the process
    process = run('%sPYTHONPATH=.:%s DNS_ADDRESS=%s python %s %s' %
        (sudo_cmd, root_path, config.DNS_ADDRESS, __file__, port), asynchronous=asynchronous)
    return process


if __name__ == '__main__':
    logging.basicConfig()
    start_edge(int(sys.argv[1]))
