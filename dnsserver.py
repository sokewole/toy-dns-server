import asyncio
import copy
import enum
import math
import argparse

import cacheout
from typing import List

import asyncudp

import dnsparser
import dnsfactory


class RootDnsServerIPs(enum.Enum):
    A = '198.41.0.4'
    B = '199.9.14.201'
    C = '192.33.4.12'
    D = '199.7.91.13'
    E = '192.203.230.10'
    F = '192.5.5.241'
    G = '192.112.36.4'
    H = '198.97.190.53'
    I = '192.36.148.17'
    J = '192.58.128.30'
    K = '193.0.14.129'
    L = '199.7.83.42'
    M = '202.12.27.33'

    @classmethod
    def values(cls) -> List:
        return [ip.value for ip in cls]


class DNSServer:
    def __init__(self, ip: str, port: int, ioloop: asyncio.AbstractEventLoop):
        self.ip = ip
        self.port = port
        self.socket = None
        self.ioloop = ioloop
        self.queue = asyncio.Queue()
        self.cache = cacheout.LRUCache()

    async def start(self):
        self.socket = await asyncudp.create_socket(local_addr=(self.ip, self.port))

        consumers = [asyncio.create_task(self.consumer())
                     for _ in range(10)]
        await self.producer()
        await self.queue.join()

        for c in consumers:
            c.cancel()

    async def producer(self):
        while True:
            query, addr = await self.socket.recvfrom()
            await self.queue.put((query, addr))

    async def consumer(self):
        while True:
            query, addr = await self.queue.get()
            response = await self.get_response(query)
            self.queue.task_done()
            self.socket.sendto(response, addr)

    async def get_response(self, query):
        parsed_query = dnsparser.parse(query)
        local_ips_to_answer = list(self.filter_ip(parsed_query))
        if local_ips_to_answer:
            response = dnsfactory.create_local_response(local_ips_to_answer, parsed_query.questions[0],
                                                        parsed_query.header.id)
        elif self.is_in_cache(parsed_query.questions[0].qname):
            answers = list(self.get_from_cache(parsed_query.questions[0].qname))
            response = dnsfactory.create_response(parsed_query.header.id, parsed_query.questions, answers)
        else:
            response = await self.query_dns_servers_recursively_with_timeout(query)
            if not response:
                response = dnsfactory.create_response_nx_domain(parsed_query.header.id, parsed_query.questions)
        return response

    async def query_dns_servers_recursively_with_timeout(self, query, timeout=5):
        try:
            return await asyncio.wait_for(self.query_dns_servers_recursively(query), timeout=timeout)
        except asyncio.TimeoutError:
            print('timeout')

    @staticmethod
    def filter_ip(parsed_query):
        for question in parsed_query.questions:
            if '.multiply.' in question.qname:
                numbers = [int(x) for x in question.qname.split('.multiply')[0].split('.') if x.isnumeric()]
                product = math.prod(numbers) % 256
                yield f'127.0.0.{product}'

    async def query_dns_servers_recursively(self, query):
        current_response = await self.make_request_to_any_from_list(query, RootDnsServerIPs.values())
        while current_response:
            if current_response.header.ancount > 0:
                return await self.add_cname_results(current_response)
            elif current_response.header.arcount > 0 and self.has_valid_types(current_response.additional):
                current_response = await self.make_request_to_ip_in_additional(query, current_response.additional)
            elif current_response.header.nscount > 0:
                current_response = await self.make_request_to_ip_in_authority(query, current_response.authority)

    async def add_cname_results(self, response: dnsparser.DNSPacket) -> bytes:
        result = response.raw_data
        new_response = copy.copy(response)
        for answer in filter(lambda a: a.type == dnsparser.DNSRecordTypes.CNAME, response.answers):
            if answer.rdata in response.questions[0].qname:
                continue
            if answer.name not in map(lambda x: x.name,
                                      filter(lambda a: a.type != dnsparser.DNSRecordTypes.CNAME, response.answers)):
                cname_response = await self.query_dns_servers_recursively_with_timeout(
                    dnsfactory.create_query(response.header.id, answer.rdata), 2)
                if cname_response:
                    cname_response = dnsparser.parse(cname_response)
                    new_response.answers.extend(cname_response.answers)
                    new_response.header.ancount += cname_response.header.ancount
                    result = dnsfactory.create_response(
                        new_response.header.id, new_response.questions, new_response.answers)

        return result

    @staticmethod
    def has_valid_types(answers):
        return any(map(lambda x: isinstance(x.type, dnsparser.DNSRecordTypes), answers))

    async def make_request_to_ip_in_additional(self, query, additional):
        ips = filter(lambda answer: answer.type == dnsparser.DNSRecordTypes.A, additional)
        ips = [answer.rdata for answer in ips]
        return await self.make_request_to_any_from_list(query, ips)

    async def make_request_to_ip_in_authority(self, query, authority):
        if response := await self.get_response_with_any_dns_server_ip_in_authority(query, authority):
            response = dnsparser.parse(response)
            ips = filter(lambda answer: answer.type == dnsparser.DNSRecordTypes.A, response.answers)
            ips = [answer.rdata for answer in ips]
            return await self.make_request_to_any_from_list(query, ips)

    async def get_response_with_any_dns_server_ip_in_authority(self, query, authority):
        names = filter(lambda answer: answer.type == dnsparser.DNSRecordTypes.NS, authority)
        for new_query in [dnsfactory.create_query_from_existing_query(query, name.rdata) for name in names]:
            return await self.get_response(new_query)

    async def make_request_to_any_from_list(self, data, ips):
        for ip in ips:
            received_data = await self.make_request(ip, 53, data)
            if received_data:
                return received_data

    async def make_request(self, host, port, data):
        try:
            request_socket = await asyncudp.create_socket(local_addr=("0.0.0.0", 0))
            request_socket.sendto(data, (host, port))
            response = dnsparser.parse((await request_socket.recvfrom())[0])
            self.put_in_cache(response)
            return response
        except Exception as e:
            print(e)

    def put_in_cache(self, response: dnsparser.DNSPacket):
        for answer in response.answers:
            self.cache.set(f"{response.questions[0].qname} {answer.rdata}", answer, ttl=answer.ttl)

    def get_from_cache(self, name):
        res = []
        for answer in self.cache.values():
            if answer.name.startswith(name) and answer.rdata not in map(lambda x: x.rdata, res):
                res.append(answer)
        return res

    def is_in_cache(self, name):
        for answer in self.cache.values():
            if isinstance(answer, dict):
                for ans in answer:
                    if ans.name == name and ans.type == dnsparser.DNSRecordTypes.A:
                        return True
            else:
                if answer.name == name and answer.type == dnsparser.DNSRecordTypes.A:
                    return True
        return False


def main(args: argparse.Namespace):
    ioloop = asyncio.get_event_loop()
    server = DNSServer(args.host, int(args.port), ioloop)
    ioloop.run_until_complete(server.start())
    ioloop.close()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', default='5000')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    main(args)
