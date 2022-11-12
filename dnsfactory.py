import copy

import dnsparser


def create_local_response(local_ips_to_answer, question, id):
    response = dnsparser.DNSPacket()
    response.header = dnsparser.DNSHeader(
        id=id,
        flags=dnsparser.DNSFlags(
            qr='1',
            rd='1',
            ra='1',
            rcode=dnsparser.DNSRCode.NO_ERROR
        ),
        ancount=len(local_ips_to_answer),
        arcount=0
    )
    for ip in local_ips_to_answer:
        answer = dnsparser.DNSAnswer(
            name=question.qname,
            type=dnsparser.DNSRecordTypes.A,
            class_=1,
            ttl=0,
            rdata=ip
        )
        response.answers.append(answer)
    response.additional = []
    return response.to_bytes()


def create_response(id, questions, answers):
    response = dnsparser.DNSPacket()
    response.header = dnsparser.DNSHeader(
        id=id,
        flags=dnsparser.DNSFlags(
            qr='1',
            rd='1',
            ra='1',
            rcode=dnsparser.DNSRCode.NO_ERROR
        ),
        qdcount=len(questions),
        ancount=len(answers)
    )
    response.questions = questions
    response.answers = answers
    response.additional = []

    return response.to_bytes()


def create_response_nx_domain(id, questions):
    response = dnsparser.DNSPacket()
    response.header = dnsparser.DNSHeader(
        id=id,
        flags=dnsparser.DNSFlags(
            qr='1',
            rd='1',
            ra='1',
            rcode=dnsparser.DNSRCode.NAME_ERROR
        )
    )
    response.questions = questions
    response.answers = []
    response.additional = []

    return response.to_bytes()


def create_query(id, name):
    query = dnsparser.DNSPacket()
    query.header = dnsparser.DNSHeader(
        id=id,
        flags=dnsparser.DNSFlags(
            qr='0',
            rd='1',
            ra='1',
            rcode=dnsparser.DNSRCode.NO_ERROR
        ),
        qdcount=1
    )
    query.questions = [
        dnsparser.DNSQuestion(
            qname=name,
            qtype=dnsparser.DNSRecordTypes.A,
            qclass=1
        )
    ]
    query.answers = []
    query.additional = []
    return query.to_bytes()


def create_query_from_existing_query(query: bytes, name: str):
    parsed_query = dnsparser.parse(query)
    new_query = dnsparser.DNSPacket()
    new_query.header = copy.copy(parsed_query.header)
    new_query.header.arcount = 0
    new_query.questions = []
    for question in parsed_query.questions:
        new_query.questions.append(dnsparser.DNSQuestion(
            qname=name,
            qtype=question.qtype,
            qclass=question.qclass
        ))

    return new_query.to_bytes()
