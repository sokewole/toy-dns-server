import binascii
import enum
from typing import List


class DNSPacket:
    def __init__(self, data=b''):
        self.raw_data = data
        self.header = DNSHeader()
        self.questions: List[DNSQuestion] = []
        self.answers: List[DNSAnswer] = []
        self.authority: List[DNSAnswer] = []
        self.additional: List[DNSAnswer] = []

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __repr__(self):
        return str(self.__dict__)

    def to_bytes(self) -> bytes:
        result = self.header.to_bytes()
        for question in self.questions:
            result += question.to_bytes()
        for answer in self.answers + self.authority + self.additional:
            result += answer.to_bytes()

        return result


def parse(data: bytes) -> DNSPacket:
    parser = DNSParser(data)
    return parser.parse()


class DNSFlags:
    def __init__(self, qr='0', opcode='0000', aa='0', tc='0', rd='0', ra='0', z='000', rcode='0000'):
        self.qr = qr
        self.opcode = opcode
        self.aa = aa
        self.tc = tc
        self.rd = rd
        self.ra = ra
        self.z = z
        self.rcode = rcode

    @classmethod
    def from_string(cls, flags='0000000000000000'):
        return cls(
            qr=flags[0],
            opcode=flags[1:5],
            aa=flags[5],
            tc=flags[6],
            rd=flags[7],
            ra=flags[8],
            z=flags[9:12],
            rcode=flags[12:16]
        )

    def to_bytes(self) -> bytes:
        flag_str = self.qr + self.opcode + self.aa + self.tc + self.rd + self.ra + self.z + self.rcode
        return int(flag_str, 2).to_bytes(2, 'big')

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __repr__(self):
        return str(self.__dict__)


class DNSHeader:
    def __init__(self, id=0, flags: DNSFlags = DNSFlags(), qdcount=0, ancount=0, nscount=0, arcount=0):
        self.id = id
        self.flags = flags
        self.qdcount = qdcount
        self.ancount = ancount
        self.nscount = nscount
        self.arcount = arcount

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __repr__(self):
        return str(self.__dict__)

    def to_bytes(self):
        result = self.id.to_bytes(2, 'big')
        result += self.flags.to_bytes()
        result += self.qdcount.to_bytes(2, 'big')
        result += self.ancount.to_bytes(2, 'big')
        result += self.nscount.to_bytes(2, 'big')
        result += self.arcount.to_bytes(2, 'big')

        return result


def name_to_bytes(name: str) -> bytes:
    parts = name.split('.')
    result = b''
    for part in parts:
        result += bytes([len(part)]) + part.encode('utf-8')
    result += b'\x00'
    return result


class DNSRCode:
    NO_ERROR = '0000'
    FORMAT_ERROR = '0001'
    SERVER_FAILURE = '0010'
    NAME_ERROR = '0011'
    NOT_IMPLEMENTED = '0100'
    REFUSED = '0101'


class DNSQuestion:
    def __init__(self, qname='', qtype=0, qclass=0):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __repr__(self):
        return str(self.__dict__)

    def to_bytes(self) -> bytes:
        result = name_to_bytes(self.qname)
        result += int(self.qtype).to_bytes(2, 'big')
        result += self.qclass.to_bytes(2, 'big')
        return result


class DNSAnswer:
    def __init__(self, name=None, type=None, class_=None, ttl=None, rdlength=None, rdata=None):
        self.name = name
        self.type = type
        self.class_ = class_
        self.ttl = ttl
        self.rdlength = rdlength
        self.rdata = rdata

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __repr__(self):
        return str(self.__dict__)

    def to_bytes(self) -> bytes:
        result = name_to_bytes(self.name)
        result += int(self.type).to_bytes(2, 'big')
        result += self.class_.to_bytes(2, 'big')
        result += self.ttl.to_bytes(4, 'big')
        rdata = self.rdata_to_bytes()
        rdlength = len(rdata).to_bytes(2, 'big')
        result += rdlength
        result += rdata
        return result

    def rdata_to_bytes(self) -> bytes:
        if self.type == DNSRecordTypes.A:
            return bytes(map(int, self.rdata.split('.')))
        elif self.type == DNSRecordTypes.AAAA:
            return binascii.unhexlify(self.rdata.replace(':', ''))
        elif self.type == DNSRecordTypes.CNAME:
            return name_to_bytes(self.rdata)
        elif self.type == DNSRecordTypes.NS:
            return name_to_bytes(self.rdata)
        if isinstance(self.rdata, str):
            try:
                return self.rdata.encode('utf-8')
            except UnicodeEncodeError:
                return b''
        return self.rdata.to_bytes()


class Hexadecimal:
    def __init__(self, data: bytes):
        self.raw_data = data
        self.data = binascii.hexlify(self.raw_data).decode('utf-8')

    def __len__(self):
        return len(self.data)

    def __repr__(self):
        return str(self.data)

    def __getitem__(self, sliced):
        return Hexadecimal(binascii.unhexlify(self.data[sliced]))

    def to_bytes(self):
        return self.raw_data

    def to_decimal(self):
        return int(self.data, 16)

    def to_binary_string(self):
        return bin(self.to_decimal())[2:].zfill(len(self) * 4)

    def to_string(self):
        return self.raw_data.decode('utf-8')


class DNSParser:
    def __init__(self, raw_data: bytes):
        self.packet = DNSPacket(raw_data)
        self.raw_data = raw_data
        self.data_hex = Hexadecimal(self.raw_data)
        self.index = 0

    def parse(self) -> DNSPacket:
        self.parse_header()
        self.parse_questions()
        self.parse_answers()
        self.parse_authority()
        self.parse_additional()

        return self.packet

    def consume(self, length) -> Hexadecimal:
        res = self.data_hex[self.index:self.index + length]
        self.index += length
        return res

    def parse_header(self):
        self.packet.header = DNSHeader(
            id=self.consume(4).to_decimal(),
            flags=DNSFlags.from_string(self.consume(4).to_binary_string()),
            qdcount=self.consume(4).to_decimal(),
            ancount=self.consume(4).to_decimal(),
            nscount=self.consume(4).to_decimal(),
            arcount=self.consume(4).to_decimal()
        )

        return self.packet.header

    def parse_questions(self):
        for _ in range(self.packet.header.qdcount):
            self.packet.questions.append(self.parse_question())

    def parse_answers(self):
        for _ in range(self.packet.header.ancount):
            self.packet.answers.append(self.parse_answer())

    def parse_authority(self):
        for _ in range(self.packet.header.nscount):
            self.packet.authority.append(self.parse_answer())

    def parse_additional(self):
        for _ in range(self.packet.header.arcount):
            self.packet.additional.append(self.parse_answer())

    def parse_question(self):
        question = DNSQuestion(
            qname=self.parse_qname(),
            qtype=self.consume(4).to_decimal(),
            qclass=self.consume(4).to_decimal()
        )

        return question

    def parse_qname(self, start_index=None):
        qname = []
        offset = self.index if start_index is None else start_index
        while True:
            if self.is_name_pointer(offset):
                pointer = self.get_name_pointer(offset)
                qname.append(self.parse_qname(pointer * 2))
                offset += 4
                break
            length = self.data_hex[offset:offset + 2].to_decimal()
            offset += 2
            if length == 0:
                break
            qname.append(self.data_hex[offset:offset + length * 2].to_string())
            offset += length * 2
        if start_index is None:
            self.index = offset
        return '.'.join(qname)

    def parse_answer(self):
        answer = DNSAnswer(
            name=self.get_answer_name(),
            type=self.get_type(self.consume(4).to_decimal()),
            class_=self.consume(4).to_decimal(),
            ttl=self.consume(8).to_decimal(),
            rdlength=self.consume(4).to_decimal()
        )
        answer.rdata = self.get_rdata(answer)

        return answer

    def get_type(self, number):
        try:
            return DNSRecordTypes(number)
        except ValueError:
            return number

    def get_answer_name(self):
        if self.is_name_pointer():
            pointer = self.get_name_pointer()
            return self.parse_qname(pointer * 2)
        return self.parse_qname()

    def is_name_pointer(self, start_index=None):
        if start_index is None:
            start_index = self.index
        return self.get_first_two_bits(start_index) == '11'

    def get_first_two_bits(self, start_index):
        name = self.data_hex[start_index:start_index + 4].to_binary_string()
        return name[0:2]

    def get_name_pointer(self, start_index=None):
        if start_index is None:
            name = self.consume(4).to_binary_string()
        else:
            name = self.data_hex[start_index:start_index + 4].to_binary_string()
        return int(name[2:], 2)

    def get_rdata(self, answer):
        if answer.type == DNSRecordTypes.A:
            return self.get_a_rdata(answer)
        elif answer.type == DNSRecordTypes.AAAA:
            return self.get_aaaa_rdata(answer)
        elif answer.type == DNSRecordTypes.NS:
            return self.get_ns_rdata(answer)
        elif answer.type == DNSRecordTypes.CNAME:
            return self.get_cname_rdata(answer)
        return self.consume(answer.rdlength * 2)

    def get_a_rdata(self, answer):
        rdata = self.consume(answer.rdlength * 2)
        octets = [str(rdata[i:i + 2].to_decimal()) for i in range(0, len(rdata), 2)]
        return '.'.join(octets)

    def get_aaaa_rdata(self, answer):
        rdata = self.consume(answer.rdlength * 2)
        octets = [str(rdata[i:i + 4]) for i in range(0, len(rdata), 4)]
        return ':'.join(octets)

    def get_ns_rdata(self, answer):
        res = self.parse_qname(self.index)
        self.consume(answer.rdlength * 2)
        return res

    def get_cname_rdata(self, answer):
        res = self.parse_qname(self.index)
        self.consume(answer.rdlength * 2)
        return res


class DNSRecordTypes(enum.Enum):
    A = 1
    A6 = 38
    AAAA = 28
    AFSDB = 18
    AVC = 258
    CAA = 257
    CNAME = 5
    DNAME = 39
    DNSKEY = 48
    DS = 43
    GPOS = 27
    HINFO = 13
    ISDN = 20
    KEY = 25
    KX = 36
    LOC = 29
    MB = 7
    MD = 3
    MF = 4
    MG = 8
    MINFO = 14
    MR = 9
    MX = 15
    NAPTR = 35
    NULL = 10
    NS = 2
    NSAP = 22
    NSAP_PTR = 23
    NSEC = 47
    NSEC3 = 50
    NSEC3PARAM = 51
    NXT = 30
    PTR = 12
    RP = 17
    RRSIG = 46
    RT = 21
    SIG = 24
    SOA = 6
    SPF = 99
    SRV = 33
    SSHFP = 44
    TKEY = 249
    TLSA = 52
    TSIG = 250
    TXT = 16
    WKS = 11
    X25 = 19

    def __int__(self):
        return self.value
