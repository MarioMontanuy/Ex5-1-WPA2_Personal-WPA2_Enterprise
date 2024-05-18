from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyshark
import pyshark.packet.layers.xml_layer
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes
import math

"""
Performs the reading of the file passed as a parameter.
"""


def read_file(file):
    with open(file, "rb") as f:
        return f.read()


"""
Read the server's private key.
"""


def read_server_key(file):
    with open(file, "rb") as f:
        pkcs12 = load_pkcs12(f.read(), b"whatever")
    private_key = pkcs12.key
    return private_key


"""
It gets the data, displays the premaster, and performs the decryption operations, showing the size of the premaster and its hexadecimal representation.
"""


def question1():
    capture = pyshark.FileCapture(
        "data/tradio_pap_wpa_enterprise.pcapng", display_filter="tls", use_ek=True
    )
    for packet in capture:
        try:
            premaster = packet["EAP"].tls["tls_tls_handshake_epms"]
            premaster = premaster.replace(":", "")
            premaster = bytes.fromhex(premaster)
            break
        except:
            continue
    try:
        server_privkey = read_server_key("data/server.p12")
        premaster_decrypted = server_privkey.decrypt(
            premaster, padding=padding.PKCS1v15()
        )
        print("Expected: 0303...fd89b0ab")
        print("Solution: " + premaster_decrypted.hex())
        capture.close()
        return premaster_decrypted
    except Exception as e:
        print("Error: " + str(e))
    capture.close()

def HMAC(key, input, algo):
    h = hmac.HMAC(key, algo)
    h.update(input)
    return h.finalize()

def PRF(key, label, seed ,algo, n):
    seed = label + seed
    A = {}
    A[0] = seed
    B = b""
    for i in range(1, n+1):
        A[i] = HMAC(key, A[i-1], algo)
    for i in range(0, n):
        B = B + HMAC(key, A[i+1] + seed, algo)
    return B

def get_packets_for_mk():
    capture = pyshark.FileCapture(
        "data/tradio_pap_wpa_enterprise.pcapng", display_filter="tls", use_json=True, include_raw=True
    )
    client_hello = bytes.fromhex(capture[0].eap.tls.record.handshake_raw[0])
    server_hello = bytes.fromhex(capture[1].eap.tls.record[0].handshake_raw[0])
    certificate = bytes.fromhex(capture[1].eap.tls.record[1].handshake_raw[0])
    server_hello_done = bytes.fromhex(capture[1].eap.tls.record[2].handshake_raw[0])
    client_key_exchange = bytes.fromhex(capture[2].eap.tls.record[0].handshake_raw[0])
    capture.close()
    return client_hello + server_hello + certificate + server_hello_done + client_key_exchange

def SHA384():
    pck_mk = get_packets_for_mk()
    sha384_hasher = hashes.Hash(hashes.SHA384())
    sha384_hasher.update(pck_mk)
    return sha384_hasher.finalize()

def question2(pm):
    s = SHA384()
    master_key = PRF(pm, b"extended master secret", s, hashes.SHA384(), 1)[:48]
    print("Expected: a5a6...b4a6")
    print("Solution: " + master_key.hex())
    return master_key

def get_random_from_hello_packets():
    capture = pyshark.FileCapture(
        "data/tradio_pap_wpa_enterprise.pcapng", display_filter="tls", use_json=True, include_raw=True
    )
    client_hello_random = bytes.fromhex(capture[0].eap.tls.record.handshake.random.replace(":", ""))
    server_hello_random = bytes.fromhex(capture[1].eap.tls.record[0].handshake.random.replace(":", ""))
    capture.close()
    return server_hello_random, client_hello_random



def question3(mk):
    server_hello_random, client_hello_random = get_random_from_hello_packets()
    key_block = PRF(mk, b"key expansion", server_hello_random + client_hello_random, hashes.SHA384(), 2)[:72]
    client_write_key = key_block[:32]
    print("Expected: 16de...dda6")
    print("Solution: " + client_write_key.hex())
    return key_block, server_hello_random, client_hello_random

# Question 4

def get_data_packet_119():
    capture = pyshark.FileCapture(
        "data/tradio_pap_wpa_enterprise.pcapng", display_filter="frame.number==119", use_json=True, include_raw=True
    )
    data = bytes.fromhex(capture[0].eap.tls.record.app_data_raw[0])
    capture.close()
    return data

def get_aad(data, tag):
    seq_num = bytes.fromhex("0000000000000001")
    content_type = bytes.fromhex("17")
    version = bytes.fromhex("0303")
    explicit_nonce = data[:8]
    ciphertext_length = int.to_bytes(len(data)-24, 2, "big")
    return seq_num + content_type + version + ciphertext_length

def AESGCM_decrypt(data, nonce, key, associated_data):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, data, associated_data)

def get_username_password_plaintext(plaintext_bytes):
    decoded_string = plaintext_bytes.decode('utf-8')
    occurrences = []
    start_index = 0
    while True:
        index = decoded_string.find("user2", start_index)
        if index == -1:
            break
        occurrences.append(index)
        start_index = index + len("user2")

    print("Username: " + decoded_string[occurrences[0]:occurrences[0]+len("user2")])
    print("Password: " + decoded_string[occurrences[1]:occurrences[1]+len("user2")])


def question4(key_block):
    client_write_key = key_block[:32]
    client_write_iv = key_block[64:68]
    data = get_data_packet_119()
    tag = data[-16:]
    client_nonce = client_write_iv + data[:8]
    aad = get_aad(data, tag)
    plaintext_bytes = AESGCM_decrypt(data[8:], client_nonce, client_write_key, aad)
    get_username_password_plaintext(plaintext_bytes)

# Question 5

def SHA1_HMAC(key, data, length):
    r = bytes()
    for i in range(0, math.ceil(length / 20)):
        r += HMAC(key, data + chr(i).encode(), hashes.SHA1())
    return r[:length]

def get_data():
    capture = pyshark.FileCapture("data/tradio_pap_wpa_enterprise.pcapng", display_filter="frame.number==123 || frame.number==125")
    nonce1 = (
        capture[0]["EAPOL"].get_field_by_showname("WPA Key Nonce").replace(":", "")
    )
    nonce2 = (
        capture[1]["EAPOL"].get_field_by_showname("WPA Key Nonce").replace(":", "")
    )
    transmission_addr = capture[0]["WLAN"].get_field_by_showname(
        "Transmitter address"
    )
    destination_addr = capture[0]["WLAN"].get_field_by_showname(
        "Destination address"
    )
    capture.close()
    return (
        "Pairwise key expansion".encode()
        + chr(0x00).encode()
        + bytes.fromhex(min(destination_addr, transmission_addr).replace(":", ""))
        + bytes.fromhex(max(destination_addr, transmission_addr).replace(":", ""))
        + bytes.fromhex(min(nonce1, nonce2))
        + bytes.fromhex(max(nonce1, nonce2))
    )

def question5(mk, server_hello_random, client_hello_random):
    # server_hello_random, client_hello_random = get_random_from_hello_packets()
    # MSK
    key_block = PRF(mk, b"ttls keying material", client_hello_random + server_hello_random, hashes.SHA384(), 1)
    MSK = key_block[:48]
    print(" - MSK - ")
    print("Expected: 85e8...297e")
    print("Solution: " + MSK.hex())
    # PTK
    data = get_data()
    PTK = SHA1_HMAC(MSK[:32], data, 48)
    print("\n - PTK - ")
    print("Expected: b3c6...8ae4")
    print("Solution: " + PTK.hex())
    return PTK

# Question 6

def get_packets_802_1X():
    packets_802_1X = []
    capture = pyshark.FileCapture(
        "data/tradio_pap_wpa_enterprise.pcapng", display_filter="frame.number==125 || frame.number==127 || frame.number==129", use_json=True, include_raw=True
    )
    for packet in capture:
        packets_802_1X.append(packet.get_raw_packet()[58:])
    capture.close()
    return packets_802_1X


def get_mic(kck, mess_i):
    data = mess_i[:81]
    for _ in range(16):
        data += chr(0x00).encode()
    data += mess_i[81 + 16 :]
    return HMAC(kck, data, hashes.SHA1())[:16]


def question6(ptk):
    kck = ptk[:16]
    packets_802_1X = get_packets_802_1X()
    for i in range(2, 5):
        mess_i = packets_802_1X[i - 2]
        mic = get_mic(kck, mess_i)
        print("Packet: " + str(i))
        print("mess_i: " + mess_i[81 : 81 + 16].hex())
        print("MIC:    " + mic.hex() + "\n")

# Question 7

def get_packet_131_data():
    capture = pyshark.FileCapture("data/tradio_pap_wpa_enterprise.pcapng", display_filter="frame.number==131")
    packet_data = {}
    packet = capture[0]
    packet_data["fc"] = bytes.fromhex(str(packet.wlan.fc)[2:])
    packet_data["fc_subtype"] = str(packet.wlan.fc_subtype).encode()
    packet_data["bssid_addr1"] = bytes.fromhex(str(packet.wlan.bssid).replace(":", ""))
    packet_data["sa_addr2"] = bytes.fromhex(str(packet.wlan.sa).replace(":", ""))
    packet_data["da_addr3"] = bytes.fromhex(str(packet.wlan.da).replace(":", ""))
    packet_data["ccpm_par"] = bytes.fromhex(
        str(packet.wlan.ccmp_extiv).replace("x", "000")
    )
    packet_data["data"] = bytes.fromhex(str(packet.data.data))
    capture.close()
    return packet_data


def get_nonce(packet_131_data):
    nonce_multicast = (
        chr(0x00).encode()
        + packet_131_data["sa_addr2"]
        + packet_131_data["ccpm_par"][0:2]
        + packet_131_data["ccpm_par"][4:8]
    )
    return nonce_multicast

def get_aad_pck_131(packet_131_data):
    aad_multicast = (
        packet_131_data["fc"]
        + packet_131_data["bssid_addr1"]
        + packet_131_data["sa_addr2"]
        + packet_131_data["da_addr3"]
        + 2 * chr(0x00).encode()
    )
    return aad_multicast

def AESCCM_decrypt(key, tag_length, data, nonce, associated_data):
    aesccm = AESCCM(key, tag_length)
    return aesccm.decrypt(nonce, data, associated_data)

def question7(TK):
    packet_131_data = get_packet_131_data()
    nonce_multicast = get_nonce(packet_131_data)
    aad_multicast = get_aad_pck_131(packet_131_data)
    plaintext = AESCCM_decrypt(
        TK, 8, packet_131_data["data"], nonce_multicast, aad_multicast
    )
    print("Solution: " + plaintext.hex())

def main():
    print("\n ------ Question 1 ------ \n")
    premaster = question1()
    print("\n ------ Question 2 ------ \n")
    master_key = question2(premaster)
    print("\n ------ Question 3 ------ \n")
    key_block, server_hello_random, client_hello_random = question3(master_key[:48])
    print("\n ------ Question 4 ------ \n")
    question4(key_block)
    print("\n ------ Question 5 ------ \n")
    PTK = question5(master_key[:48], server_hello_random, client_hello_random)
    print("\n ------ Question 6 ------ \n")
    question6(PTK)
    print("\n ------ Question 7 ------ \n")
    question7(PTK[32:48])
    print("\n ------ End ------ \n")

if __name__ == "__main__":
    main()


