from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
import pyshark
import pyshark.packet.layers.xml_layer
import math
import json
import xml.etree.ElementTree as ET

"""
Performs the reading of the file passed as a parameter.
"""
NONCES = {}


def read_file(file):
    with open(file, "rb") as f:
        return f.read()


# Question 1


def question1():
    password = b"Wifi_Test_Password"
    ssid = b"Wifi_Test"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=32,
        salt=ssid,  # Use SSID as salt
        iterations=4096,
    )
    psk = kdf.derive(password)
    print("Expected: a22c...b603")
    print("Solution: " + psk.hex())
    return psk


# Question 2


def question2():
    capture = pyshark.FileCapture("data/tradio.pcapng", display_filter="eapol")
    for packet in capture:
        try:
            message_id = packet["EAPOL"].get_field_by_showname("Message number")
            nonce = (
                packet["EAPOL"].get_field_by_showname("WPA Key Nonce").replace(":", "")
            )
            NONCES[message_id] = nonce
            
        except:
            continue
    print("Handshake message id: 1" + "\nExpected: b6ea...d7d3b\nNonce:    " + NONCES["1"])
    print("\nHandshake message id: 2" + "\nExpected: e6d8...b61c\nNonce:    " + NONCES["2"])
    capture.close()


# Question 3


def get_data():
    capture = pyshark.FileCapture("data/tradio.pcapng", display_filter="eapol")
    for packet in capture:
        try:
            transmission_addr = packet["WLAN"].get_field_by_showname(
                "Transmitter address"
            )
            destination_addr = packet["WLAN"].get_field_by_showname(
                "Destination address"
            )
            break
        except:
            continue
    capture.close()

    # print("destination_addr: " + destination_addr)
    # print("transmission_addr: " + transmission_addr)
    # print("Nonce 1: " + str(NONCES["1"]))
    # print("Nonce 2: " + str(NONCES["2"]))
    return (
        "Pairwise key expansion".encode()
        + chr(0x00).encode()
        + bytes.fromhex(min(destination_addr, transmission_addr).replace(":", ""))
        + bytes.fromhex(max(destination_addr, transmission_addr).replace(":", ""))
        + bytes.fromhex(min(NONCES["1"], NONCES["2"]))
        + bytes.fromhex(max(NONCES["1"], NONCES["2"]))
    )


def HMAC(key, algo, data):
    hash = hmac.HMAC(key, algo)
    hash.update(data)
    return hash.finalize()


def SHA1_HMAC(key, data, length):
    r = bytes()
    for i in range(0, math.ceil(length / 20)):
        r += HMAC(key, hashes.SHA1(), data + chr(i).encode())
    return r[:length]


def question3(psk):
    data = get_data()
    result = SHA1_HMAC(psk, data, 48)
    print("Expected: 0ffc...8aad")
    print("Solution: " + result.hex())
    return result


# Question 4


def get_packets_802_1X():
    packets_802_1X = []
    capture = pyshark.FileCapture(
        "data/tradio.pcapng", display_filter="eapol", use_json=True, include_raw=True
    )
    for packet in capture:
        packets_802_1X.append(packet.get_raw_packet()[60:])
    capture.close()
    return packets_802_1X


def get_mic(kck, mess_i):
    data = mess_i[:81]
    for _ in range(16):
        data += chr(0x00).encode()
    data += mess_i[81 + 16 :]
    return HMAC(kck, hashes.SHA1(), data)[:16]


def question4(ptk):
    kck = ptk[:16]
    packets_802_1X = get_packets_802_1X()
    for i in range(2, 5):
        mess_i = packets_802_1X[i - 1]
        mic = get_mic(kck, mess_i)
        print("Packet: " + str(i))
        print("mess_i: " + mess_i[81 : 81 + 16].hex())
        print("MIC:    " + mic.hex() + "\n")


# Question 5

# Se ha elegido este orden para las addr1-3 porque TO DS: 1 From DS: 0


def get_packet_517_data():
    capture = pyshark.FileCapture("data/tradio.pcapng", display_filter="frame.number==517")
    packet_data = {}
    packet = capture[0]
    packet_data["fc"] = bytes.fromhex(str(packet.wlan.fc)[2:])
    packet_data["fc_subtype"] = str(packet.wlan.fc_subtype).encode()
    packet_data["qos_control"] = bytes.fromhex(str(packet.wlan.qos)[2:])
    packet_data["bssid_addr1"] = bytes.fromhex(str(packet.wlan.bssid).replace(":", ""))
    packet_data["sa_addr2"] = bytes.fromhex(str(packet.wlan.sa).replace(":", ""))
    packet_data["da_addr3"] = bytes.fromhex(str(packet.wlan.da).replace(":", ""))
    packet_data["ccpm_par"] = bytes.fromhex(
        str(packet.wlan.ccmp_extiv).replace("x", "000")
    )
    packet_data["data"] = bytes.fromhex(str(packet.data.data))
    capture.close()
    return packet_data


def question5(packet_517_data):
    nonce_unicast = (
        packet_517_data["qos_control"][0:1]
        + packet_517_data["sa_addr2"]
        + packet_517_data["ccpm_par"][0:2]
        + packet_517_data["ccpm_par"][4:8]
    )
    print("Nonce:    002269a9e50b3500000000000b")
    print("Solution: " + nonce_unicast.hex())
    return nonce_unicast


# Question 6


def question6(packet_517_data):
    aad_unicast = (
        packet_517_data["fc"]
        + packet_517_data["bssid_addr1"]
        + packet_517_data["sa_addr2"]
        + packet_517_data["da_addr3"]
        + 2 * chr(0x00).encode()
        + packet_517_data["qos_control"][0:2]
    )
    print("AAD:      884184aa9cfd08202269a9e50b3584aa9cfd081f00000000")
    print("Solution: " + aad_unicast.hex())
    return aad_unicast


# Question 7


def AESCCM_decrypt(key, tag_length, data, nonce, associated_data):
    aesccm = AESCCM(key, tag_length)
    return aesccm.decrypt(nonce, data, associated_data)


def question7(packet_517_data, tk, nonce_unicast, aad_unicast):
    plaintext = AESCCM_decrypt(
        tk, 8, packet_517_data["data"], nonce_unicast, aad_unicast
    )
    print("plaintext: aaaa...3637")
    print("Solution:  " + plaintext.hex())


# Question 8


def question8(kek):
    capture = pyshark.FileCapture("data/tradio.pcapng", display_filter="eapol")
    packet_data = bytes.fromhex(capture[2].eapol.wlan_rsna_keydes_data.replace(":", ""))
    GTK = aes_key_unwrap(kek, packet_data)
    print("Expected: 3014...dd00")
    print("Solution: " + GTK.hex())
    return GTK


# Question 9

# Se ha elegido este orden para las addr1-3 porque TO DS: 0 From DS: 1


def get_packet_527_data():
    capture = pyshark.FileCapture("data/tradio.pcapng", display_filter="frame.number==527")
    packet_data = {}
    packet = capture[0]
    packet_data["fc"] = bytes.fromhex(str(packet.wlan.fc)[2:])
    packet_data["fc_subtype"] = str(packet.wlan.fc_subtype).encode()
    packet_data["da_addr1"] = bytes.fromhex(str(packet.wlan.da).replace(":", ""))
    packet_data["bssid_addr2"] = bytes.fromhex(str(packet.wlan.bssid).replace(":", ""))
    packet_data["sa_addr3"] = bytes.fromhex(str(packet.wlan.sa).replace(":", ""))
    packet_data["ccpm_par"] = bytes.fromhex(
        str(packet.wlan.ccmp_extiv).replace("x", "000")
    )
    packet_data["data"] = bytes.fromhex(str(packet.data.data))
    capture.close()
    return packet_data


def question9(packet_527_data):
    nonce_multicast = (
        chr(0x00).encode()
        + packet_527_data["bssid_addr2"]
        + packet_527_data["ccpm_par"][0:2]
        + packet_527_data["ccpm_par"][4:8]
    )
    print("Expected: 0084aa9cfd08200000000008f0")
    print("Solution: " + nonce_multicast.hex())
    return nonce_multicast


# Question 10


def question10(packet_527_data):
    aad_multicast = (
        packet_527_data["fc"]
        + packet_527_data["da_addr1"]
        + packet_527_data["bssid_addr2"]
        + packet_527_data["sa_addr3"]
        + 2 * chr(0x00).encode()
    )
    print("AAD:      0842ffffffffffff84aa9cfd082084aa9cfd081f0000")
    print("Solution: " + aad_multicast.hex())
    return aad_multicast


# Question 11
def question11(GTK, packet_527_data, nonce_multicast, aad_multicast):
    plaintext = AESCCM_decrypt(
        GTK, 8, packet_527_data["data"], nonce_multicast, aad_multicast
    )
    print("Solution: " + plaintext.hex())


# Question 12

def get_psk_q12(password):
    ssid = b"Wifi_Test"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=32,
        salt=ssid,  # Use SSID as salt
        iterations=4096,
    )
    psk = kdf.derive(password)
    return psk


def get_packet_info_q12():
    capture = pyshark.FileCapture("data/tradio2.pcapng", display_filter="eapol")
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

def get_packet2_q12():
    capture = pyshark.FileCapture(
        "data/tradio2.pcapng", display_filter="eapol", use_json=True, include_raw=True
    )
    return capture[1].get_raw_packet()[60:]

def question12():
    passwords = [f'Wifi_Test{i}' for i in range(10)]
    data = get_packet_info_q12()
    packet2 = get_packet2_q12()
    for password in passwords:
        psk = get_psk_q12(password.encode())
        ptk = SHA1_HMAC(psk, data, 48)
        kck = ptk[:16]
        mess_i = packet2
        mic = get_mic(kck, mess_i)
        if mess_i[81 : 81 + 16].hex() == mic.hex():
            print("mess_i: " + mess_i[81 : 81 + 16].hex())
            print("MIC:    " + mic.hex() + "\n")
            print("Password found: " + password)
            break




def main():
    print("\n ------ Question 1 ------ \n")
    result_q1_PSK = question1()
    print("\n ------ Question 2 ------ \n")
    question2()
    print("\n ------ Question 3 ------ \n")
    result_q3_PTK = question3(result_q1_PSK)
    print("\n ------ Question 4 ------ \n")
    question4(result_q3_PTK[0:16])
    print("\n ------ Question 5 ------ \n")
    packet_517_data = get_packet_517_data()
    nonce_unicast = question5(packet_517_data)
    print("\n ------ Question 6 ------ \n")
    aad_unicast = question6(packet_517_data)
    print("\n ------ Question 7 ------ \n")
    question7(packet_517_data, result_q3_PTK[32:48], nonce_unicast, aad_unicast)
    print("\n ------ Question 8 ------ \n")
    GTK = question8(result_q3_PTK[16:32])
    print("\n ------ Question 9 ------ \n")
    packet_527_data = get_packet_527_data()
    nonce_multicast = question9(packet_527_data)
    print("\n ------ Question 10 ------ \n")
    aad_multicast = question10(packet_527_data)
    print("\n ------ Question 11 ------ \n")
    question11(GTK[30:46], packet_527_data, nonce_multicast, aad_multicast)
    print("\n ------ Question 12 ------ \n")
    question12()
    print("\n ------ End ------ \n")


if __name__ == "__main__":
    main()
