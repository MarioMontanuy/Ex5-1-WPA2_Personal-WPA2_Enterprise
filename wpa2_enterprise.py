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
Validates that the expected and the result are the same on their first and last characters.
"""


def validate_result_start_end(start_chars, end_chars, result):
    print("Expected: " + start_chars + "..." + end_chars)
    print("Result:   " + result)
    if (
        start_chars == result[: len(start_chars)]
        and end_chars == result[-len(end_chars) :]
    ):
        print("\nCorrect\n")
    else:
        print("\nIncorrect\n")


"""
Validates that the expected and the result are completely equals.
"""


def validate_result_equals(expected, result):
    print("Expected: " + expected)
    print("Result:   " + result)
    if expected == result:
        print("\nCorrect\n")
    else:
        print("\nIncorrect\n")


"""
Extracts the encrypted premaster secret from a TLS handshake packet.
"""


def get_premaster():
    premaster_encrypted = ""
    capture = pyshark.FileCapture(
        "data/tradio_pap_wpa_enterprise.pcapng", display_filter="tls", use_ek=True
    )
    for packet in capture:
        try:
            premaster_encrypted = packet["EAP"].tls["tls_tls_handshake_epms"]
            premaster_encrypted = premaster_encrypted.replace(":", "")
            premaster_encrypted = bytes.fromhex(premaster_encrypted)
            break
        except:
            continue
    capture.close()
    return premaster_encrypted


"""
Decrypts the premaster secret using the server's private key and prints the result.
"""


def question1():
    premaster = get_premaster()
    try:
        server_privkey = read_server_key("data/server.p12")
        premaster_decrypted = server_privkey.decrypt(
            premaster, padding=padding.PKCS1v15()
        )
        validate_result_start_end("0303", "fd89b0ab", premaster_decrypted.hex())
        # print("premaster key: 0303...fd89b0ab")
        # print("Result:        " + premaster_decrypted.hex())
        return premaster_decrypted
    except Exception as e:
        print("Error: " + str(e))


"""
Calculate HMAC of input using a given key and algorithm.
"""


def HMAC(key, input, algo):
    h = hmac.HMAC(key, algo)
    h.update(input)
    return h.finalize()


"""
Pseudorandom Function (PRF) implementation used in TLS to derive keys.
"""


def PRF(key, label, seed, algo, n):
    seed = label + seed
    A = {}
    A[0] = seed
    B = b""
    for i in range(1, n + 1):
        A[i] = HMAC(key, A[i - 1], algo)
    for i in range(0, n):
        B = B + HMAC(key, A[i + 1] + seed, algo)
    return B


"""
Get the necessary packets to compute the master key.
"""


def get_packets_for_mk():
    capture = pyshark.FileCapture(
        "data/tradio_pap_wpa_enterprise.pcapng",
        display_filter="tls",
        use_json=True,
        include_raw=True,
    )
    client_hello = bytes.fromhex(capture[0].eap.tls.record.handshake_raw[0])
    server_hello = bytes.fromhex(capture[1].eap.tls.record[0].handshake_raw[0])
    certificate = bytes.fromhex(capture[1].eap.tls.record[1].handshake_raw[0])
    server_hello_done = bytes.fromhex(capture[1].eap.tls.record[2].handshake_raw[0])
    client_key_exchange = bytes.fromhex(capture[2].eap.tls.record[0].handshake_raw[0])
    capture.close()
    return (
        client_hello
        + server_hello
        + certificate
        + server_hello_done
        + client_key_exchange
    )


"""
Compute the SHA-384 hash of the concatenated handshake messages.
"""


def SHA384():
    pck_mk = get_packets_for_mk()
    sha384_hasher = hashes.Hash(hashes.SHA384())
    sha384_hasher.update(pck_mk)
    return sha384_hasher.finalize()


"""
Derive the master key from the premaster secret.
"""


def question2(pm):
    s = SHA384()
    master_key = PRF(pm, b"extended master secret", s, hashes.SHA384(), 1)[:48]
    validate_result_start_end("a5a6", "b4a6", master_key.hex())
    return master_key


"""
Extract random values from ClientHello and ServerHello messages.
"""


def get_random_from_hello_packets():
    capture = pyshark.FileCapture(
        "data/tradio_pap_wpa_enterprise.pcapng",
        display_filter="tls",
        use_json=True,
        include_raw=True,
    )
    client_hello_random = bytes.fromhex(
        capture[0].eap.tls.record.handshake.random.replace(":", "")
    )
    server_hello_random = bytes.fromhex(
        capture[1].eap.tls.record[0].handshake.random.replace(":", "")
    )
    capture.close()
    return server_hello_random, client_hello_random


"""
Derive the key block used for encryption from the master key.
"""


def question3(mk):
    server_hello_random, client_hello_random = get_random_from_hello_packets()
    key_block = PRF(
        mk,
        b"key expansion",
        server_hello_random + client_hello_random,
        hashes.SHA384(),
        2,
    )[:72]
    client_write_key = key_block[:32]
    validate_result_start_end("16de", "dda6", client_write_key.hex())
    # print("Client Write Key: 16de...dda6")
    # print("Result:           " + client_write_key.hex())
    return key_block, server_hello_random, client_hello_random


# Question 4

"""
Extract data packet 119 and return its content.
"""


def get_data_packet_119():
    capture = pyshark.FileCapture(
        "data/tradio_pap_wpa_enterprise.pcapng",
        display_filter="frame.number==119",
        use_json=True,
        include_raw=True,
    )
    data = bytes.fromhex(capture[0].eap.tls.record.app_data_raw[0])
    capture.close()
    return data


"""
Construct additional authenticated data (AAD) for GCM decryption.
"""


def get_aad(data, tag):
    seq_num = bytes.fromhex("0000000000000001")
    content_type = bytes.fromhex("17")
    version = bytes.fromhex("0303")
    ciphertext_length = int.to_bytes(len(data) - 24, 2, "big")
    return seq_num + content_type + version + ciphertext_length


"""
Decrypt data using AES-GCM.
"""


def AESGCM_decrypt(data, nonce, key, associated_data):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, data, associated_data)


"""
Extract and print the username and password from decrypted plaintext bytes.
"""


def get_username_password_plaintext(plaintext_bytes):
    decoded_string = plaintext_bytes.decode("utf-8")
    occurrences = []
    start_index = 0
    while True:
        index = decoded_string.find("user2", start_index)
        if index == -1:
            break
        occurrences.append(index)
        start_index = index + len("user2")

    print("Username: " + decoded_string[occurrences[0] : occurrences[0] + len("user2")])
    print("Password: " + decoded_string[occurrences[1] : occurrences[1] + len("user2")])


"""
Decrypt the data packet using the derived key and print the username and password.
"""


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

"""
Compute HMAC-SHA1 for a given key and data.
"""


def SHA1_HMAC(key, data, length):
    r = bytes()
    for i in range(0, math.ceil(length / 20)):
        r += HMAC(key, data + chr(i).encode(), hashes.SHA1())
    return r[:length]


"""
Extract necessary data from the pcap file for WPA key generation.
"""


def get_data():
    capture = pyshark.FileCapture(
        "data/tradio_pap_wpa_enterprise.pcapng",
        display_filter="frame.number==123 || frame.number==125",
    )
    nonce1 = capture[0]["EAPOL"].get_field_by_showname("WPA Key Nonce").replace(":", "")
    nonce2 = capture[1]["EAPOL"].get_field_by_showname("WPA Key Nonce").replace(":", "")
    transmission_addr = capture[0]["WLAN"].get_field_by_showname("Transmitter address")
    destination_addr = capture[0]["WLAN"].get_field_by_showname("Destination address")
    capture.close()
    return (
        "Pairwise key expansion".encode()
        + chr(0x00).encode()
        + bytes.fromhex(min(destination_addr, transmission_addr).replace(":", ""))
        + bytes.fromhex(max(destination_addr, transmission_addr).replace(":", ""))
        + bytes.fromhex(min(nonce1, nonce2))
        + bytes.fromhex(max(nonce1, nonce2))
    )


"""
Derive the MSK and PTK from the master key and other data.
"""


def question5(mk, server_hello_random, client_hello_random):
    # MSK
    key_block = PRF(
        mk,
        b"ttls keying material",
        client_hello_random + server_hello_random,
        hashes.SHA384(),
        1,
    )
    MSK = key_block[:48]
    validate_result_start_end("85e8", "297e", MSK.hex())
    # print("MSK:    85e8...297e")
    # print("Result: " + MSK.hex())
    # PTK
    data = get_data()
    PTK = SHA1_HMAC(MSK[:32], data, 48)
    validate_result_start_end("b3c6", "8ae4", PTK.hex())
    # print("PTK:    b3c6...8ae4")
    # print("Result: " + PTK.hex())
    return PTK


# Question 6
"""
Get the raw of 802.1x packets needed for the MIC calculation.
"""


def get_packets_802_1X():
    packets_802_1X = []
    capture = pyshark.FileCapture(
        "data/tradio_pap_wpa_enterprise.pcapng",
        display_filter="frame.number==125 || frame.number==127 || frame.number==129",
        use_json=True,
        include_raw=True,
    )
    for packet in capture:
        packets_802_1X.append(packet.get_raw_packet()[58:])
    capture.close()
    return packets_802_1X


"""
Calculate the MIC for a given message and key.
"""


def get_mic(kck, mess_i):
    data = mess_i[:81]
    for _ in range(16):
        data += chr(0x00).encode()
    data += mess_i[81 + 16 :]
    return HMAC(kck, data, hashes.SHA1())[:16]


"""
Compute and print the MIC for the given 802.1X packets using the PTK.
"""


def question6(ptk):
    kck = ptk[:16]
    packets_802_1X = get_packets_802_1X()
    for i in range(2, 5):
        mess_i = packets_802_1X[i - 2]
        mic = get_mic(kck, mess_i)
        print("Packet: " + str(i))
        validate_result_equals(mess_i[81 : 81 + 16].hex(), mic.hex())
        # print("mess_i: " + mess_i[81 : 81 + 16].hex())
        # print("MIC:    " + mic.hex() + "\n")


# Question 7
"""
Extract the necessary data from packet 131 for decryption.
"""


def get_packet_131_data():
    capture = pyshark.FileCapture(
        "data/tradio_pap_wpa_enterprise.pcapng", display_filter="frame.number==131"
    )
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


"""
Construct the nonce for decrypting packet 131.
"""


def get_nonce(packet_131_data):
    nonce_multicast = (
        chr(0x00).encode()
        + packet_131_data["sa_addr2"]
        + packet_131_data["ccpm_par"][0:2]
        + packet_131_data["ccpm_par"][4:8]
    )
    return nonce_multicast


"""
Construct the additional authenticated data (AAD) for packet 131 decryption.
"""


def get_aad_pck_131(packet_131_data):
    aad_multicast = (
        packet_131_data["fc"]
        + packet_131_data["bssid_addr1"]
        + packet_131_data["sa_addr2"]
        + packet_131_data["da_addr3"]
        + 2 * chr(0x00).encode()
    )
    return aad_multicast


"""
Decrypt data using AES-CCM.
"""


def AESCCM_decrypt(key, tag_length, data, nonce, associated_data):
    aesccm = AESCCM(key, tag_length)
    return aesccm.decrypt(nonce, data, associated_data)


"""
Decrypt the data in packet 131 and print the plaintext.
"""


def question7(TK):
    packet_131_data = get_packet_131_data()
    nonce_multicast = get_nonce(packet_131_data)
    aad_multicast = get_aad_pck_131(packet_131_data)
    plaintext = AESCCM_decrypt(
        TK, 8, packet_131_data["data"], nonce_multicast, aad_multicast
    )
    print("Result: " + plaintext.hex())
    print("It is a multicast packet")


"""
Main function to run all questions in sequence.
"""


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
