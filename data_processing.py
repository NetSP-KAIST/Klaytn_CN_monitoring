import binascii
from Crypto.Cipher import AES
from Crypto.Util import Counter
import sha3
import snappy
from rlp import (
    encode,
    decode
)
import data_processing_header as h
from scapy.all import *
import os
from os.path import getsize
import pymysql


knownMessages = dict()



###############################################################
######################### MySQL start##########################
###############################################################

#TODO: Modify here#
klaytn_db = pymysql.connect(
    user='{your user ID}',
    passwd='{your password}',
    host='localhost',
    db='{your database table name}',
    charset='utf8'
)

cursor = klaytn_db.cursor(pymysql.cursors.DictCursor)


#################################################################
############## read pcap file & sort payload ####################
#################################################################

#TODO: Modify here#
output_dir = "/{your home directory}/data_collection"

total_node = ["cn1","cn2","cn3","cn4","cn5","cn6","cn7"]

for desire_node in total_node:
    table_reset = "truncate " + desire_node
    cursor.execute(table_reset)
    klaytn_db.commit()

    #TODO: Modify here#
    path_dir = "/{your home directory}/tcpflow" + desire_node[2]
    file_list = os.listdir(path_dir)


    # sort pcap by decreasing order. Then read the largest one, since if current working tcp session's pcap keeps growing.
    file_list.sort(key = lambda x: getsize(path_dir + "/" + x), reverse = True)

    for node in total_node: # cn1, cn2, cn3, ... 
        if node == desire_node:
            continue
        else: 
            for f in file_list: 
                if h.node_to_ip(desire_node) in f and h.node_to_ip(node) in f:
                    line_n = 0
                    print(output_dir + "/" + node + "_" + f + ".txt")
                    outputf = open(output_dir + "/" + node + "_" + desire_node + ".txt", "a")
                    outputf.truncate(0)
                    next_seq_num = 0
                    
                    print(path_dir + "/" + f)
                    for packet in PcapReader(path_dir + "/" + f): # read pcap and save as txt without duplicate packets
                        line_n = line_n + 1

                        if line_n < 5 :
                            continue
                        else:
                            try:
                                if packet[IP].dst == h.node_to_ip(desire_node):
                                    if next_seq_num == 0:
                                        next_seq_num = packet[TCP].seq + len(packet[TCP].payload)
                                    elif next_seq_num > packet[TCP].seq :
                                        continue
                                    next_seq_num = packet[TCP].seq + len(packet[TCP].payload)
                                    outputf.write(bytes(packet[TCP].payload).hex())
                            except:
                                continue

                    outputf.close()
                    break
                        


    # Traverse each tcp session's data, decrypt them secret keys, and save them in mysql database. 
    for node in total_node:
        if node == desire_node:
            continue
        data_path = "/{your home directory}/data_collection/" + node + "_" + desire_node + ".txt"
        
        secret_path = "/{your home directory}/secrets"
        secret_list = os.listdir(secret_path)
        secrets = []
        for s in secret_list:
            if desire_node in s and node in s:
                secret_f = open(secret_path + "/" + s)
                secrets.append(secret_f.readline())
                secret_f.close()

        file_list.sort(key = lambda x: getsize(path_dir + "/" + x), reverse = True)

        prepare_round = []

        for i in range(len(secrets)):
            try: 
                aes_str = secrets[i]

                iv = 0 
                aes_int = int(aes_str, 16)
                aes_hex = hex(aes_int)
                aes_bytes = bytes.fromhex(aes_hex[2:])
                encc = h.AES_CTR(aes_bytes, "0000000000000000")

                f = open(data_path, 'r')

                line = f.readline()

                ptr = 0 

                while ptr <= len(line):
                    # read rlpx header
                    header = line[ptr:ptr+64]
                    ptr = ptr + 64

                    if header == "":
                        break

                    header_int = int(header[:32], 16)
                    header_hex = hex(header_int)
                    header_hex = header_hex[2:]
                    if len(header_hex) < 32:
                        temp = 32 - len(header_hex)
                        header_hex = '0'*temp + header_hex
                        
                    header_bytes = bytes.fromhex(header_hex)

                    rw_dec = encc.decrypt(header_bytes)


                    fsize = h.readInt24(rw_dec)
                    rsize = fsize

                    padding = fsize % 16
                    if padding > 0:
                        rsize += 16 - padding 

                    # read rlpx frame data by rsize
                    framebuf = line[ptr:ptr+rsize*2]
                    ptr = ptr + rsize*2
                    
                    frame_int = int(framebuf, 16)
                    frame_hex = hex(frame_int)
                    frame_hex = frame_hex[2:]
                        
                    if len(frame_hex) < rsize*2:
                        temp = rsize*2 - len(frame_hex)
                        frame_hex = '0'*temp + frame_hex
                            
                    frame_bytes = bytes.fromhex(frame_hex)
                    frame_dec = encc.decrypt(frame_bytes)



                    frame_dec_toString = h.hexlify(frame_dec).decode("utf-8")
                    content_str = frame_dec_toString[:fsize*2]
                    content_byte = bytes.fromhex(content_str[2:])

                    msg_code = content_str[:2]
                    
                    #read 16Bytes
                    ptr = ptr + 32
                    msg_payload = content_byte

                    if msg_code != "80":
                        # snappy 
                        msg_payload = snappy.uncompress(msg_payload)
                        
                    if msg_code == "21": # consensus message
                        cmsg = decode(msg_payload)
                        cmsg_prev_hash = cmsg[0].hex()
                        cmsg_data = cmsg[1].hex()
                        cmsg_data_bytes = bytes.fromhex(cmsg_data)

                        k = sha3.keccak_256()
                        k.update(cmsg_data_bytes)
                        knownMessages_hash = k.hexdigest()

                        consensus_msg_list = decode(cmsg_data_bytes)
                        consensus_msg_code = consensus_msg_list[1]
                        consensus_msg_code = consensus_msg_code.hex()
                        consensus_msg_address = consensus_msg_list[3]
                        consensus_msg_msg = consensus_msg_list[2]
                        
                        decoded_consensus_msg_msg = decode(consensus_msg_msg)



                        if h.export_msg_type(consensus_msg_code) == "preprepare":
                            round_number = int(decoded_consensus_msg_msg[0][1].hex(), 16)
                            sql = "INSERT INTO " + desire_node + " (round_number, preprepare, prepare, commit, roundchange) VALUES (%s, 1, 0, 0, 0) ON DUPLICATE KEY UPDATE preprepare = preprepare + 1"
                            cursor.execute(sql, (round_number))
                            klaytn_db.commit()
                        elif h.export_msg_type(consensus_msg_code) == "prepare":
                            round_number = int(decoded_consensus_msg_msg[0][1].hex(), 16)
                            prepare_round.append(round_number)
                            sql = "INSERT INTO " + desire_node +  " (round_number, preprepare, prepare, commit, roundchange) VALUES (%s, 0, 1, 0, 0) ON DUPLICATE KEY UPDATE prepare = prepare + 1"
                            cursor.execute(sql, (round_number))
                            klaytn_db.commit()
                        elif h.export_msg_type(consensus_msg_code) == "commit":
                            round_number = int(decoded_consensus_msg_msg[0][1].hex(), 16)
                            sql = "INSERT INTO " + desire_node +  " (round_number, preprepare, prepare, commit, roundchange) VALUES (%s, 0, 0, 1, 0) ON DUPLICATE KEY UPDATE commit = commit + 1"
                            cursor.execute(sql, (round_number))
                            klaytn_db.commit()
                        elif h.export_msg_type(consensus_msg_code) == "roundchange":
                            round_number = int(decoded_consensus_msg_msg[0][1].hex(), 16)
                            sql = "INSERT INTO " + desire_node + " (round_number, preprepare, prepare, commit, roundchange) VALUES (%s, 0, 0, 0, 1) ON DUPLICATE KEY UPDATE roundchange = roundchange + 1"
                            cursor.execute(sql, (round_number))
                            klaytn_db.commit()
                    
                        
                        # 00 : preprepare
                        # 01 : prepare
                        # 02 : commit
                        # 03 : roundchage
                        # 04 : msgall

                        ####################################
                        ##### hash-32B,Code-64bit(8B) ######
                        ####################################

                        if knownMessages_hash in knownMessages:
                            knownMessages[knownMessages_hash][0] = knownMessages[knownMessages_hash][0] + 1
                        else:
                            knownMessages[knownMessages_hash] = [1, h.export_msg_type(consensus_msg_code), h.export_cn(consensus_msg_address)]
            except: 
                continue
            else:
                break
