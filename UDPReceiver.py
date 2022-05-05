import socket
import getpass
import json
import base64

# install using 'python3 -m pip install rsa'
import rsa
# install using 'python3 -m pip install zlib'
import zlib

# install using 'python3 -m pip install profanity-filter'
from profanity_filter import ProfanityFilter
pf = ProfanityFilter()
# Needs spacy module for wordlist
# install using 'python3 -m spacy download en'

BUFFER_SIZE = 4096

# Uses CRC32 to calculate a checksum for our data to be sent
# takes in json data and compares the checksum in the json object with the calculated checksum
# checksum is performed on the type and content of the json
def checksum_calculator(data):
    name = data.get("type")
    content = data.get("content")
    if (name is None):
        name = ""
    if (content is None):
        content = ""
    checksum_sequence = name + content

    checksum = zlib.crc32(bytes(checksum_sequence, "utf-8"))
    return checksum


def sendData(sock, jsonData):

    # calculates checksum and puts it in json object
    checksumVal = checksum_calculator(jsonData)
    # append checksum to json
    jsonData['checksum'] = checksumVal

    jsonData = json.dumps(jsonData)

    # Attempts to send the data to the recipient
    global client
    sock.sendto(jsonData.encode(), client)
    # After every message is sent there should be an ACK packet sent back to confirm it's arrival,
    # Else it will attempt to resend the data one more time before moving on to the next address
    data, server = sock.recvfrom(BUFFER_SIZE)
    x = json.loads(data)
    msgType = x.get("type")


    # Checks if the received packet has a checksum as it was optional for this implementation
    # if the checksums do not match then it will raise an exception
    if (x.get("checksum") is not None):
        if (checksum_calculator(x) != int(x.get("checksum"))):
            print("Checksums do not match, need the packet resent")
            raise Exception()
        else:
            print("Checksum on ACK matches")
    else:
        print("No checksum attached to the data, awaiting the data to be re-sent")
        raise Exception()

    # if an acknowledgement message is received then we know the data reached the recipient correctly
    if (msgType == "ack"):
        print("ACK packet received")
    else:
        print("No ACK packet received")
        raise socket.error


def receiveData(sock, expectedMessageType):
    # Attempts to receive data from recipient
    data, address = sock.recvfrom(BUFFER_SIZE)
    
    # sets client address
    global client
    client = address

    x = json.loads(data)

    # # Checks if the received packet has a checksum as it was optional for this implementation
    # if the checksums do not match then it will raise an exception
    if (x.get("checksum") is not None):
        if (checksum_calculator(x) != int(x.get("checksum"))):
            print("Checksums do not match, need the packet resent")
            raise Exception()
        else:
            print("Checksums match")
    else:
        print("No checksum attached to the data, awaiting the data to be re-sent")
        raise Exception()

    msgType = x.get("type")

    if ( msgType != expectedMessageType ):
        raise Exception()

    if (msgType == "sync"):
        print("Connection initialized with: ",client)

    elif (msgType == "sender_public_key"):
        global senderKey
        senderKey = rsa.PublicKey.load_pkcs1(x.get("content").encode())


    elif (msgType == "message"):

        message = x.get("content")
        decodedMessage = base64.b64decode(message)
        message = rsa.decrypt(decodedMessage, privKey).decode()

        censoredMessage = pf.censor(message)
        messageCache.append(censoredMessage)
        print("\n\nReceived Message:\n-----\n"+censoredMessage+"\n-----\n\n")
    





    elif (msgType == "fin"):
        print("Terminating connection")
    
    # sends an ACK packet back to confirm the data was received
    data = {"type": "ack"}
    
    # calculates checksum and puts it in json object
    checksumVal = checksum_calculator(data)
    # append checksum to json
    data['checksum'] = checksumVal

    jsonData = json.dumps(data)
    sock.sendto(jsonData.encode(), address)




######### MAIN PART OF CODE #########

localUsername = "Marcus"

responseMessage = str(input("Please enter a message to respond with (optional): "))
# Sets a default response message if user chooses to not enter a response message
# it will use this message if not.
if (responseMessage == ""):
    responseMessage = "\n\nThank you for your message!\n\n"


global senderKey

## Generates a new RSA private and public key
pubKey, privKey = rsa.newkeys(2048)

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

serverSocket.bind(('127.0.0.1', 12000))


# Client that's sending messages to it currently
global client

# Message cache used to store all greetings received by people, 
global messageCache
messageCache = []


print("Started receiver server")

while True:
    # client set to null
    client = ()
##### A connection is initiated, the client is set

    try:
        receiveData(serverSocket, "sync")
    except KeyboardInterrupt:
        break
    except:
        continue

#### Encryption public key is received
    try:
        receiveData(serverSocket, "sender_public_key")
    except KeyboardInterrupt:
        break
    except:
        continue

### Sending our own encryption public key
    # Converts public key to PEM format as bytes
    pubKeyAsPackets = pubKey.save_pkcs1().decode()
    data = {"type": "recipient_public_key", "content": pubKeyAsPackets }
    
    try:
        sendData(serverSocket, data)
        print("sent our public key")
    except KeyboardInterrupt:
        break
    except:
        continue

#### Our username is requested
    try:
        receiveData(serverSocket, "request_username")
    except KeyboardInterrupt:
        break
    except:
        continue

#### Sending our username
    encryptedUsername = rsa.encrypt(localUsername.encode(), senderKey)
    encryptedUsername = base64.b64encode(encryptedUsername)
    encryptedUsername = str(encryptedUsername, "latin-1")
    data = {"type": "recipient_username", "content": encryptedUsername}
    try:
        sendData(serverSocket, data)
    except KeyboardInterrupt:
        break
    except:
        continue

#### A message is received
    try:
        receiveData(serverSocket, "message")
    except KeyboardInterrupt:
        break
    except:
        continue

#### Replying with our own response message
    
    message = rsa.encrypt(responseMessage.encode(), senderKey)
    message = base64.b64encode(message)
    message = str(message, "latin-1")

    data = {"type": "message", "content": message}
    try:
        sendData(serverSocket, data)
    except KeyboardInterrupt:
        break
    except:
        continue

#### Ending communication with client
    try:
        receiveData(serverSocket, "fin")
    except KeyboardInterrupt:
        break
    except:
        print("closed")
        continue

serverSocket.close()
print("\n\n\n\nCached Greetings:\n")

for i in range(len(messageCache)):
    print(messageCache[i])

print("\n\nEnd of program")
