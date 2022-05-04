import socket
import getpass
import json
import datetime
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
    sock.sendto(jsonData.encode(), UDP_ADDRESS)
    
    try:
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

    # if an acknowledgement message is received then we know the data reached the recipient correctly
        if (msgType == "ack"):
            print("ACK packet received")
        else:
            print("No ACK packet received")
            raise socket.error
    
    except:
        print("No ACK packet received")
        raise socket.error
    

def receiveData(sock, expectedMessageType):
    # Attempts to receive data from recipient
    data, server = sock.recvfrom(BUFFER_SIZE)
    x = json.loads(data)
    

    # Checks if the received packet has a checksum as it was optional for this implementation
    # if the checksums do not match then it will raise an exception
    if (x.get("checksum") is not None):
        if (checksum_calculator(x) != int(x.get("checksum"))):
            print("Checksums do not match, need the packet resent")
            raise Exception()
        else:
            print("Checksums match")

    msgType = x.get("type")

    print("Packet Type Received: ", msgType)

    if (msgType != expectedMessageType):
        print("Incorrect packet type received")
        raise Exception()

    if (msgType == "recipient_public_key"):
        global recipientKey
        recipientKey =  rsa.PublicKey.load_pkcs1(x.get("content").encode())
    elif (msgType == "recipient_username"):
        global recipientUsername
        recipientUsername = x.get("content")
        decodedUsername = base64.b64decode(recipientUsername)
        recipientUsername = rsa.decrypt(decodedUsername, privKey).decode()

    elif (msgType == "message"):

        message = x.get("content")
        decodedMessage = base64.b64decode(message)
        message = rsa.decrypt(decodedMessage, privKey).decode()
        
        censoredMessage = pf.censor(message)
        print("\n\nReceived Message:\n-----\n"+ censoredMessage +"\n-----\n\n")
    
    # sends an ACK packet back to confirm the data was received
    data = {"type": "ack"}
    # calculates checksum and puts it in json object
    checksumVal = checksum_calculator(data)
    # append checksum to json
    data['checksum'] = checksumVal

    jsonData = json.dumps(data)
    sock.sendto(jsonData.encode(), UDP_ADDRESS)



localUsername = getpass.getuser()

## Generates a new RSA private and public key
pubKey, privKey = rsa.newkeys(2048)


# Defining global variables
global recipientKey
global recipientUsername


recipientList = ""
while (recipientList == ""):
    recipientList = str(input("Enter your list of IP addresses you want to send greetings to with commas separating the addresses (e.g '127.0.0.1, 127.0.0.2, 127.0.0.3' ):\n"))

recipientList = recipientList.replace(" ", "")
recipientList = recipientList.split(",")
print(recipientList)

# This custom Message is optional and will be taken at the start of program execution
customMessage = str(input("Please enter your custom message (optional): "))
while ( len(customMessage.encode()) > 200 ):
    customMessage = str(input("Message can not be over 200 bytes long (approximately 200 characters)\nPlease enter your message (optional): "))



# Attempts to send the greeting to each IP address that the user entered
for i in range(len(recipientList)):

###### Creating socket for current IP

    # Change the IP Address to the list of IPs
    UDP_IP_ADDRESS = recipientList[i]
    try:
        socket.inet_aton(UDP_IP_ADDRESS)
        # IP is legal if passes
    except socket.error:
        # Not legal
        print("IP is not valid")
        # continue, used to end the for loop iteration for the IP entered
        continue

    # Setting the Receiver address and establishing a socket connection, setting a timeout to 1 second
    UDP_PORT_NO = 12000
    UDP_ADDRESS = (UDP_IP_ADDRESS, UDP_PORT_NO)
    socket.setdefaulttimeout(5) # 5 second timeout
    clientSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)



###### Synchronize packet for initiating connection
    print("\n\nInitialising connection")
    data = {"type": "sync"}

    # Tries to send the json payload to the address
    try:
        sendData(clientSock, data)
    except socket.timeout as inst:
        # If the request times out it attempts to resend the data once then will move on to the next address if that fails
        print("Request timed out - Resending Data")
        try:
            sendData(clientSock, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except socket.error:
        print("Error with connection - Resending Data")
        try:
            sendData(clientSock, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except:
        print("Unknown error occurred, moving on to next IP address\n\n")
        clientSock.close()
        continue


###### Exchange Public keys between receiver and sender
    print("Exchanging public keys")
    # Converts public key to PEM format as bytes then decodes it to string
    pubKeyAsPackets = pubKey.save_pkcs1().decode()
    data = {"type": "sender_public_key", "content": pubKeyAsPackets }

    # Tries to send the json payload to the address
    try:
        sendData(clientSock, data)
    except socket.timeout as inst:
        # If the request times out it attempts to resend the data once then will move on to the next address if that fails
        print("Request timed out - Resending Data")
        try:
            sendData(clientSock, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except socket.error:
        print("Error with connection - Resending Data")
        try:
            sendData(clientSock, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except:
        print("Unknown error occurred, moving on to next IP address\n\n")
        clientSock.close()
        continue


    try:
        receiveData(clientSock, "recipient_public_key")
    except socket.timeout as inst:
        print("Socket timed out, trying again")
        try:
            receiveData(clientSock, "recipient_public_key")
        except:
            print("An Error occurred receiving data from the current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except:
        print("An error occurred, trying again")
        try:
            receiveData(clientSock, "recipient_public_key")
        except:
            print("An Error occurred receiving data from the current IP, moving on to next address\n\n")
            clientSock.close()
            continue




###### Sending a request for the recipient username
    print("Asking for recipient username")
    data = {"type": "request_username"}
    # Tries to send the json payload to the address
    try:
        sendData(clientSock, data)
    except socket.timeout as inst:
        # If the request times out it attempts to resend the data once then will move on to the next address if that fails
        print("Request timed out - Resending Data")
        try:
            sendData(clientSock, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except socket.error:
        print("Error with connection - Resending Data")
        try:
            sendData(clientSock, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except:
        print("Unknown error occurred, moving on to next IP address\n\n")
        clientSock.close()
        continue


#### Receiving recipient username
    try:
        receiveData(clientSock, "recipient_username")
    except socket.timeout as inst:
        print("Socket timed out, trying again")
        try:
            receiveData(clientSock, "recipient_username")
        except:
            print("An Error occurred receiving data from the current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except:
        print("An error occurred, trying again")
        try:
            receiveData(clientSock, "recipient_username")
        except:
            print("An Error occurred receiving data from the current IP, moving on to next address\n\n")
            clientSock.close()
            continue

    print("Recipient username is: "+recipientUsername)

###### Sending the greeting message

    # Checks time to put in correct greeting of Good Morning, Good Afternoon or Good Evening
    if datetime.time(4, 00, 00) < datetime.datetime.now().time() <= datetime.time(11, 00, 00):
        greeting = "Good Morning "
    elif datetime.time(11, 00, 00) < datetime.datetime.now().time() <= datetime.time(18, 00, 00):
        greeting = "Good Afternoon "
    else:
        greeting = "Good Evening "
    
    message = greeting + recipientUsername+ ".\n"+customMessage + "\n\nFrom: " +localUsername
    

    print("Sending Message: \n"+message+"\n")
    
    message = rsa.encrypt(message.encode(), recipientKey)
    message = base64.b64encode(message)
    message = str(message, "latin-1")

    data = {"type": "message", "content":message}

    # Tries to send the json payload to the address
    try:
        sendData(clientSock, data)
    except socket.timeout as inst:
        # If the request times out it attempts to resend the data once then will move on to the next address if that fails
        print("Request timed out - Resending Data")
        try:
            sendData(clientSock, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except socket.error:
        print("Error with connection - Resending Data")
        try:
            sendData(clientSock, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except:
        print("Unknown error occurred, moving on to next IP address\n\n")
        clientSock.close()
        continue

#### Receiving a response message
    try:
        receiveData(clientSock, "message")
    except socket.timeout as inst:
        print("Socket timed out, trying again")
        try:
            receiveData(clientSock, "message")
        except:
            print("An Error occurred receiving data from the current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except:
        print("An error occurred, trying again")
        try:
            receiveData(clientSock, "message")
        except:
            print("An Error occurred receiving data from the current IP, moving on to next address\n\n")
            clientSock.close()
            continue

##### Ending the connection with the current receipient as the message has been sent successfully
    data = {"type": "fin"}
    # Tries to send the json payload to the address
    try:
        sendData(clientSock, data)
    except socket.timeout as inst:
        # If the request times out it attempts to resend the data once then will move on to the next address if that fails
        print("Request timed out - Resending Data")
        try:
            sendData(clientSock, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except socket.error:
        print("Error with connection - Resending Data")
        try:
            sendData(clientSock, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except:
        print("Unknown error occurred, moving on to next IP address\n\n")
        clientSock.close()
        continue



    clientSock.close()

    print("Terminated connection with recipient - " + str(UDP_IP_ADDRESS))


print("Finished sending greetings")