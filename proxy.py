import sys
import socket
import threading

#1
HEX_FILTER = ''.join([(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])

def hexdump(src, lenght=16, show=True):
    #2
    if isinstance(src, bytes):
        src = src.decode()
    results = list()
    for i in range (0, len(src), lenght):
        #3
        word = str(src[i:i+lenght])

        #4
        printable = word.translate(HEX_FILTER)
        hexa = ' '.join([f'{ord(c):02X}' for c in word])
        hexwidth = lenght*3

        #5
        results.append(f'{i:04x} {hexa:<{hexwidth}} {printable}')
    if show:
        for line in results:
            print(line)
    else:
        return results
#6
def receive_from(connection):
    buffer = b""
    #7
    connection.settimeout(5)
    try:
        while True:
            #8
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except Exception as e:
        pass
    return buffer

"""
request_handler() & response_handler() -> helps us if we  want to modify the response or request packets before the proxy sends them on their way

Inside these functions, you can modify the packet contents, perform 
fuzzing tasks, test for authentication issues or [...]

This can be useful, for example, if you find plaintext user credentials being sent and want to try to elevate privileges on an application by 
passing in admin instead of your own username.
"""

def request_handler(buffer):
    # perform packet modifications
    return buffer

def response_handler(buffer):
    # perform packet modifications
    return buffer    

#This function contains the bulk of the logic for our proxy

def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #9
    remote_socket.connect((remote_host, remote_port))
    #10
    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)

    #11
    remote_buffer = response_handler(remote_buffer)
    if len(remote_buffer):
        print("[<==] Sending %d bytes to localhost." % len(remote_buffer))
        client_socket.send(remote_buffer)

    while True:
        local_buffer = receive_from(client_socket)
        if len(local_buffer):
            line = "[==>]Received %d bytes from localhost." % len(local_buffer)
            print(line)
            hexdump(local_buffer)
            
            local_buffer = request_handler(local_buffer)
            remote_socket.send(local_buffer)
            print("[==>] Sent to remote.")

        remote_buffer = receive_from(remote_socket)
        if len(remote_buffer):
            print("[<==] Received %d bytes from remote." % len(remote_buffer))
            hexdump(remote_buffer)

            remote_buffer = response_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print("[<==] Sent to localhost.")
        #12
        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print("[*] No more data. Closing connections.")
            break

# this function is able to set up & manage the connection

def server_loop(local_host, local_port,remote_host, remote_port, receive_first):
    #13
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        #14
        server.bind((local_host, local_port))
    except Exception as e:
        print('problem on bind: %r' % e)
        
        print("[!!] Failed to listen on %s:%d" % (local_host, local_port))
        print("[!!] Check for other listening sockets or correct permissions.")
        sys.exit(0)

    print("[*] Listening on %s:%d" % (local_host, local_port))
    server.listen(5)

    #15
    while True:
        client_socket, addr = server.accept()
        # print out the local connection information
        line = "> Received incoming connection from %s:%d" % (addr[0], addr[1])
        print(line)
        # start a thread to talk to the remote host

        #16
        proxy_thread = threading.Thread(target=proxy_handler, args=(client_socket, remote_host, remote_port, receive_first))
        proxy_thread.start()

def main():
    if len(sys.argv[1:]) != 5:
        print("Usage: ./proxy.py [localhost] [localport]", end='')
        print("[remotehost] [remoteport] [receive_first]")
        print("Example: ./proxy.py 127.0.0.1 9000 10.12.132.1 9000 True")
        sys.exit(0)

    local_host = sys.argv[1]
    local_port = int(sys.argv[2])
    
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])
    
    receive_first = sys.argv[5]
    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False
    
    server_loop(local_host, local_port, remote_host, remote_port, receive_first)

if __name__ == '__main__':
    main()



'''
to start the code example

python proxy.py 192.168.1.203 21 ftp.sun.ac.za 21 Tru

port 21 - requires root
linux add "sudo"
'''



"""
the moving part of proxy.py are 4 fucntions

hexdump() -> to display the communication between the local and remote machines to the console
receive_from() -> to receive data from an incoming socket from either the local or remote machine
proxy_handler() -> to manage the traffic direction between remote and local machines
server_loop() ->  to set up a listening socket and pass it to our proxy_handler()


1.
we create the HEXFILTER string  that contains ASCII printable characters, if one exists, or a dot (.) if such a representation doesn’t exis 

The list comprehension used to create the string employs a Boolean short-circuit technique
for each integer in the range of 0 to 255, if the length of the corresponding 
character equals 3, we get the character (chr(i)). 
Otherwise, we get a dot (.). Then we join that list into a string

2.
when we create the hexdump() we make sure we have a string, decoding the bytes if a byte string was passed in

3.
Then we grab a piece of the string to dump and put it into the word variable

4.
We use the translate built-in function to substitute the string 
representation of each character for the corresponding character in the raw 
string (printable)

Likewise, we substitute the hex representation of the 
integer value of every character in the raw string (hexa)

5.
we create a new array to hold the strings, result, that contains the hex value of the index 
of the first byte in the word, the hex value of the word, and its printable representation

N.B.
This function provides us with a way to watch the communication going 
through the proxy in real time

6.
For receiving both local and remote data, we pass in the socket object 
to be used. We create an empty byte string, buffer, that will accumulate 
responses from the socket

7.
By default, we set a five-second timeout, which 
might be aggressive if you’re proxying traffic to other countries or over lossy 
networks, so increase the timeout as necessary!!!

8.
We set up a loop to read response data into the buffer until there’s no more data or we time out. 
Finally, we return the buffer byte string to the caller, which could be either 
the local or remote machine.

9.
we connect to the remote host

10.
Then we check to make sure we don’t 
need to first initiate a connection to the remote side and request data 
before going into the main loop

N.B.
Some server daemons will expect you to do this (FTP servers typically send a banner first, for example). 
We then use the receive_from function for both sides of the communication. It accepts 
a connected socket object and performs a receive. We dump the contents of 
the packet so that we can inspect it for anything interesting.

11.
we hand the output to the response_handler() function  and then send the received buffer to the local client

The rest of the proxy code is straightforward: we 
set up our loop to continually read from the local client, process the data, 
send it to the remote client, read from the remote client, process the data, 
and send it to the local client until we no longer detect any data

12.
When 
there’s no data to send on either side of the connection, we close both 
the local and remote sockets and break out of the loop.

13.
The server_loop function creates a socket

14.
which we bind it to the local host & listens

15.
when a fresh connection request comes in, we hand it off to the proxy_handler in a new thread

16.
the thread  does all of the sending and receiving of juicy bits to either side of the data stream






"""