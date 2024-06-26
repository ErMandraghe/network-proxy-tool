# network-proxy-tool
This Python script sets up a network proxy to intercept and manipulate traffic between a local client and a remote server


#HOW TO USE stepbystep

Here's a step-by-step guide on how to use the provided Python code to set up and use a network proxy:

1. **Setup Environment:**
   - Ensure you have Python installed on your system.
   - Save the provided code as `proxy.py` in a directory of your choice.

2. **Understand Command-line Arguments:**
   - The script requires five command-line arguments:
     - `localhost`: The local host IP address.
     - `localport`: The local port number.
     - `remotehost`: The remote host IP address.
     - `remoteport`: The remote port number.
     - `receive_first`: Boolean indicating whether to receive data from the remote host first.

3. **Start the Proxy:**
   - Open a terminal or command prompt.
   - Navigate to the directory where `proxy.py` is saved.

4. **Run the Script:**
   - Use the following command format:
     ```
     python proxy.py [localhost] [localport] [remotehost] [remoteport] [receive_first]
     ```
     Replace `[localhost]`, `[localport]`, `[remotehost]`, `[remoteport]`, and `[receive_first]` with your desired values.

5. **Example Usage:**
   - For instance, to set up a proxy where the local host is `127.0.0.1`, the local port is `9000`, the remote host is `10.12.132.1`, the remote port is `9000`, and to receive data first, you would run:
     ```
     python proxy.py 127.0.0.1 9000 10.12.132.1 9000 True
     ```
   - If the remote port requires root access (such as port `21` for FTP), you may need to run the script with elevated privileges (e.g., `sudo python proxy.py ...` on Linux).

6. **Monitor Connections:**
   - Once the script is running, it will start listening for incoming connections on the specified local host and port.
   - It will display information about incoming connections in the terminal, including the IP address and port of the client.

7. **Interact with the Proxy:**
   - Once a connection is established, the proxy will intercept and forward traffic between the local client and the remote server.
   - You can observe the communication between the local and remote machines in real-time, as the `hexdump` function displays the data exchanged.

8. **Customize Behavior (Optional):**
   - You can modify the `request_handler` and `response_handler` functions within the code to customize how packets are handled before being sent on their way. This can be useful for tasks like packet modification, fuzzing, or testing for authentication issues.

9. **Terminate the Proxy:**
   - To stop the proxy, you can typically use `Ctrl + C` in the terminal where the script is running. This will gracefully close the connections and terminate the script execution.

10. **Explore Further:**
    - Feel free to explore the code further to understand its inner workings and adapt it to your specific needs. You can also refer to the provided comments within the code for additional insights.
