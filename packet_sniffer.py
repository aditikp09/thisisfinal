from scapy.all import sniff, TCP, IP
import threading
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)  # Create a logger instance

# List to store captured packet details
captured_packets = []

# Flag to indicate if code injection has been detected
code_injection_detected = False

# Packet callback function
def packet_callback(packet):
    global code_injection_detected
    if not code_injection_detected:
        try:
            if packet.haslayer(TCP) and packet.haslayer(IP):
                packet_info = f"{packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport} {packet[TCP].flags}"
                logger.info(f"Captured Packet: {packet_info}")
                captured_packets.append(packet_info)
                if len(captured_packets) > 10:
                    captured_packets.pop(0)
                # Check for code injection attempt
                if "__import__" in packet_info or "system" in packet_info:
                    logger.warning("Potential Code Injection Detected!")
                    code_injection_detected = True
        except Exception as e:
            logger.error(f"Error processing packet: {e}")

# Start packet sniffing in a separate thread
def start_sniffing():
    global code_injection_detected
    try:
        sniff(prn=packet_callback, filter="tcp", store=0, stop_filter=lambda x: code_injection_detected)
        if code_injection_detected:
            logger.info("Code injection detected. Stopping packet sniffing.")
    except Exception as e:
        logger.error(f"Error sniffing packets: {e}")

thread = threading.Thread(target=start_sniffing)
thread.daemon = True
thread.start()

def get_packets():
    return captured_packets

def execute_command(command):
    if "__import__" in command or "system" in command:
        logger.warning(f"Potential Code Injection Detected: {command}")
        return "Potential Code Injection Detected!", 400
    else:
        try:
            exec(command)
            logger.info(f"Executed Command: {command}")
            return "Command executed successfully"
        except Exception as e:
            logger.error(f"Error executing command: {command} - {e}")
            return str(e), 400
