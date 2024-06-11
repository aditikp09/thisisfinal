from flask import Flask, request, render_template
import logging
import packet_sniffer

app = Flask(__name__)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)  # Create a logger instance

# Vulnerable endpoint
@app.route('/execute', methods=['GET', 'POST'])
def execute():
    if request.method == 'POST':
        command = request.form['command']
        # Execute command
        result = packet_sniffer.execute_command(command)
        return result
    else:
        return render_template('index.html', packets=packet_sniffer.get_packets())

if __name__ == '__main__':
    app.run(debug=True)
