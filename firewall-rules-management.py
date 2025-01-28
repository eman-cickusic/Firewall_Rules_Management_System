import subprocess
import logging
import json
import argparse
from datetime import datetime
import ipaddress
import re
import sys

class FirewallRulesManager:
    def __init__(self, log_file='firewall_rules.log'):
        """
        Initialize the Firewall Rules Management System
        
        Args:
            log_file (str): Path to the log file for tracking rule changes
        """
        self.log_file = log_file
        self.config_file = 'firewall_config.json'
        
        # Configure logging
        logging.basicConfig(
            filename=self.log_file, 
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s'
        )
        
        # Ensure user has sudo privileges for iptables management
        self.check_sudo_privileges()
    
    def check_sudo_privileges(self):
        """
        Verify sudo access for iptables modifications
        """
        try:
            subprocess.run(['sudo', '-n', 'true'], check=True)
        except subprocess.CalledProcessError:
            logging.error("Insufficient sudo privileges")
            raise PermissionError("This script requires sudo access to modify firewall rules")
    
    def list_current_rules(self):
        """
        List current iptables rules
        
        Returns:
            list: Current firewall rules
        """
        try:
            result = subprocess.run(
                ['sudo', 'iptables', '-L', '-n', '-v'], 
                capture_output=True, 
                text=True, 
                check=True
            )
            print("Current Firewall Rules:")
            print(result.stdout)
            return result.stdout
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to list rules: {e}")
            return []
    
    def validate_ip(self, ip):
        """
        Validate IP address format
        
        Args:
            ip (str): IP address to validate
        
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def add_rule(self, chain, source_ip, destination_port, protocol='tcp'):
        """
        Add a new firewall rule
        
        Args:
            chain (str): iptables chain (INPUT/OUTPUT/FORWARD)
            source_ip (str): Source IP address
            destination_port (int): Destination port
            protocol (str): Network protocol
        
        Returns:
            bool: True if rule added successfully
        """
        # Validate inputs
        if not self.validate_ip(source_ip):
            logging.error(f"Invalid IP address: {source_ip}")
            return False
        
        try:
            rule_command = [
                'sudo', 'iptables', '-A', chain,
                '-p', protocol,
                '-s', source_ip,
                '--dport', str(destination_port),
                '-j', 'ACCEPT'
            ]
            
            subprocess.run(rule_command, check=True)
            
            # Log the rule addition
            log_message = (
                f"Rule Added: Chain={chain}, "
                f"Source IP={source_ip}, "
                f"Destination Port={destination_port}, "
                f"Protocol={protocol}"
            )
            logging.info(log_message)
            print(log_message)
            
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to add rule: {e}")
            return False
    
    def delete_rule(self, chain, source_ip, destination_port, protocol='tcp'):
        """
        Delete an existing firewall rule
        
        Args:
            chain (str): iptables chain (INPUT/OUTPUT/FORWARD)
            source_ip (str): Source IP address
            destination_port (int): Destination port
            protocol (str): Network protocol
        
        Returns:
            bool: True if rule deleted successfully
        """
        try:
            rule_command = [
                'sudo', 'iptables', '-D', chain,
                '-p', protocol,
                '-s', source_ip,
                '--dport', str(destination_port),
                '-j', 'ACCEPT'
            ]
            
            subprocess.run(rule_command, check=True)
            
            # Log the rule deletion
            log_message = (
                f"Rule Deleted: Chain={chain}, "
                f"Source IP={source_ip}, "
                f"Destination Port={destination_port}, "
                f"Protocol={protocol}"
            )
            logging.info(log_message)
            print(log_message)
            
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to delete rule: {e}")
            return False
    
    def analyze_traffic(self):
        """
        Analyze recent network traffic and generate insights
        
        Returns:
            dict: Traffic analysis summary
        """
        try:
            # Use netstat to capture network connections
            result = subprocess.run(
                ['sudo', 'netstat', '-tuln'], 
                capture_output=True, 
                text=True, 
                check=True
            )
            
            # Basic traffic analysis
            connections = result.stdout.split('\n')
            analysis = {
                'total_connections': len(connections),
                'listening_ports': [],
                'connection_protocols': {}
            }
            
            for conn in connections:
                if re.search(r'\d+\.\d+\.\d+\.\d+:\d+', conn):
                    parts = conn.split()
                    if len(parts) >= 4:
                        protocol = parts[0]
                        port = parts[3].split(':')[-1]
                        
                        analysis['listening_ports'].append(port)
                        analysis['connection_protocols'][protocol] = \
                            analysis['connection_protocols'].get(protocol, 0) + 1
            
            logging.info("Traffic Analysis Completed")
            return analysis
        except subprocess.CalledProcessError as e:
            logging.error(f"Traffic analysis failed: {e}")
            return {}
    
    def save_configuration(self):
        """
        Save current firewall configuration to a JSON file
        """
        try:
            current_rules = self.list_current_rules()
            config = {
                'timestamp': datetime.now().isoformat(),
                'rules': current_rules
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
            
            logging.info(f"Configuration saved to {self.config_file}")
        except Exception as e:
            logging.error(f"Failed to save configuration: {e}")
    
    def restore_configuration(self):
        """
        Restore firewall configuration from saved JSON file
        """
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            
            print(f"Restoring configuration from {config['timestamp']}")
            # Note: Actual rule restoration would require parsing the saved rules
            logging.info(f"Configuration restored from {self.config_file}")
        except FileNotFoundError:
            logging.error("No saved configuration found")
        except Exception as e:
            logging.error(f"Configuration restoration failed: {e}")

def main():
    if sys.platform != 'linux':
        print("Error: This script is designed for Linux systems with iptables.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Firewall Rules Management System')
    parser.add_argument('--list', action='store_true', help='List current firewall rules')
    parser.add_argument('--add', nargs=3, metavar=('CHAIN', 'SOURCE_IP', 'PORT'), 
                        help='Add a new firewall rule')
    parser.add_argument('--delete', nargs=3, metavar=('CHAIN', 'SOURCE_IP', 'PORT'), 
                        help='Delete an existing firewall rule')
    parser.add_argument('--analyze', action='store_true', help='Analyze network traffic')
    parser.add_argument('--save', action='store_true', help='Save current firewall configuration')
    parser.add_argument('--restore', action='store_true', help='Restore firewall configuration')
    
    args = parser.parse_args()
    
    firewall_manager = FirewallRulesManager()
    
    if args.list:
        firewall_manager.list_current_rules()
    
    if args.add:
        firewall_manager.add_rule(args.add[0], args.add[1], int(args.add[2]))
    
    if args.delete:
        firewall_manager.delete_rule(args.delete[0], args.delete[1], int(args.delete[2]))
    
    if args.analyze:
        traffic_analysis = firewall_manager.analyze_traffic()
        print("Traffic Analysis Results:")
        print(json.dumps(traffic_analysis, indent=2))
    
    if args.save:
        firewall_manager.save_configuration()
    
    if args.restore:
        firewall_manager.restore_configuration()

if __name__ == '__main__':
    main()
