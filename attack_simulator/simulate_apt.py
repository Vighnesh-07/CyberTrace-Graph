import argparse
import sys
import json
import os
from collections import Counter
from attack_simulator.scenarios.dns_tunneling import DNSTunnelingScenario
from junction_nodes.common.kafka_producer import KafkaEventProducer
from junction_nodes.common.config import KafkaConfig

def print_summary(events):
    print("\n\033[1m\033[92mSimulation Complete\033[0m")
    print("-" * 30)
    print(f"Total events generated: {len(events)}")
    
    malicious = [e for e in events if getattr(e, 'mitre_tactic', None)]
    print(f"\033[91mMalicious events: {len(malicious)}\033[0m")
    
    types = Counter([e.event_type.value for e in events])
    print("\nEvent Types:")
    for k, v in types.items():
        print(f"  - {k}: {v}")

def main():
    parser = argparse.ArgumentParser(description="CyberTrace-Graph - Attack Simulator")
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    dns_parser = subparsers.add_parser("dns-tunnel", help="Simulate DNS tunneling attack")
    dns_parser.add_argument("--duration", type=int, default=300, help="Simulation duration in seconds")
    dns_parser.add_argument("--c2-domain", type=str, default="data.evil-c2-server.xyz", help="C2 Domain")
    dns_parser.add_argument("--output", type=str, choices=["json", "kafka"], default="json", help="Output destination")
    
    kill_chain_parser = subparsers.add_parser("kill-chain", help="Simulate multi-stage lateral movement kill chain")
    kill_chain_parser.add_argument("--duration", type=int, default=300, help="Simulation duration in seconds")
    kill_chain_parser.add_argument("--output", type=str, choices=["json", "kafka"], default="json", help="Output destination")
    
    ransomware_parser = subparsers.add_parser("ransomware", help="Simulate ransomware attack")
    ransomware_parser.add_argument("--duration", type=int, default=60, help="Simulation duration in seconds")
    ransomware_parser.add_argument("--output", type=str, choices=["json", "kafka"], default="json", help="Output destination")

    portscan_parser = subparsers.add_parser("port-scan", help="Simulate a fast port scan")
    portscan_parser.add_argument("--duration", type=int, default=60, help="Simulation duration in seconds")
    portscan_parser.add_argument("--output", type=str, choices=["json", "kafka"], default="json", help="Output destination")

    creddump_parser = subparsers.add_parser("cred-dump", help="Simulate LSASS credential dumping")
    creddump_parser.add_argument("--duration", type=int, default=60, help="Simulation duration in seconds")
    creddump_parser.add_argument("--output", type=str, choices=["json", "kafka"], default="json", help="Output destination")
    
    list_parser = subparsers.add_parser("list", help="List available scenarios")
    
    args = parser.parse_args()
    
    if args.command == "list":
        print("\033[1mAvailable Scenarios:\033[0m")
        print("  - dns-tunnel : Simulates data exfiltration via DNS queries")
        print("  - kill-chain : Simulates a 4-stage lateral movement attack")
        print("  - ransomware : Simulates a ransomware infection with shadow copy deletion")
        print("  - port-scan  : Simulates a rapid port scan against a host")
        print("  - cred-dump  : Simulates LSASS credential dumping")
        sys.exit(0)
        
    elif args.command in ["dns-tunnel", "kill-chain", "ransomware", "port-scan", "cred-dump"]:
        if args.command == "dns-tunnel":
            scenario = DNSTunnelingScenario(c2_domain=args.c2_domain)
        elif args.command == "kill-chain":
            from attack_simulator.scenarios.kill_chain import KillChainScenario
            scenario = KillChainScenario()
        elif args.command == "ransomware":
            from attack_simulator.scenarios.ransomware import RansomwareScenario
            scenario = RansomwareScenario()
        elif args.command == "port-scan":
            from attack_simulator.scenarios.port_scan import PortScanScenario
            scenario = PortScanScenario()
        elif args.command == "cred-dump":
            from attack_simulator.scenarios.cred_dump import CredDumpScenario
            scenario = CredDumpScenario()
            
        events = scenario.generate_events(duration_seconds=args.duration)
        
        if args.output == "json":
            os.makedirs(os.path.join(os.path.dirname(__file__), "output"), exist_ok=True)
            output_file = os.path.join(os.path.dirname(__file__), "output", f"{args.command.replace('-', '_')}_events.json")
            with open(output_file, "w") as f:
                json.dump([json.loads(e.model_dump_json()) for e in events], f, indent=2)
            print(f"\033[94mSaved events to {output_file}\033[0m")
            
        elif args.output == "kafka":
            config = KafkaConfig()
            producer = KafkaEventProducer(config)
            print("\033[93mSending events to Kafka...\033[0m")
            for e in events:
                topic = "apt.events.dns"
                if e.event_type in ["AUTH_LOGIN", "AUTH_FAILURE"]:
                    topic = "apt.events.auth"
                elif e.event_type == "NETWORK_CONNECTION":
                    topic = "apt.events.network"
                elif e.event_type == "PROCESS_CREATION":
                    topic = "apt.events.endpoint"
                producer.produce(topic, e)
            producer.flush()
            print("\033[94mFinished sending to Kafka.\033[0m")
            
        print_summary(events)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
