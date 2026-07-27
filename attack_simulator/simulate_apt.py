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
    
    list_parser = subparsers.add_parser("list", help="List available scenarios")
    
    args = parser.parse_args()
    
    if args.command == "list":
        print("\033[1mAvailable Scenarios:\033[0m")
        print("  - dns-tunnel : Simulates data exfiltration via DNS queries")
        sys.exit(0)
        
    elif args.command == "dns-tunnel":
        scenario = DNSTunnelingScenario(c2_domain=args.c2_domain)
        events = scenario.generate_events(duration_seconds=args.duration)
        
        if args.output == "json":
            os.makedirs(os.path.join(os.path.dirname(__file__), "output"), exist_ok=True)
            output_file = os.path.join(os.path.dirname(__file__), "output", "dns_tunnel_events.json")
            with open(output_file, "w") as f:
                json.dump([json.loads(e.model_dump_json()) for e in events], f, indent=2)
            print(f"\033[94mSaved events to {output_file}\033[0m")
            
        elif args.output == "kafka":
            config = KafkaConfig()
            producer = KafkaEventProducer(config)
            print("\033[93mSending events to Kafka...\033[0m")
            for e in events:
                producer.produce("apt.events.dns", e)
            producer.flush()
            print("\033[94mFinished sending to Kafka.\033[0m")
            
        print_summary(events)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
