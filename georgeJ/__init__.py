import re
import sh
import argparse
from kubernetes import client, config
from pick import pick
import json

class Pod:
    def __init__(self, name, namespace, node, containers):
        self.name = name
        self.namespace = namespace
        self.node = node
        self.containers = containers

class GeorgeJ:
    def __init__(self, use_tsh):
        config.load_kube_config()
        self.kube_v1 = client.CoreV1Api()
        self.use_tsh = use_tsh
        if use_tsh:
            self.ssh = sh.tsh.ssh.bake('-l', 'root')
        else:
            self.ssh = sh.ssh.bake()

    def fetch_filtered_pods(self, regex):
        pod_list = self.kube_v1.list_pod_for_all_namespaces(watch=False).items
        pod_pattern = re.compile(regex)
        pods = [
            Pod(
                name=pod.metadata.name,
                namespace=pod.metadata.namespace,
                node=pod.spec.node_name,
                containers=[{
                    "name": container.name,
                    "id": re.sub(r'^docker://','', container.container_id),
                } for container in pod.status.container_statuses],
            )
            for pod in pod_list if pod_pattern.match(pod.metadata.name)
        ]
        return pods

    def can_be_reached(self, node):
        if self.use_tsh:
            for line in sh.tsh.ls(_iter=True):
                if node in line:
                    return True
            return False
        else:
            return True

    def get_docker_id_from(self, node, container):
        docker_inspect_json = json.loads(str(self.ssh(node, 'sudo', 'docker', 'inspect', container["id"])))
        container_pid = docker_inspect_json[0]["State"]["Pid"]
        return container_pid

    def get_interfaces_nsenter(self, pid, node):
        cmd_result = self.ssh(node, 'sudo', 'nsenter', '-t', pid, '-n', 'ip', '-br', 'a')

        ip_results = [re.sub(' +', ' ',line).rstrip().split(' ') for line in cmd_result]
        cleanup_ip_results = [ ]
        for ip_result in ip_results :
            # 2 - no ip, 3 - single ip, 4 dual stack
            if (len(ip_result) < 2):
                continue

            status = ip_result[1]
            if status == "DOWN":
                continue

            cleanup_ip_results.append({'name': re.sub('@.*','', ip_result[0]), 'status': status})

        return cleanup_ip_results

    def filter_interfaces(self, regex, interfaces):
        interfaces_pattern = re.compile(regex)
        filtered_interfaces = [interface for interface in interfaces if interfaces_pattern.match(interface["name"])]
        return filtered_interfaces

    def pick_interface(self, interfaces):
        if len(interfaces) == 1:
            return interfaces[0]["name"]
        else:
            interfaces = [{ 'name':"any" }] + interfaces
            interface, index = pick(interfaces, "which interface", indicator='->')
            return interface["name"]

    def start_wireshark_nsenter(self, pid, node, interface):
        tcpdump_params = [
            '-w', '-',       # print to stdout
            '-lUn',          # list interfaces, buffer output, do not convert address to names
            '-i', interface, # interface name
        ]

        tcpdump_ns_enter = self.ssh.bake(node, 'sudo', 'nsenter', '-t', pid, '-n', 'tcpdump')

        sh.wireshark(tcpdump_ns_enter(*tcpdump_params, _piped=True), '-k', '-i', '-')


def pick_pod_from(pods):
    if len(pods) == 1:
        return pods[0]
    else:
        pod, index = pick([f'{pod.name} @ {pod.node}' for pod in pods], "which pod", indicator='->')
        return pods[index]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pod', default='', help='regex for filtering pods (default .*)')
    parser.add_argument('--interface', default='any', help='regex for interface or use "any" (default any)')
    parser.add_argument('-tsh', action='store_true', default=False, help='use tsh way')

    podregex = parser.parse_args().pod
    interface_regex = parser.parse_args().interface
    use_tsh = parser.parse_args().tsh

    g = GeorgeJ(use_tsh)

    pods = g.fetch_filtered_pods(podregex)
    if len(pods) == 0:
        print('no pods matched your regex')
        exit(1)
    pod = pick_pod_from(pods)

    container = pod.containers[0]

    if not g.can_be_reached(pod.node):
        print("node can't be reached exiting")
        exit(2)

    container_pid = g.get_docker_id_from(pod.node, container)
    interfaces = g.get_interfaces_nsenter(container_pid, pod.node)

    if interface_regex == "any":
        interface = "any"
    else:
        filtered_interfaces = g.filter_interfaces(interface_regex, interfaces)
        if len(filtered_interfaces) == 0:
            print('no interfaces matched your regex')
            exit(1)
        interface = g.pick_interface(filtered_interfaces)

    print(f'start sniffing interface {interface} of container {container["name"]} in pod {pod.name} on node {pod.node}')

    try:
        g.start_wireshark_nsenter(container_pid, pod.node, interface)
    except KeyboardInterrupt:
        print(f'interrputed')

if __name__ == '__main__':
    main()
