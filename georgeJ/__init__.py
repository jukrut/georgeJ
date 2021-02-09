import re
import sh
import argparse
from kubernetes import client, config
from pick import pick
import json

def fetch_all_pods():
    config.load_kube_config()
    v1 = client.CoreV1Api()
    return v1.list_pod_for_all_namespaces(watch=False).items


def filter_pods_by(regex, pod_list):
    pod_pattern = re.compile(regex)
    pods = [
        {
            'name': pod.metadata.name,
            'namespace': pod.metadata.namespace,
            'node': pod.spec.node_name,
            'containers': [ {"name":container.name, "id": re.sub(r'^docker://','', container.container_id)}for container in pod.status.container_statuses]
        }
        for pod in pod_list if pod_pattern.match(pod.metadata.name)
    ]
    return pods

def pick_pod_from(pods):
    if len(pods) == 1:
        return pods[0]
    else:
        pod, index = pick([f'{pod["name"]} @ {pod["node"]}' for pod in pods], "which pod", indicator='->')
        return pods[index]

def filter_container_by(regex, containers):
    container_pattern = re.compile(regex)
    filtered_containers = [container for container in containers if container_pattern.match(container["name"])]
    return filtered_containers

def pick_container_from(containers):
    if len(containers) == 1:
        return containers[0]
    else:
        container, index = pick([container["name"] for container in containers], "which container", indicator='->')
        return containers[index]

def can_be_reached(node):
    for line in sh.tsh.ls(_iter=True):
        if node in line:
            return True
    return False

def get_docker_id_from(node,container):
    ssh_on_node = sh.tsh.ssh.bake(f'root@{node}')
    docker_on_node = ssh_on_node.bake('docker')
    docker_inspect_json = json.loads(str(docker_on_node.inspect(container["id"])))
    container_pid = docker_inspect_json[0]["State"]["Pid"]
    return container_pid

def get_interfaces_nsenter(pid, node):
    ssh_on_node = sh.tsh.ssh.bake(f'root@{node}')
    ns_enter_for_container = ssh_on_node.bake('nsenter', '-t', pid, '-n')
    ip_results = [re.sub(' +', ' ',line).rstrip().split(' ') for line in ns_enter_for_container.ip('-br', 'a')]
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

def filter_interfaces(regex, interfaces):
    interfaces_pattern = re.compile(regex)
    filtered_interfaces = [interface for interface in interfaces if interfaces_pattern.match(interface["name"])]
    return filtered_interfaces

def pick_interface(interfaces):
    if len(interfaces) == 1:
        return interfaces[0]["name"]
    else:
        interfaces = [{ 'name':"any" }] + interfaces
        interface, index = pick(interfaces, "which interface", indicator='->')
        return interface["name"]

def start_wireshark_nsenter(pid, node, interface):
    ssh_on_node = sh.tsh.ssh.bake(f'root@{node}')
    tcpdump_ns_enter = ssh_on_node.bake('nsenter', '-t', pid, '-n').tcpdump
    wireshark = sh.wireshark.bake('-k', '-i', '-')

    tcpdump_params = [
        '-w', '-',       # print to stdout
        '-lUn',          # list interfaces, buffer output, do not convert address to names
        '-i', interface, # interface name
    ]

    wireshark(tcpdump_ns_enter(*tcpdump_params, _piped=True))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pod', default='.*', help='regex for filtering pods (default .*)')
    parser.add_argument('--container', default='.*', help='regex for filtering containers (default .*) or se "any" to select first container')
    parser.add_argument('--interface', default='.*', help='regex for filtering interfaces (default .*) or use "any" to listen on all interfaces')
    podregex = parser.parse_args().pod
    container_regex = parser.parse_args().container
    interface_regex = parser.parse_args().interface

    pod_list = fetch_all_pods()
    pods = filter_pods_by(podregex, pod_list)
    if len(pods) == 0:
        print('no pods matched your regex')
        exit(1)
    pod = pick_pod_from(pods)

    if container_regex == "any":
        container = pod["containers"][0]
    else:
        containers = filter_container_by(container_regex, pod["containers"])
        if len(containers) == 0:
            print('no containers matched your regex')
            exit(1)
        container = pick_container_from(containers)

    node = pod["node"]
    if(not can_be_reached(node)):
        print("node can't be reached exiting")
        exit(2)

    container_pid = get_docker_id_from(node, container)
    interfaces = get_interfaces_nsenter(container_pid, node)

    if interface_regex == "any":
        interface = "any"
    else:
        filtered_interfaces = filter_interfaces(interface_regex, interfaces)
        if len(filtered_interfaces) == 0:
            print('no interfaces matched your regex')
            exit(1)
        interface = pick_interface(filtered_interfaces)

    print(f'start sniffing interface {interface} of container {container["name"]} in pod {pod["name"]} on node {node}')

    try:
        start_wireshark_nsenter(container_pid, node, interface)
    except KeyboardInterrupt:
        print(f'interrputed')

if __name__ == '__main__':
    main()
