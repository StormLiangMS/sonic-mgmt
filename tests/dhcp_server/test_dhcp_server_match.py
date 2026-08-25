import contextlib
import ipaddress
import logging

import pytest

from tests.common import config_reload
from tests.common.dhcp_relay_utils import enable_sonic_dhcpv4_relay_agent, wait_dhcp_relay_ready  # noqa: F401
from tests.common.fixtures.split_vlan import apply_config_patch, generate_sub_vlans_config_patch
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until
from dhcp_server_test_common import DHCP_DEFAULT_LEASE_TIME, DHCP_MESSAGE_TYPE_ACK_NUM, \
    DHCP_MESSAGE_TYPE_DISCOVER_NUM, DHCP_MESSAGE_TYPE_REQUEST_NUM, DHCP_SERVER_CONFIG_TOOL_CLI, \
    DHCP_SERVER_CONFIG_TOOL_GCU, append_common_config_patch, append_match_config_patch, \
    apply_dhcp_server_config_gcu, clean_dhcp_server_config, create_dhcp_client_packet, create_match_config_patch, \
    dhcp_server_config as base_dhcp_server_config, empty_config_patch, generate_match_config_cli_commands, \
    send_and_verify, \
    send_release_packet, validate_dhcp_server_pkts, validate_no_dhcp_server_pkts, \
    verify_discover_and_request_then_release, verify_lease, wait_dhcp_server_ready


pytestmark = [
    pytest.mark.topology('mx'),
    pytest.mark.parametrize("relay_agent", ["isc-relay-agent", "sonic-relay-agent"]),
]


DEFAULT_REQUEST_EXPECTED_IP = object()
DHCP_SERVER_CONFIG_SETTLE_TIME = 3
DHCP_LEASE_STATE_TIMEOUT = 11


def _build_option60_option(value):
    return ("vendor_class_id", value.encode('utf-8'))


def _port_match_name(port_alias):
    return "port-{}".format(port_alias)


def _relay_types_for_agent(relay_agent):
    return ["sonic"] if relay_agent == "sonic-relay-agent" else ["isc-internal"]


def _get_connected_ptf_port_mapping(duthost, tbinfo):
    disabled_host_interfaces = tbinfo['topo']['properties']['topology'].get('disabled_host_interfaces', [])
    connected_ptf_ports_idx = sorted(
        int(interface) for interface in tbinfo['topo']['properties']['topology'].get('host_interfaces', [])
        if interface not in disabled_host_interfaces
    )
    dut_intf_to_ptf_index = duthost.get_extended_minigraph_facts(tbinfo)['minigraph_ptf_indices']
    connected_dut_intf_to_ptf_index = {
        dut_port: int(ptf_port_index)
        for dut_port, ptf_port_index in dut_intf_to_ptf_index.items()
        if int(ptf_port_index) in connected_ptf_ports_idx
    }
    return connected_ptf_ports_idx, connected_dut_intf_to_ptf_index


def _build_vlan_context(duthost, vlan_name, interface_prefix, members_with_ptf_idx, connected_ptf_ports_idx):
    running_config = duthost.get_running_config_facts()
    port_table = running_config.get('PORT', {})
    vlan_net = ipaddress.ip_network(address=interface_prefix, strict=False)
    gateway = interface_prefix.split('/')[0]
    vlan_hosts = [str(host) for host in vlan_net.hosts()]
    vlan_hosts_after_gateway = vlan_hosts[vlan_hosts.index(gateway) + 1:]
    pytest_require(vlan_hosts_after_gateway, 'Vlan {} does not have assignable IPv4 addresses'.format(vlan_name))
    return {
        'vlan_name': vlan_name,
        'gateway': gateway,
        'netmask': str(vlan_net.netmask),
        'hosts': vlan_hosts_after_gateway,
        'members': [
            {
                'name': member,
                'alias': port_table.get(member, {}).get('alias', member),
                'ptf_port_index': ptf_port_index
            }
            for member, ptf_port_index in members_with_ptf_idx
        ],
        'connected_ptf_port_indices': connected_ptf_ports_idx,
    }


def _select_client_mac_ptf_ports(vlan_context, send_ptf_port_index, count):
    mac_ptf_port_indices = [send_ptf_port_index] + [
        ptf_port_index
        for ptf_port_index in vlan_context['connected_ptf_port_indices']
        if ptf_port_index != send_ptf_port_index
    ]
    pytest_require(
        len(mac_ptf_port_indices) >= count,
        'Need at least {} connected PTF ports to source distinct client MACs'.format(count)
    )
    return mac_ptf_port_indices[:count]


def _get_lease_keys(duthost, vlan_name, client_mac):
    return duthost.shell(
        "sonic-db-cli STATE_DB KEYS 'DHCP_SERVER_IPV4_LEASE|{}|{}'".format(vlan_name, client_mac)
    )['stdout_lines']


def _assert_no_lease(duthost, vlan_name, client_mac):
    observed_lease = {'keys': []}

    def lease_exists():
        observed_lease['keys'] = _get_lease_keys(duthost, vlan_name, client_mac)
        return bool(observed_lease['keys'])

    pytest_assert(
        not wait_until(DHCP_LEASE_STATE_TIMEOUT, 1, 3, lease_exists),
        'Unexpected lease entry for client {} on {}: {}'.format(
            client_mac,
            vlan_name,
            observed_lease['keys']
        )
    )


def _wait_lease_absent(duthost, vlan_name, client_mac):
    pytest_assert(
        wait_until(
            DHCP_LEASE_STATE_TIMEOUT,
            1,
            1,
            lambda: not _get_lease_keys(duthost, vlan_name, client_mac)
        ),
        'Lease entry for client {} on {} was not released'.format(client_mac, vlan_name)
    )


def _wait_dhcp_server_config_applied(duthost):
    wait_dhcp_server_ready(duthost, initial_delay=DHCP_SERVER_CONFIG_SETTLE_TIME)


@contextlib.contextmanager
def dhcp_server_config(duthost, config_tool, config_to_apply):
    with base_dhcp_server_config(duthost, config_tool, config_to_apply):
        _wait_dhcp_server_config_applied(duthost)
        yield


def _restart_dhcp_server_container(duthost):
    duthost.shell('systemctl reset-failed dhcp_server.service')
    duthost.shell('systemctl restart dhcp_server.service')
    wait_dhcp_server_ready(duthost)


def _verify_client_assignment(
    duthost,
    ptfhost,
    ptfadapter,
    vlan_context,
    dut_port,
    send_ptf_port_index,
    client_mac_ptf_port_index,
    test_xid,
    expected_ip,
    option60_value=None,
    release_needed=True,
    request_includes_option60=True,
    request_expected_assigned_ip=DEFAULT_REQUEST_EXPECTED_IP
):
    if request_expected_assigned_ip is DEFAULT_REQUEST_EXPECTED_IP:
        request_expected_assigned_ip = expected_ip
    client_options = [_build_option60_option(option60_value)] if option60_value is not None else []
    request_client_options = client_options if request_includes_option60 else []
    return verify_discover_and_request_then_release(
        duthost=duthost,
        ptfhost=ptfhost,
        ptfadapter=ptfadapter,
        dut_port_to_capture_pkt=dut_port,
        ptf_port_index=send_ptf_port_index,
        ptf_mac_port_index=client_mac_ptf_port_index,
        test_xid=test_xid,
        dhcp_interface=vlan_context['vlan_name'],
        expected_assigned_ip=expected_ip,
        exp_gateway=vlan_context['gateway'],
        server_id=vlan_context['gateway'],
        net_mask=vlan_context['netmask'],
        release_needed=release_needed,
        discover_client_options=client_options,
        request_client_options=request_client_options,
        request_expected_assigned_ip=request_expected_assigned_ip
    )


@pytest.fixture(scope="module")
def match_test_context(duthost, tbinfo):
    vlan_brief = duthost.get_vlan_brief()
    first_vlan_name = list(vlan_brief.keys())[0]
    first_vlan_info = list(vlan_brief.values())[0]
    connected_ptf_ports_idx, connected_dut_intf_to_ptf_index = _get_connected_ptf_port_mapping(duthost, tbinfo)
    vlan_members_with_ptf_idx = [
        (member, connected_dut_intf_to_ptf_index[member])
        for member in first_vlan_info['members']
        if member in connected_dut_intf_to_ptf_index
    ]
    pytest_require(len(vlan_members_with_ptf_idx) >= 2, 'Expected at least two vlan members for MATCH testing')
    pytest_require(len(connected_ptf_ports_idx) >= 4, 'Expected at least four connected PTF ports for MATCH testing')
    vlan_context = _build_vlan_context(
        duthost,
        first_vlan_name,
        first_vlan_info['interface_ipv4'][0],
        vlan_members_with_ptf_idx,
        connected_ptf_ports_idx
    )
    pytest_require(len(vlan_context['hosts']) >= 8, 'Expected at least eight IPv4 hosts for MATCH testing')
    logging.info('match_test_context=%s', vlan_context)
    return vlan_context


@pytest.fixture
def match_mode_two_vlans(
    duthost,
    tbinfo,
    enable_sonic_dhcpv4_relay_agent,  # noqa: F811
    relay_agent
):
    vlan_brief = duthost.get_vlan_brief()
    first_vlan_name = list(vlan_brief.keys())[0]
    first_vlan_info = list(vlan_brief.values())[0]
    running_config = duthost.get_running_config_facts()
    first_vlan_info['dhcp_servers'] = running_config['VLAN'][first_vlan_name].get('dhcp_servers', [])
    first_vlan_info['dhcp_relay'] = running_config['DHCP_RELAY'].get(first_vlan_name, {}).get('dhcp_servers', [])
    first_vlan_info['dhcpv6_servers'] = running_config['VLAN'][first_vlan_name].get('dhcpv6_servers', [])
    first_vlan_info['dhcpv6_relay'] = running_config['DHCP_RELAY'].get(first_vlan_name, {}).get('dhcpv6_servers', [])
    first_vlan_info['dhcpv4_relay'] = running_config.get('DHCPV4_RELAY', {}).get(first_vlan_name, {})
    connected_ptf_ports_idx, connected_dut_intf_to_ptf_index = _get_connected_ptf_port_mapping(duthost, tbinfo)
    vlan_members_with_ptf_idx = [
        (member, connected_dut_intf_to_ptf_index[member])
        for member in first_vlan_info['members']
        if member in connected_dut_intf_to_ptf_index
    ]
    pytest_require(len(vlan_members_with_ptf_idx) >= 2, 'Expected at least two vlan members to split the test vlan')
    sub_vlans_info, config_patch = generate_sub_vlans_config_patch(
        first_vlan_name,
        first_vlan_info,
        vlan_members_with_ptf_idx,
        2
    )
    apply_config_patch(duthost, config_patch)
    wait_dhcp_relay_ready(duthost, _relay_types_for_agent(relay_agent))
    try:
        yield [
            _build_vlan_context(
                duthost,
                vlan_info['vlan_name'],
                vlan_info['interface_ipv4'],
                vlan_info['members_with_ptf_idx'],
                connected_ptf_ports_idx
            )
            for vlan_info in sub_vlans_info
        ]
    finally:
        config_reload(duthost)


@pytest.mark.parametrize("config_tool", [DHCP_SERVER_CONFIG_TOOL_GCU, DHCP_SERVER_CONFIG_TOOL_CLI])
def test_dhcp_server_match_option60_same_port(
    duthost,
    ptfhost,
    ptfadapter,
    match_test_context,
    config_tool,
    enable_sonic_dhcpv4_relay_agent,  # noqa: F811
    relay_agent
):
    """Verify two option-60 clients on one port receive deterministic single-IP bindings."""
    vlan_context = match_test_context
    dut_port = vlan_context['members'][0]
    send_ptf_port_index = dut_port['ptf_port_index']
    mac_ptf_port_indices = _select_client_mac_ptf_ports(vlan_context, send_ptf_port_index, 2)
    expected_ips = vlan_context['hosts'][:2]
    port_match = _port_match_name(dut_port['alias'])
    matches = {
        port_match: {'type': 'circuit_id', 'value': dut_port['alias']},
        'vendor-a': {'type': 'option60', 'value': 'MAIA-A'},
        'vendor-b': {'type': 'option60', 'value': 'MAIA-B'},
    }
    bindings = {
        'vendor-a': {'matches': [port_match, 'vendor-a'], 'ips': [expected_ips[0]]},
        'vendor-b': {'matches': [port_match, 'vendor-b'], 'ips': [expected_ips[1]]},
    }
    config_to_apply = create_match_config_patch(
        vlan_context['vlan_name'],
        vlan_context['gateway'],
        vlan_context['netmask'],
        matches,
        bindings
    )
    if config_tool == DHCP_SERVER_CONFIG_TOOL_CLI:
        config_to_apply = generate_match_config_cli_commands(
            vlan_context['vlan_name'],
            vlan_context['gateway'],
            vlan_context['netmask'],
            matches,
            bindings
        )

    acquired_clients = []
    with dhcp_server_config(duthost, config_tool, config_to_apply):
        try:
            client_a_mac = _verify_client_assignment(
                duthost,
                ptfhost,
                ptfadapter,
                vlan_context,
                dut_port['name'],
                send_ptf_port_index,
                mac_ptf_port_indices[0],
                5101,
                expected_ips[0],
                option60_value='MAIA-A',
                release_needed=False
            )
            acquired_clients.append((5101, client_a_mac, expected_ips[0]))
            client_b_mac = _verify_client_assignment(
                duthost,
                ptfhost,
                ptfadapter,
                vlan_context,
                dut_port['name'],
                send_ptf_port_index,
                mac_ptf_port_indices[1],
                5102,
                expected_ips[1],
                option60_value='MAIA-B',
                release_needed=False
            )
            acquired_clients.append((5102, client_b_mac, expected_ips[1]))
        finally:
            for xid, client_mac, assigned_ip in acquired_clients:
                send_release_packet(
                    ptfadapter,
                    send_ptf_port_index,
                    xid,
                    client_mac,
                    assigned_ip,
                    vlan_context['gateway']
                )


def test_dhcp_server_match_four_clients_same_port(
    duthost,
    ptfhost,
    ptfadapter,
    match_test_context,
    enable_sonic_dhcpv4_relay_agent,  # noqa: F811
    relay_agent
):
    """Verify four distinct clients on one port each receive the configured MATCH pool."""
    vlan_context = match_test_context
    dut_port = vlan_context['members'][0]
    send_ptf_port_index = dut_port['ptf_port_index']
    mac_ptf_port_indices = _select_client_mac_ptf_ports(vlan_context, send_ptf_port_index, 4)
    expected_ips = vlan_context['hosts'][:4]
    vendor_values = ['VENDOR-0', 'VENDOR-1', 'VENDOR-2', 'VENDOR-3']
    port_match = _port_match_name(dut_port['alias'])
    matches = {port_match: {'type': 'circuit_id', 'value': dut_port['alias']}}
    bindings = {}
    for index, vendor_value in enumerate(vendor_values):
        match_name = 'vendor-{}'.format(index)
        binding_name = 'binding-{}'.format(index)
        matches[match_name] = {'type': 'option60', 'value': vendor_value}
        bindings[binding_name] = {'matches': [port_match, match_name], 'ips': [expected_ips[index]]}

    acquired_clients = []
    with dhcp_server_config(
        duthost,
        DHCP_SERVER_CONFIG_TOOL_GCU,
        create_match_config_patch(
            vlan_context['vlan_name'],
            vlan_context['gateway'],
            vlan_context['netmask'],
            matches,
            bindings
        )
    ):
        try:
            for index, vendor_value in enumerate(vendor_values):
                client_mac = _verify_client_assignment(
                    duthost,
                    ptfhost,
                    ptfadapter,
                    vlan_context,
                    dut_port['name'],
                    send_ptf_port_index,
                    mac_ptf_port_indices[index],
                    5200 + index,
                    expected_ips[index],
                    option60_value=vendor_value,
                    release_needed=False
                )
                acquired_clients.append((5200 + index, client_mac, expected_ips[index]))
        finally:
            for xid, client_mac, assigned_ip in acquired_clients:
                send_release_packet(
                    ptfadapter,
                    send_ptf_port_index,
                    xid,
                    client_mac,
                    assigned_ip,
                    vlan_context['gateway']
                )


def test_dhcp_server_match_specificity_fallback(
    duthost,
    ptfhost,
    ptfadapter,
    match_test_context,
    enable_sonic_dhcpv4_relay_agent,  # noqa: F811
    relay_agent
):
    """Verify a more-specific port-plus-option60 binding overrides the port-only fallback."""
    vlan_context = match_test_context
    dut_port = vlan_context['members'][0]
    send_ptf_port_index = dut_port['ptf_port_index']
    mac_ptf_port_indices = _select_client_mac_ptf_ports(vlan_context, send_ptf_port_index, 3)
    specific_ip, fallback_ip = vlan_context['hosts'][:2]
    port_match = _port_match_name(dut_port['alias'])
    matches = {
        port_match: {'type': 'circuit_id', 'value': dut_port['alias']},
        'vendor-a': {'type': 'option60', 'value': 'MAIA-A'},
    }
    bindings = {
        'specific': {'matches': [port_match, 'vendor-a'], 'ips': [specific_ip]},
        'fallback': {'matches': [port_match], 'ranges': ['fallback-range']},
    }
    ip_ranges = {'fallback-range': [fallback_ip]}

    acquired_clients = []
    with dhcp_server_config(
        duthost,
        DHCP_SERVER_CONFIG_TOOL_GCU,
        create_match_config_patch(
            vlan_context['vlan_name'],
            vlan_context['gateway'],
            vlan_context['netmask'],
            matches,
            bindings,
            ip_ranges
        )
    ):
        try:
            client_specific_mac = _verify_client_assignment(
                duthost,
                ptfhost,
                ptfadapter,
                vlan_context,
                dut_port['name'],
                send_ptf_port_index,
                mac_ptf_port_indices[0],
                5301,
                specific_ip,
                option60_value='MAIA-A',
                release_needed=False
            )
            acquired_clients.append((5301, client_specific_mac, specific_ip))
            client_fallback_mac = _verify_client_assignment(
                duthost,
                ptfhost,
                ptfadapter,
                vlan_context,
                dut_port['name'],
                send_ptf_port_index,
                mac_ptf_port_indices[1],
                5302,
                fallback_ip,
                option60_value='MAIA-B',
                release_needed=False
            )
            acquired_clients.append((5302, client_fallback_mac, fallback_ip))
        finally:
            for xid, client_mac, assigned_ip in acquired_clients:
                send_release_packet(
                    ptfadapter,
                    send_ptf_port_index,
                    xid,
                    client_mac,
                    assigned_ip,
                    vlan_context['gateway']
                )


def test_dhcp_server_match_no_binding(
    duthost,
    ptfhost,
    ptfadapter,
    match_test_context,
    enable_sonic_dhcpv4_relay_agent,  # noqa: F811
    relay_agent
):
    """Verify a client that matches no binding receives no DHCPOFFER."""
    vlan_context = match_test_context
    dut_port = vlan_context['members'][0]
    send_ptf_port_index = dut_port['ptf_port_index']
    client_mac_ptf_port_index = _select_client_mac_ptf_ports(vlan_context, send_ptf_port_index, 2)[1]
    client_mac = ptfadapter.dataplane.get_mac(0, client_mac_ptf_port_index).decode('utf-8')
    port_match = _port_match_name(dut_port['alias'])
    matches = {
        port_match: {'type': 'circuit_id', 'value': dut_port['alias']},
        'vendor-a': {'type': 'option60', 'value': 'MAIA-A'},
    }
    bindings = {
        'vendor-a': {'matches': [port_match, 'vendor-a'], 'ips': [vlan_context['hosts'][0]]},
    }

    with dhcp_server_config(
        duthost,
        DHCP_SERVER_CONFIG_TOOL_GCU,
        create_match_config_patch(
            vlan_context['vlan_name'],
            vlan_context['gateway'],
            vlan_context['netmask'],
            matches,
            bindings
        )
    ):
        discover_pkt = create_dhcp_client_packet(
            src_mac=client_mac,
            message_type=DHCP_MESSAGE_TYPE_DISCOVER_NUM,
            client_options=[_build_option60_option('MAIA-B')],
            xid=5401
        )
        send_and_verify(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port['name'],
            ptf_port_index=send_ptf_port_index,
            test_pkt=discover_pkt,
            pkts_validator=validate_no_dhcp_server_pkts,
            pkts_validator_args=[5401]
        )
        _assert_no_lease(duthost, vlan_context['vlan_name'], client_mac)


def test_dhcp_server_match_or_same_pool(
    duthost,
    ptfhost,
    ptfadapter,
    match_test_context,
    enable_sonic_dhcpv4_relay_agent,  # noqa: F811
    relay_agent
):
    """Verify separate bindings can OR into one shared pool without duplicate-pool failure."""
    vlan_context = match_test_context
    dut_port = vlan_context['members'][0]
    send_ptf_port_index = dut_port['ptf_port_index']
    mac_ptf_port_indices = _select_client_mac_ptf_ports(vlan_context, send_ptf_port_index, 3)
    shared_ip = vlan_context['hosts'][0]
    matches = {
        'vendor-a': {'type': 'option60', 'value': 'MAIA-A'},
        'vendor-b': {'type': 'option60', 'value': 'MAIA-B'},
    }
    bindings = {
        'vendor-a': {'matches': ['vendor-a'], 'ips': [shared_ip]},
        'vendor-b': {'matches': ['vendor-b'], 'ips': [shared_ip]},
    }

    with dhcp_server_config(
        duthost,
        DHCP_SERVER_CONFIG_TOOL_GCU,
        create_match_config_patch(
            vlan_context['vlan_name'],
            vlan_context['gateway'],
            vlan_context['netmask'],
            matches,
            bindings
        )
    ):
        first_client_mac = _verify_client_assignment(
            duthost,
            ptfhost,
            ptfadapter,
            vlan_context,
            dut_port['name'],
            send_ptf_port_index,
            mac_ptf_port_indices[0],
            5501,
            shared_ip,
            option60_value='MAIA-A'
        )
        _wait_lease_absent(duthost, vlan_context['vlan_name'], first_client_mac)
        _verify_client_assignment(
            duthost,
            ptfhost,
            ptfadapter,
            vlan_context,
            dut_port['name'],
            send_ptf_port_index,
            mac_ptf_port_indices[1],
            5502,
            shared_ip,
            option60_value='MAIA-B'
        )


def test_dhcp_server_match_dynamic_match_update(
    duthost,
    ptfhost,
    ptfadapter,
    match_test_context,
    enable_sonic_dhcpv4_relay_agent,  # noqa: F811
    relay_agent
):
    """Verify updating an active match value changes client eligibility after reload."""
    vlan_context = match_test_context
    dut_port = vlan_context['members'][0]
    send_ptf_port_index = dut_port['ptf_port_index']
    mac_ptf_port_indices = _select_client_mac_ptf_ports(vlan_context, send_ptf_port_index, 3)
    expected_ip = vlan_context['hosts'][0]
    port_match = _port_match_name(dut_port['alias'])
    matches = {
        port_match: {'type': 'circuit_id', 'value': dut_port['alias']},
        'dynamic-vendor': {'type': 'option60', 'value': 'MAIA-A'},
    }
    bindings = {
        'dynamic-binding': {'matches': [port_match, 'dynamic-vendor'], 'ips': [expected_ip]},
    }

    with dhcp_server_config(
        duthost,
        DHCP_SERVER_CONFIG_TOOL_GCU,
        create_match_config_patch(
            vlan_context['vlan_name'],
            vlan_context['gateway'],
            vlan_context['netmask'],
            matches,
            bindings
        )
    ):
        _verify_client_assignment(
            duthost,
            ptfhost,
            ptfadapter,
            vlan_context,
            dut_port['name'],
            send_ptf_port_index,
            mac_ptf_port_indices[0],
            5601,
            expected_ip,
            option60_value='MAIA-A'
        )
        apply_dhcp_server_config_gcu(
            duthost,
            [{
                'op': 'replace',
                'path': '/DHCP_SERVER_IPV4_MATCH/dynamic-vendor/value',
                'value': 'MAIA-B'
            }]
        )
        _wait_dhcp_server_config_applied(duthost)
        old_client_mac = _verify_client_assignment(
            duthost,
            ptfhost,
            ptfadapter,
            vlan_context,
            dut_port['name'],
            send_ptf_port_index,
            mac_ptf_port_indices[1],
            5602,
            None,
            option60_value='MAIA-A'
        )
        _assert_no_lease(duthost, vlan_context['vlan_name'], old_client_mac)
        _verify_client_assignment(
            duthost,
            ptfhost,
            ptfadapter,
            vlan_context,
            dut_port['name'],
            send_ptf_port_index,
            mac_ptf_port_indices[2],
            5603,
            expected_ip,
            option60_value='MAIA-B'
        )


def test_dhcp_server_match_dynamic_binding_update(
    duthost,
    ptfhost,
    ptfadapter,
    match_test_context,
    enable_sonic_dhcpv4_relay_agent,  # noqa: F811
    relay_agent
):
    """Verify updating a binding pool takes effect without restarting the dhcp_server container."""
    vlan_context = match_test_context
    dut_port = vlan_context['members'][0]
    send_ptf_port_index = dut_port['ptf_port_index']
    mac_ptf_port_indices = _select_client_mac_ptf_ports(vlan_context, send_ptf_port_index, 2)
    first_ip, second_ip = vlan_context['hosts'][:2]
    port_match = _port_match_name(dut_port['alias'])
    matches = {
        port_match: {'type': 'circuit_id', 'value': dut_port['alias']},
        'vendor-a': {'type': 'option60', 'value': 'MAIA-A'},
    }
    bindings = {
        'binding-a': {'matches': [port_match, 'vendor-a'], 'ips': [first_ip]},
    }

    with dhcp_server_config(
        duthost,
        DHCP_SERVER_CONFIG_TOOL_GCU,
        create_match_config_patch(
            vlan_context['vlan_name'],
            vlan_context['gateway'],
            vlan_context['netmask'],
            matches,
            bindings
        )
    ):
        _verify_client_assignment(
            duthost,
            ptfhost,
            ptfadapter,
            vlan_context,
            dut_port['name'],
            send_ptf_port_index,
            mac_ptf_port_indices[0],
            5701,
            first_ip,
            option60_value='MAIA-A'
        )
        container_id_before = duthost.shell("docker inspect -f '{{.Id}}' dhcp_server")['stdout']
        apply_dhcp_server_config_gcu(
            duthost,
            [{
                'op': 'replace',
                'path': '/DHCP_SERVER_IPV4_BINDING/{}|binding-a'.format(vlan_context['vlan_name']),
                'value': {
                    'matches': [port_match, 'vendor-a'],
                    'ips': [second_ip]
                }
            }]
        )
        _wait_dhcp_server_config_applied(duthost)
        container_id_after = duthost.shell("docker inspect -f '{{.Id}}' dhcp_server")['stdout']
        pytest_assert(
            container_id_before == container_id_after,
            'dhcp_server container restarted during a binding-only update'
        )
        _verify_client_assignment(
            duthost,
            ptfhost,
            ptfadapter,
            vlan_context,
            dut_port['name'],
            send_ptf_port_index,
            mac_ptf_port_indices[1],
            5702,
            second_ip,
            option60_value='MAIA-A'
        )


def test_dhcp_server_match_mode_switch(
    duthost,
    ptfhost,
    ptfadapter,
    match_test_context,
    enable_sonic_dhcpv4_relay_agent,  # noqa: F811
    relay_agent
):
    """Verify staged MATCH bindings activate on PORT→MATCH and PORT behavior returns on MATCH→PORT."""
    vlan_context = match_test_context
    dut_port = vlan_context['members'][0]
    send_ptf_port_index = dut_port['ptf_port_index']
    mac_ptf_port_indices = _select_client_mac_ptf_ports(vlan_context, send_ptf_port_index, 3)
    port_ip, match_ip = vlan_context['hosts'][:2]
    port_match = _port_match_name(dut_port['alias'])
    matches = {
        port_match: {'type': 'circuit_id', 'value': dut_port['alias']},
        'vendor-a': {'type': 'option60', 'value': 'MAIA-A'},
    }
    bindings = {
        'match-only': {'matches': [port_match, 'vendor-a'], 'ips': [match_ip]},
    }
    config_to_apply = empty_config_patch(include_match=True)
    append_common_config_patch(
        config_to_apply,
        vlan_context['vlan_name'],
        vlan_context['gateway'],
        vlan_context['netmask'],
        [dut_port['name']],
        [[port_ip]]
    )
    append_match_config_patch(
        config_to_apply,
        vlan_context['vlan_name'],
        vlan_context['gateway'],
        vlan_context['netmask'],
        matches,
        bindings,
        include_interface=False
    )

    with dhcp_server_config(duthost, DHCP_SERVER_CONFIG_TOOL_GCU, config_to_apply):
        _verify_client_assignment(
            duthost,
            ptfhost,
            ptfadapter,
            vlan_context,
            dut_port['name'],
            send_ptf_port_index,
            mac_ptf_port_indices[0],
            5801,
            port_ip,
            option60_value='MAIA-A'
        )
        apply_dhcp_server_config_gcu(
            duthost,
            [{
                'op': 'replace',
                'path': '/DHCP_SERVER_IPV4/{}/mode'.format(vlan_context['vlan_name']),
                'value': 'MATCH'
            }]
        )
        _wait_dhcp_server_config_applied(duthost)
        _verify_client_assignment(
            duthost,
            ptfhost,
            ptfadapter,
            vlan_context,
            dut_port['name'],
            send_ptf_port_index,
            mac_ptf_port_indices[1],
            5802,
            match_ip,
            option60_value='MAIA-A'
        )
        apply_dhcp_server_config_gcu(
            duthost,
            [{
                'op': 'replace',
                'path': '/DHCP_SERVER_IPV4/{}/mode'.format(vlan_context['vlan_name']),
                'value': 'PORT'
            }]
        )
        _wait_dhcp_server_config_applied(duthost)
        _verify_client_assignment(
            duthost,
            ptfhost,
            ptfadapter,
            vlan_context,
            dut_port['name'],
            send_ptf_port_index,
            mac_ptf_port_indices[2],
            5803,
            port_ip,
            option60_value='MAIA-A'
        )


def test_dhcp_server_match_existing_lease_mode_switch(
    duthost,
    ptfhost,
    ptfadapter,
    match_test_context,
    enable_sonic_dhcpv4_relay_agent,  # noqa: F811
    relay_agent
):
    """Verify an existing lease renews across a PORT→MATCH mode switch when the IP remains eligible."""
    vlan_context = match_test_context
    dut_port = vlan_context['members'][0]
    send_ptf_port_index = dut_port['ptf_port_index']
    lease_ip = vlan_context['hosts'][0]
    port_match = _port_match_name(dut_port['alias'])
    matches = {
        port_match: {'type': 'circuit_id', 'value': dut_port['alias']},
    }
    bindings = {
        'same-ip': {'matches': [port_match], 'ips': [lease_ip]},
    }
    config_to_apply = empty_config_patch(include_match=True)
    append_common_config_patch(
        config_to_apply,
        vlan_context['vlan_name'],
        vlan_context['gateway'],
        vlan_context['netmask'],
        [dut_port['name']],
        [[lease_ip]]
    )
    append_match_config_patch(
        config_to_apply,
        vlan_context['vlan_name'],
        vlan_context['gateway'],
        vlan_context['netmask'],
        matches,
        bindings,
        include_interface=False
    )

    with dhcp_server_config(duthost, DHCP_SERVER_CONFIG_TOOL_GCU, config_to_apply):
        client_mac = _verify_client_assignment(
            duthost,
            ptfhost,
            ptfadapter,
            vlan_context,
            dut_port['name'],
            send_ptf_port_index,
            send_ptf_port_index,
            5901,
            lease_ip,
            release_needed=False
        )
        try:
            apply_dhcp_server_config_gcu(
                duthost,
                [{
                    'op': 'replace',
                    'path': '/DHCP_SERVER_IPV4/{}/mode'.format(vlan_context['vlan_name']),
                    'value': 'MATCH'
                }]
            )
            _wait_dhcp_server_config_applied(duthost)
            request_pkt = create_dhcp_client_packet(
                src_mac=client_mac,
                message_type=DHCP_MESSAGE_TYPE_REQUEST_NUM,
                xid=5902,
                ciaddr=lease_ip,
                src_ip=lease_ip,
                dst_ip=vlan_context['gateway'],
                dst_mac=duthost.get_dut_iface_mac(vlan_context['vlan_name'])
            )
            send_and_verify(
                duthost=duthost,
                ptfhost=ptfhost,
                ptfadapter=ptfadapter,
                dut_port_to_capture_pkt=dut_port['name'],
                ptf_port_index=send_ptf_port_index,
                test_pkt=request_pkt,
                pkts_validator=validate_dhcp_server_pkts,
                pkts_validator_args=[
                    5902,
                    lease_ip,
                    DHCP_MESSAGE_TYPE_ACK_NUM,
                    vlan_context['netmask'],
                    vlan_context['gateway'],
                    DHCP_DEFAULT_LEASE_TIME,
                    None,
                    vlan_context['gateway']
                ]
            )
            verify_lease(duthost, vlan_context['vlan_name'], client_mac, lease_ip, DHCP_DEFAULT_LEASE_TIME)
        finally:
            send_release_packet(
                ptfadapter,
                send_ptf_port_index,
                5901,
                client_mac,
                lease_ip,
                vlan_context['gateway']
            )


def test_dhcp_server_match_mixed_vlan_modes(
    duthost,
    ptfhost,
    ptfadapter,
    match_mode_two_vlans,
    enable_sonic_dhcpv4_relay_agent,  # noqa: F811
    relay_agent
):
    """Verify one VLAN can stay in PORT mode while another serves MATCH clients concurrently."""
    port_vlan_context, match_vlan_context = match_mode_two_vlans
    port_dut_port = port_vlan_context['members'][0]
    match_dut_port = match_vlan_context['members'][0]
    port_ip = port_vlan_context['hosts'][0]
    match_ip = match_vlan_context['hosts'][0]
    match_port_binding = _port_match_name(match_dut_port['alias'])
    matches = {
        match_port_binding: {'type': 'circuit_id', 'value': match_dut_port['alias']},
        'vendor-a': {'type': 'option60', 'value': 'MAIA-A'},
    }
    bindings = {
        'vendor-a': {'matches': [match_port_binding, 'vendor-a'], 'ips': [match_ip]},
    }
    config_to_apply = empty_config_patch(include_match=True)
    append_common_config_patch(
        config_to_apply,
        port_vlan_context['vlan_name'],
        port_vlan_context['gateway'],
        port_vlan_context['netmask'],
        [port_dut_port['name']],
        [[port_ip]]
    )
    append_match_config_patch(
        config_to_apply,
        match_vlan_context['vlan_name'],
        match_vlan_context['gateway'],
        match_vlan_context['netmask'],
        matches,
        bindings
    )

    acquired_clients = []
    with dhcp_server_config(duthost, DHCP_SERVER_CONFIG_TOOL_GCU, config_to_apply):
        try:
            port_client_mac = _verify_client_assignment(
                duthost,
                ptfhost,
                ptfadapter,
                port_vlan_context,
                port_dut_port['name'],
                port_dut_port['ptf_port_index'],
                port_dut_port['ptf_port_index'],
                6001,
                port_ip,
                release_needed=False
            )
            acquired_clients.append((
                port_dut_port['ptf_port_index'],
                6001,
                port_client_mac,
                port_ip,
                port_vlan_context['gateway']
            ))
            match_client_mac = _verify_client_assignment(
                duthost,
                ptfhost,
                ptfadapter,
                match_vlan_context,
                match_dut_port['name'],
                match_dut_port['ptf_port_index'],
                match_dut_port['ptf_port_index'],
                6002,
                match_ip,
                option60_value='MAIA-A',
                release_needed=False
            )
            acquired_clients.append((
                match_dut_port['ptf_port_index'],
                6002,
                match_client_mac,
                match_ip,
                match_vlan_context['gateway']
            ))
        finally:
            for ptf_port_index, xid, client_mac, assigned_ip, server_id in acquired_clients:
                send_release_packet(
                    ptfadapter,
                    ptf_port_index,
                    xid,
                    client_mac,
                    assigned_ip,
                    server_id
                )


def test_dhcp_server_match_config_reload(
    duthost,
    ptfhost,
    ptfadapter,
    match_test_context,
    enable_sonic_dhcpv4_relay_agent,  # noqa: F811
    relay_agent
):
    """Verify config save + config reload preserves MATCH behavior."""
    vlan_context = match_test_context
    dut_port = vlan_context['members'][0]
    send_ptf_port_index = dut_port['ptf_port_index']
    mac_ptf_port_indices = _select_client_mac_ptf_ports(vlan_context, send_ptf_port_index, 3)
    expected_ips = vlan_context['hosts'][:2]
    port_match = _port_match_name(dut_port['alias'])
    matches = {
        port_match: {'type': 'circuit_id', 'value': dut_port['alias']},
        'vendor-a': {'type': 'option60', 'value': 'MAIA-A'},
        'vendor-b': {'type': 'option60', 'value': 'MAIA-B'},
    }
    bindings = {
        'vendor-a': {'matches': [port_match, 'vendor-a'], 'ips': [expected_ips[0]]},
        'vendor-b': {'matches': [port_match, 'vendor-b'], 'ips': [expected_ips[1]]},
    }
    saved_config = False

    with dhcp_server_config(
        duthost,
        DHCP_SERVER_CONFIG_TOOL_GCU,
        create_match_config_patch(
            vlan_context['vlan_name'],
            vlan_context['gateway'],
            vlan_context['netmask'],
            matches,
            bindings
        )
    ):
        try:
            _verify_client_assignment(
                duthost,
                ptfhost,
                ptfadapter,
                vlan_context,
                dut_port['name'],
                send_ptf_port_index,
                mac_ptf_port_indices[0],
                6101,
                expected_ips[0],
                option60_value='MAIA-A'
            )
            duthost.shell('sudo config save -y')
            saved_config = True
            config_reload(duthost, safe_reload=True)
            wait_dhcp_server_ready(duthost)
            wait_dhcp_relay_ready(duthost, _relay_types_for_agent(relay_agent))
            _verify_client_assignment(
                duthost,
                ptfhost,
                ptfadapter,
                vlan_context,
                dut_port['name'],
                send_ptf_port_index,
                mac_ptf_port_indices[1],
                6102,
                expected_ips[0],
                option60_value='MAIA-A'
            )
            _verify_client_assignment(
                duthost,
                ptfhost,
                ptfadapter,
                vlan_context,
                dut_port['name'],
                send_ptf_port_index,
                mac_ptf_port_indices[2],
                6103,
                expected_ips[1],
                option60_value='MAIA-B'
            )
        finally:
            if saved_config:
                clean_dhcp_server_config(duthost)
                duthost.shell('sudo config save -y')


def test_dhcp_server_match_container_restart(
    duthost,
    ptfhost,
    ptfadapter,
    match_test_context,
    enable_sonic_dhcpv4_relay_agent,  # noqa: F811
    relay_agent
):
    """Verify restarting the dhcp_server container regenerates equivalent MATCH behavior."""
    vlan_context = match_test_context
    dut_port = vlan_context['members'][0]
    send_ptf_port_index = dut_port['ptf_port_index']
    mac_ptf_port_indices = _select_client_mac_ptf_ports(vlan_context, send_ptf_port_index, 2)
    expected_ip = vlan_context['hosts'][0]
    port_match = _port_match_name(dut_port['alias'])
    matches = {
        port_match: {'type': 'circuit_id', 'value': dut_port['alias']},
        'vendor-a': {'type': 'option60', 'value': 'MAIA-A'},
    }
    bindings = {
        'vendor-a': {'matches': [port_match, 'vendor-a'], 'ips': [expected_ip]},
    }

    with dhcp_server_config(
        duthost,
        DHCP_SERVER_CONFIG_TOOL_GCU,
        create_match_config_patch(
            vlan_context['vlan_name'],
            vlan_context['gateway'],
            vlan_context['netmask'],
            matches,
            bindings
        )
    ):
        _verify_client_assignment(
            duthost,
            ptfhost,
            ptfadapter,
            vlan_context,
            dut_port['name'],
            send_ptf_port_index,
            mac_ptf_port_indices[0],
            6201,
            expected_ip,
            option60_value='MAIA-A'
        )
        _restart_dhcp_server_container(duthost)
        _verify_client_assignment(
            duthost,
            ptfhost,
            ptfadapter,
            vlan_context,
            dut_port['name'],
            send_ptf_port_index,
            mac_ptf_port_indices[1],
            6202,
            expected_ip,
            option60_value='MAIA-A'
        )


def test_dhcp_server_match_request_without_option60(
    duthost,
    ptfhost,
    ptfadapter,
    match_test_context,
    enable_sonic_dhcpv4_relay_agent,  # noqa: F811
    relay_agent
):
    """Verify the suite preserves the compatibility signal when DHCPREQUEST omits option 60."""
    vlan_context = match_test_context
    dut_port = vlan_context['members'][0]
    send_ptf_port_index = dut_port['ptf_port_index']
    expected_ip = vlan_context['hosts'][0]
    matches = {
        'vendor-a': {'type': 'option60', 'value': 'MAIA-A'},
    }
    bindings = {
        'vendor-a': {'matches': ['vendor-a'], 'ips': [expected_ip]},
    }

    with dhcp_server_config(
        duthost,
        DHCP_SERVER_CONFIG_TOOL_GCU,
        create_match_config_patch(
            vlan_context['vlan_name'],
            vlan_context['gateway'],
            vlan_context['netmask'],
            matches,
            bindings
        )
    ):
        client_mac = _verify_client_assignment(
            duthost,
            ptfhost,
            ptfadapter,
            vlan_context,
            dut_port['name'],
            send_ptf_port_index,
            send_ptf_port_index,
            6301,
            expected_ip,
            option60_value='MAIA-A',
            request_includes_option60=False,
            request_expected_assigned_ip=None
        )
        _assert_no_lease(duthost, vlan_context['vlan_name'], client_mac)
