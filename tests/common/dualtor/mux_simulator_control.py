import logging
import pytest

import requests

from tests.common import utilities
from tests.common.helpers.assertions import pytest_assert
from tests.common.dualtor.constants import UPPER_TOR, LOWER_TOR, TOGGLE, RANDOM, NIC, DROP, OUTPUT, FLAP_COUNTER, CLEAR_FLAP_COUNTER, RESET

__all__ = ['check_simulator_read_side', 'mux_server_url', 'url', 'recover_all_directions', 'set_drop', 'set_output', 'toggle_all_simulator_ports_to_another_side', \
           'toggle_all_simulator_ports_to_lower_tor', 'toggle_all_simulator_ports_to_random_side', 'toggle_all_simulator_ports_to_upper_tor', \
           'toggle_simulator_port_to_lower_tor', 'toggle_simulator_port_to_upper_tor', 'toggle_all_simulator_ports', 'get_mux_status', 'reset_simulator_port']

logger = logging.getLogger(__name__)

TOGGLE_SIDES = [UPPER_TOR, LOWER_TOR, TOGGLE, RANDOM]


@pytest.fixture(scope='session')
def mux_server_url(request, tbinfo):
    """
    A session level fixture to retrieve the address of mux simulator address
    Args:
        request: A fixture from Ansible
        tbinfo: A session level fixture
    Returns:
        str: The address of mux simulator server + vmset_name, like http://10.0.0.64:8080/mux/vms17-8
    """
    if 'dualtor' in tbinfo['topo']['name']:
        server = tbinfo['server']
        vmset_name = tbinfo['group-name']
        inv_files = request.config.option.ansible_inventory
        ip = utilities.get_test_server_vars(inv_files, server).get('ansible_host')
        port = utilities.get_group_visible_vars(inv_files, server).get('mux_simulator_port')
        return "http://{}:{}/mux/{}".format(ip, port, vmset_name)
    return ""

@pytest.fixture(scope='module')
def url(mux_server_url, duthost, tbinfo):
    """
    A helper function is returned to make fixture accept arguments
    """
    def _url(interface_name=None, action=None):
        """
        Helper function to build an url for given port and target

        Args:
            interface_name: a str, the name of interface
                            If interface_name is none, the returned url contains no '/port/action' (For polling/toggling all ports)
                            or /mux/vms/flap_counter for retrieving flap counter for all ports
                            or /mux/vms/clear_flap_counter for clearing flap counter for given ports
            action: a str, output|drop|None. If action is None, the returned url contains no '/action'
        Returns:
            The url for posting flow update request, like http://10.0.0.64:8080/mux/vms17-8[/1/drop|output]
        """
        if not interface_name:
            if action:
                # Only for flap_counter, clear_flap_counter, or reset
                return mux_server_url + "/{}".format(action)
            return mux_server_url
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        mbr_index = mg_facts['minigraph_ptf_indices'][interface_name]
        if not action:
            return mux_server_url + "/{}".format(mbr_index)
        return mux_server_url + "/{}/{}".format(mbr_index, action)

    return _url

def _get(server_url):
    """
    Helper function for polling status from y_cable server.

    Args:
        server_url: a str, the full address of mux server, like http://10.0.0.64:8080/mux/vms17-8[/1]
    Returns:
        dict: A dict decoded from server's response.
        None: Returns None if request failed.
    """
    try:
        logger.debug('GET {}'.format(server_url))
        headers = {'Accept': 'application/json'}
        resp = requests.get(server_url, headers=headers)
        if resp.status_code == 200:
            return resp.json()
        else:
            logger.warn("GET {} failed with {}".format(server_url, resp.text))
    except Exception as e:
        logger.warn("GET {} failed with {}".format(server_url, repr(e)))

    return None


def _post(server_url, data):
    """
    Helper function for posting data to y_cable server.

    Args:
        server_url: a str, the full address of mux server, like http://10.0.0.64:8080/mux/vms17-8[/1/drop|output]
        data: data to post {"out_sides": ["nic", "upper_tor", "lower_tor"]}
    Returns:
        True if succeed. False otherwise
    """
    try:
        logger.debug('POST {} with {}'.format(server_url, data))
        headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
        resp = requests.post(server_url, json=data, headers=headers)
        return resp.status_code == 200
    except Exception as e:
        logger.warn("POST {} with data {} failed, err: {}".format(server_url, data, repr(e)))

    return False


@pytest.fixture(scope='function')
def set_drop(url, recover_all_directions):
    """
    A helper function is returned to make fixture accept arguments
    """
    drop_intfs = set()
    def _set_drop(interface_name, directions):
        """
        A fixture to set drop for a certain direction on a port
        Args:
            interface_name: a str, the name of interface
            directions: a list, may contain "upper_tor", "lower_tor", "nic"
        Returns:
            None.
        """
        drop_intfs.add(interface_name)
        server_url = url(interface_name, DROP)
        data = {"out_sides": directions}
        pytest_assert(_post(server_url, data), "Failed to set drop on {}".format(directions))

    yield _set_drop

    for intf in drop_intfs:
        recover_all_directions(intf)


@pytest.fixture(scope='function')
def set_output(url):
    """
    A helper function is returned to make fixture accept arguments
    """
    def _set_output(interface_name, directions):
        """
        Function to set output for a certain direction on a port
        Args:
            interface_name: a str, the name of interface
            directions: a list, may contain "upper_tor", "lower_tor", "nic"
        Returns:
            None.
        """
        server_url = url(interface_name, OUTPUT)
        data = {"out_sides": directions}
        pytest_assert(_post(server_url, data), "Failed to set output on {}".format(directions))

    return _set_output

@pytest.fixture(scope='module')
def toggle_simulator_port_to_upper_tor(url):
    """
    Returns _toggle_simulator_port_to_upper_tor to make fixture accept arguments
    """
    def _toggle_simulator_port_to_upper_tor(interface_name):
        """
        A helper function to toggle y_cable simulator ports
        Args:
            interface_name: a str, the name of interface
            target: "upper_tor" or "lower_tor"
        """
        server_url = url(interface_name)
        data = {"active_side": UPPER_TOR}
        pytest_assert(_post(server_url, data), "Failed to toggle to upper_tor on interface {}".format(interface_name))

    return _toggle_simulator_port_to_upper_tor

@pytest.fixture(scope='module')
def toggle_simulator_port_to_lower_tor(url):
    """
    Returns _toggle_simulator_port_to_lower_tor to make fixture accept arguments
    """
    def _toggle_simulator_port_to_lower_tor(interface_name):
        """
        Function to toggle a given y_cable ports to lower_tor
        Args:
            interface_name: a str, the name of interface to control
        """
        server_url = url(interface_name)
        data = {"active_side": LOWER_TOR}
        pytest_assert(_post(server_url, data), "Failed to toggle to lower_tor on interface {}".format(interface_name))

    return _toggle_simulator_port_to_lower_tor

@pytest.fixture(scope='module')
def recover_all_directions(url):
    """
    A function level fixture, will return _recover_all_directions to make fixture accept arguments
    """
    def _recover_all_directions(interface_name):
        """
        Function to recover all traffic on all directions on a certain port
        Args:
            interface_name: a str, the name of interface to control
        Returns:
            None.
        """
        server_url = url(interface_name, OUTPUT)
        data = {"out_sides": [UPPER_TOR, LOWER_TOR, NIC]}
        pytest_assert(_post(server_url, data), "Failed to set output on all directions for interface {}".format(interface_name))

    return _recover_all_directions

@pytest.fixture(scope='module')
def check_simulator_read_side(url):
    """
    A function level fixture, will return _check_simulator_read_side
    """
    def _check_simulator_read_side(interface_name):
        """
        Retrieve the current active tor from y_cable simulator server.
        Args:
            interface_name: a str, the name of interface to control
        Returns:
            1 if upper_tor is active
            2 if lower_tor is active
            -1 for exception or inconsistent status
        """
        server_url = url(interface_name)
        res = _get(server_url)
        if not res:
            return -1
        active_side = res["active_side"]
        if active_side == UPPER_TOR:
            return 1
        elif active_side == LOWER_TOR:
            return 2
        else:
            return -1

    return _check_simulator_read_side

@pytest.fixture(scope='module')
def get_active_torhost(upper_tor_host, lower_tor_host, check_simulator_read_side):
    """
    A function level fixture which returns a helper function
    """
    def _get_active_torhost(interface_name):
        active_tor_host = None
        active_side = check_simulator_read_side(interface_name)
        pytest_assert(active_side != -1, "Failed to retrieve the current active tor from y_cable simulator server")
        if active_side == 1:
            active_tor_host = upper_tor_host
        elif active_side == 2:
            active_tor_host = lower_tor_host
        return active_tor_host

    return _get_active_torhost

def _toggle_all_simulator_ports(mux_server_url, side):
    pytest_assert(side in TOGGLE_SIDES, "Unsupported side '{}'".format(side))
    data = {"active_side": side}
    logger.info('Toggle all ports to "{}"'.format(side))
    pytest_assert(_post(mux_server_url, data), "Failed to toggle all ports to '{}'".format(side))

@pytest.fixture(scope='module')
def toggle_all_simulator_ports(mux_server_url):
    """
    A module level fixture to toggle all ports to specified side.
    """
    def _toggle(side):
        _toggle_all_simulator_ports(mux_server_url, side)
    return _toggle

@pytest.fixture
def toggle_all_simulator_ports_to_upper_tor(mux_server_url):
    """
    A module level fixture to toggle all ports to upper_tor
    """
    _toggle_all_simulator_ports(mux_server_url, UPPER_TOR)

@pytest.fixture
def toggle_all_simulator_ports_to_lower_tor(mux_server_url):
    """
    A module level fixture to toggle all ports to lower_tor
    """
    _toggle_all_simulator_ports(mux_server_url, LOWER_TOR)

@pytest.fixture
def toggle_all_simulator_ports_to_rand_selected_tor(mux_server_url, tbinfo, rand_one_dut_hostname):
    """
    A module level fixture to toggle all ports to randomly selected tor
    """
    # Skip on non dualtor testbed
    if 'dualtor' not in tbinfo['topo']['name']:
        return
    dut_index = tbinfo['duts'].index(rand_one_dut_hostname)
    if dut_index == 0:
        data = {"active_side": UPPER_TOR}
    else:
        data = {"active_side": LOWER_TOR}

    pytest_assert(_post(mux_server_url, data), "Failed to toggle all ports to {}".format(rand_one_dut_hostname))

@pytest.fixture
def toggle_all_simulator_ports_to_another_side(mux_server_url):
    """
    A module level fixture to toggle all ports to another side
    For example, if the current active side for a certain port is upper_tor,
    then it will be toggled to lower_tor.
    """
    _toggle_all_simulator_ports(mux_server_url, TOGGLE)

@pytest.fixture
def toggle_all_simulator_ports_to_random_side(mux_server_url):
    """
    A module level fixture to toggle all ports to a random side.
    """
    _toggle_all_simulator_ports(mux_server_url, RANDOM)

@pytest.fixture
def simulator_server_down(set_drop, set_output):
    """
    A fixture to set drop on a given mux cable
    """
    tmp_list = []
    def _drop_helper(interface_name):
        tmp_list.append(interface_name)
        set_drop(interface_name, [UPPER_TOR, LOWER_TOR])

    yield _drop_helper
    set_output(tmp_list[0], [UPPER_TOR, LOWER_TOR])


@pytest.fixture
def simulator_flap_counter(url):
    """
    A function level fixture to retrieve mux simulator flap counter for a given interface
    """
    def _simulator_flap_counter(interface_name):
        server_url = url(interface_name, FLAP_COUNTER)
        counter = _get(server_url)
        assert(counter and len(counter) == 1)
        return list(counter.values())[0]

    return _simulator_flap_counter


@pytest.fixture
def simulator_flap_counters(url):
    """
    A function level fixture to retrieve mux simulator flap counter for all ports of a testbed
    """
    server_url = url(action=FLAP_COUNTER)
    return _get(server_url)


@pytest.fixture
def simulator_clear_flap_counter(url, duthost, tbinfo):
    """
    A function level fixture to clear mux simulator flap counter for given port(s)
    """
    def _simulator_clear_flap_counter(interface_name):
        server_url = url(action=CLEAR_FLAP_COUNTER)
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        mbr_index = mg_facts['minigraph_ptf_indices'][interface_name]
        data = {"port_to_clear": str(mbr_index)}
        pytest_assert(_post(server_url, data), "Failed to clear flap counter for all ports")

    return _simulator_clear_flap_counter


@pytest.fixture
def simulator_clear_flap_counters(url):
    """
    A function level fixture to clear mux simulator flap counter for all ports of a testbed
    """
    server_url = url(action=CLEAR_FLAP_COUNTER)
    data = {"port_to_clear": "all"}
    pytest_assert(_post(server_url, data), "Failed to clear flap counter for all ports")

@pytest.fixture(scope='module')
def reset_simulator_port(url):

    def _reset_simulator_port(interface_name=None):
        logger.warn("Resetting simulator ports {}".format('all' if interface_name is None else interface_name))
        server_url = url(interface_name=interface_name, action=RESET)
        pytest_assert(_post(server_url, {}))

    return _reset_simulator_port

@pytest.fixture
def reset_all_simulator_ports(url):

    server_url = url(action=RESET)
    pytest_assert(_post(server_url, {}))

@pytest.fixture(scope='module')
def get_mux_status(url):

    def _get_mux_status(interface_name=None):
        return _get(url(interface_name=interface_name))

    return _get_mux_status
