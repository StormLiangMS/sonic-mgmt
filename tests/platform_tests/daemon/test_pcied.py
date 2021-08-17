"""
Check daemon status inside PMON container. Each daemon status is checked under the conditions below in this script:
* Daemon Running Status 
* Daemon Stop status
* Daemon Restart status

This script is to cover the test case in the SONiC platform daemon and service test plan:
https://github.com/Azure/sonic-mgmt/blob/master/docs/testplan/PMON-Services-Daemons-test-plan.md
"""
import logging
import re
import time

from datetime import datetime

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.daemon_utils import check_pmon_daemon_enable_status
from tests.common.platform.processes_utils import wait_critical_processes, check_critical_processes

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer
]

expected_running_status = "RUNNING"
expected_stopped_status = "STOPPED"
expected_exited_status = "EXITED"

daemon_name = "pcied"

SIG_STOP_SERVICE = None
SIG_TERM = "-15"
SIG_KILL = "-9"

status_field = "status"
expected_pcied_devices_status = "PASSED"

@pytest.fixture(scope="module", autouse=True)
def setup(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    daemon_en_status = check_pmon_daemon_enable_status(duthost, daemon_name)
    if daemon_en_status is False:
        pytest.skip("{} is not enabled in {}".format(daemon_name, duthost.facts['platform'], duthost.os_version))


@pytest.fixture(scope="module", autouse=True)
def teardown_module(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    yield

    daemon_status, daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    if daemon_status is not "RUNNING":
        duthost.start_pmon_daemon(daemon_name)
        time.sleep(10)
    logger.info("Tearing down: to make sure all the critical services, interfaces and transceivers are good")
    check_critical_processes(duthost, watch_secs=10)


@pytest.fixture(scope="module", autouse=True)
def disable_and_enable_autorestart(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    """Changes the autorestart of containers from `enabled` to `disabled` before testing.
       and Rolls them back after testing.
    Args:
        duthost: Hostname of DUT.
    Returns:
        None.
    """
    containers_autorestart_states = duthost.get_container_autorestart_states()
    disabled_autorestart_containers = []

    for container_name, state in containers_autorestart_states.items():
        if state == "enabled":
            logger.info("Disabling the autorestart of container '{}'.".format(container_name))
            command_disable_autorestart = "sudo config feature autorestart {} disabled".format(container_name)
            command_output = duthost.shell(command_disable_autorestart)
            exit_code = command_output["rc"]
            pytest_assert(exit_code == 0, "Failed to disable the autorestart of container '{}'".format(container_name))
            logger.info("The autorestart of container '{}' was disabled.".format(container_name))
            disabled_autorestart_containers.append(container_name)

    yield

    for container_name in disabled_autorestart_containers:
        logger.info("Enabling the autorestart of container '{}'...".format(container_name))
        command_output = duthost.shell("sudo config feature autorestart {} enabled".format(container_name))
        exit_code = command_output["rc"]
        pytest_assert(exit_code == 0, "Failed to enable the autorestart of container '{}'".format(container_name))
        logger.info("The autorestart of container '{}' is enabled.".format(container_name))

@pytest.fixture()
def check_daemon_status(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    daemon_status, daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    if daemon_status is not "RUNNING":
        duthost.start_pmon_daemon(daemon_name)
        time.sleep(10)

@pytest.fixture(scope="module", autouse=True)
def get_pcie_devices_tbl_key(duthosts,rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    command_output = duthost.shell("redis-cli -n 6 keys '*' | grep PCIE_DEVICES")
    return command_output["stdout"]

def test_pmon_pcied_running_status(duthosts, rand_one_dut_hostname, get_pcie_devices_tbl_key):
    """
    @summary: This test case is to check pcied status on dut
    """
    duthost = duthosts[rand_one_dut_hostname]
    daemon_status, daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    logger.info("{} daemon is {} with pid {}".format(daemon_name, daemon_status, daemon_pid))
    pytest_assert(daemon_status == expected_running_status,
                          "Pcied expected running status is {} but is {}".format(expected_running_status, daemon_status))
    pytest_assert(daemon_pid != -1,
                          "Pcied expected pid is a positive integer but is {}".format(daemon_pid))

    daemon_db_value = duthost.get_pmon_daemon_db_value(get_pcie_devices_tbl_key, status_field)
    pytest_assert(daemon_db_value == expected_pcied_devices_status,
                          "Expected {} {} is {} but is {}".format(get_pcie_devices_tbl_key, status_field, expected_pcied_devices_status, daemon_db_value))



def test_pmon_pcied_stop_and_start_status(check_daemon_status, duthosts, rand_one_dut_hostname):
    """
    @summary: This test case is to check the pcied stopped and restarted status 
    """
    duthost = duthosts[rand_one_dut_hostname]
    pre_daemon_status, pre_daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    logger.info("{} daemon is {} with pid {}".format(daemon_name, pre_daemon_status, pre_daemon_pid))

    duthost.stop_pmon_daemon(daemon_name, SIG_STOP_SERVICE)
    time.sleep(2)

    daemon_status, daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    pytest_assert(daemon_status == expected_stopped_status,
                          "Pcied expected stopped status is {} but is {}".format(expected_stopped_status, daemon_status))
    pytest_assert(daemon_pid == -1,
                          "Pcied expected pid is -1 but is {}".format(daemon_pid))

    duthost.start_pmon_daemon(daemon_name)
    time.sleep(10)

    post_daemon_status, post_daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    pytest_assert(post_daemon_status == expected_running_status,
                          "Pcied expected restarted status is {} but is {}".format(expected_running_status, post_daemon_status))
    pytest_assert(post_daemon_pid != -1,
                          "Pcied expected pid is -1 but is {}".format(post_daemon_pid))
    pytest_assert(post_daemon_pid > pre_daemon_pid,
                          "Restarted {} pid should be bigger than {} but it is {}".format(daemon_name, pre_daemon_pid, post_daemon_pid))


def test_pmon_pcied_term_and_start_status(check_daemon_status, duthosts, rand_one_dut_hostname):
    """
    @summary: This test case is to check the pcied terminated and restarted status
    """
    duthost = duthosts[rand_one_dut_hostname]
    pre_daemon_status, pre_daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    logger.info("{} daemon is {} with pid {}".format(daemon_name, pre_daemon_status, pre_daemon_pid))

    duthost.stop_pmon_daemon(daemon_name, SIG_TERM, pre_daemon_pid)
    time.sleep(2)

    daemon_status, daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    pytest_assert(daemon_status == expected_exited_status,
                          "Pcied expected terminated status is {} but is {}".format(expected_exited_status, daemon_status))
    pytest_assert(daemon_pid == -1,
                          "Pcied expected pid is -1 but is {}".format(daemon_pid))

    duthost.start_pmon_daemon(daemon_name)
    time.sleep(10)

    post_daemon_status, post_daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    pytest_assert(post_daemon_status == expected_running_status,
                          "Pcied expected restarted status is {} but is {}".format(expected_running_status, post_daemon_status))
    pytest_assert(post_daemon_pid != -1,
                          "Pcied expected pid is -1 but is {}".format(post_daemon_pid))
    pytest_assert(post_daemon_pid > pre_daemon_pid,
                          "Restarted {} pid should be bigger than {} but it is {}".format(daemon_name, pre_daemon_pid, post_daemon_pid))


def test_pmon_pcied_kill_and_start_status(check_daemon_status, duthosts, rand_one_dut_hostname):
    """
    @summary: This test case is to check the pcied killed unexpectedly (automatically restarted) status
    """
    duthost = duthosts[rand_one_dut_hostname]
    pre_daemon_status, pre_daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    logger.info("{} daemon is {} with pid {}".format(daemon_name, pre_daemon_status, pre_daemon_pid))

    duthost.stop_pmon_daemon(daemon_name, SIG_KILL, pre_daemon_pid)

    daemon_status, daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    logger.info("{} daemon got killed unexpectedly and it is {} with pid {}".format(daemon_name, daemon_status, daemon_pid))
    pytest_assert(daemon_status != expected_running_status,
                          "Pcied unexpected killed status is not {}".format(daemon_status))

    time.sleep(10)

    post_daemon_status, post_daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    pytest_assert(post_daemon_status == expected_running_status,
                          "Pcied expected restarted status is {} but is {}".format(expected_running_status, post_daemon_status))
    pytest_assert(post_daemon_pid != -1,
                          "Pcied expected pid is -1 but is {}".format(post_daemon_pid))
    pytest_assert(post_daemon_pid > pre_daemon_pid,
                          "Restarted {} pid should be bigger than {} but it is {}".format(daemon_name, pre_daemon_pid, post_daemon_pid))
