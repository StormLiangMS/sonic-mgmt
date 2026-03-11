"""
Test to verify that BGP-learned routes in ROUTE_TABLE have the weight
attribute set for their nexthops.

Addresses the test gap described in:
https://github.com/sonic-net/sonic-mgmt/issues/18208

If the weight attribute is missing from ROUTE_TABLE entries, weighted
ECMP will not function correctly — all nexthops would be treated
equally regardless of their configured BGP weight.
"""
import json
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1'),
]

KEYS_CMD_TEMPLATE = "sonic-db-cli {ns}APPL_DB keys 'ROUTE_TABLE:*'"
HGETALL_CMD_TEMPLATE = 'sonic-db-cli {ns}APPL_DB hgetall "ROUTE_TABLE:{prefix}"'


def get_bgp_learned_prefixes(duthost):
    """Return a list of IPv4 prefixes from ROUTE_TABLE that have a nexthop
    (i.e., BGP-learned routes, not directly connected or blackhole)."""
    ns_flag = ""
    if duthost.is_multi_asic:
        frontend_ids = duthost.get_frontend_asic_ids()
        if frontend_ids:
            ns_flag = "-n asic{} ".format(frontend_ids[0])

    keys_output = duthost.shell(
        KEYS_CMD_TEMPLATE.format(ns=ns_flag),
        module_ignore_errors=True
    )["stdout"].strip()

    if not keys_output:
        return [], ns_flag

    prefixes = []
    for key in keys_output.splitlines():
        # Strip the ROUTE_TABLE: prefix
        prefix = key.replace("ROUTE_TABLE:", "").strip()
        # Only consider IPv4 prefixes with a subnet mask
        if "/" in prefix and ":" not in prefix:
            prefixes.append(prefix)
    return prefixes, ns_flag


def get_route_info(duthost, prefix, ns_flag):
    """Query ROUTE_TABLE for a single prefix and return the parsed dict."""
    cmd = HGETALL_CMD_TEMPLATE.format(ns=ns_flag, prefix=prefix)
    output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].strip()

    if not output:
        return {}

    # sonic-db-cli hgetall returns alternating key/value lines
    lines = output.splitlines()
    result = {}
    for i in range(0, len(lines) - 1, 2):
        result[lines[i].strip()] = lines[i + 1].strip()
    return result


def test_bgp_route_weight_attribute(duthosts, enum_frontend_dut_hostname):
    """
    @summary: Verify that BGP-learned routes in ROUTE_TABLE have the
              weight attribute set for nexthop weighting.

              Routes without the weight attribute will cause weighted ECMP
              to malfunction since all nexthops would be treated equally.

              Addresses: https://github.com/sonic-net/sonic-mgmt/issues/18208
    """
    duthost = duthosts[enum_frontend_dut_hostname]

    prefixes, ns_flag = get_bgp_learned_prefixes(duthost)
    pytest_assert(len(prefixes) > 0,
                  "No IPv4 routes found in ROUTE_TABLE on '{}'".format(
                      duthost.hostname))

    # Sample up to 20 routes to keep the test fast
    sample = prefixes[:20]
    logger.info("Checking weight attribute on {} routes (out of {}) on '{}'".format(
        len(sample), len(prefixes), duthost.hostname))

    routes_with_nexthop = 0
    routes_with_weight = 0
    missing_weight = []

    for prefix in sample:
        route_info = get_route_info(duthost, prefix, ns_flag)
        if not route_info:
            continue
        # Only check routes that have nexthop (BGP-learned, not connected/blackhole)
        if "nexthop" not in route_info:
            continue
        if route_info.get("blackhole", "") == "true":
            continue

        routes_with_nexthop += 1
        if "weight" in route_info and route_info["weight"]:
            routes_with_weight += 1
        else:
            missing_weight.append(prefix)

    if routes_with_nexthop == 0:
        pytest.skip("No BGP-learned routes with nexthops found in ROUTE_TABLE")

    logger.info("Routes with nexthop: {}, with weight: {}, missing weight: {}".format(
        routes_with_nexthop, routes_with_weight, len(missing_weight)))

    pytest_assert(len(missing_weight) == 0,
                  "The following {} BGP-learned routes are missing the 'weight' "
                  "attribute in ROUTE_TABLE on '{}': {}".format(
                      len(missing_weight), duthost.hostname,
                      ", ".join(missing_weight[:10])))
