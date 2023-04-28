def prefilter_route_lines(lines):
    """https://github.com/brandonmpace/routeparser/issues/2"""

    for el in lines:
        if "linkdown" in el:
            continue
        if "src" not in el:
            continue
        yield el


def post_filter_routes(routes):
    for r in routes:
        if "docker" in r.interface:
            continue
        if r.gateway is not None:
            continue
        yield r


def get_ip_route_lines():
    import subprocess

    return subprocess.getoutput("/usr/sbin/ip route").splitlines()


def get_needed_routes():
    import routeparser

    routeLines = list(prefilter_route_lines(get_ip_route_lines()))
    t = routeparser.RoutingTable.from_ip_route_lines(routeLines)
    return post_filter_routes(t.routes)


def get_interface_and_network():
    r = next(iter(get_needed_routes()))
    ifc = r.interface
    domain = r.network
    return ifc, domain
