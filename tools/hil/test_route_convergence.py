"""A learned route is routable even when host hop count is unknown."""

import unittest

from route_convergence import has_route


class RouteConvergenceTest(unittest.TestCase):
    def test_direct_route(self):
        self.assertTrue(has_route({"connected": True, "hops": 1}))

    def test_learned_route_with_unknown_hops(self):
        self.assertTrue(has_route({"connected": True, "hops": None,
                                   "next_hop": "0000000000000003", "route_metric": 2}))

    def test_connected_without_route(self):
        self.assertFalse(has_route({"connected": True, "hops": None,
                                    "next_hop": None, "route_metric": None}))


if __name__ == "__main__":
    unittest.main()
