# Copyright (c) 2019 Cable Television Laboratories, Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Unit tests for convert.py
import unittest
from trans_sec.controller.shortest_path import ShortestPath


class ShortestPathTests(unittest.TestCase):
    """
    Unit tests for utility functions in shortest_path.py
    """
    def test_shortest_path(self):
        """
        Tests shortest_path.py
        """
        edges = [
            (1, 2),
            (1, 3),
            (1, 5),
            (2, 4),
            (3, 4),
            (3, 5),
            (3, 6),
            (4, 6),
            (5, 6),
            (7, 8)

        ]
        sp = ShortestPath(edges)

        self.assertEquals(sp.get(1, 1), [1])
        self.assertEquals(sp.get(2, 2), [2])

        self.assertEquals(sp.get(1, 2), [1, 2])
        self.assertEquals(sp.get(2, 1), [2, 1])

        self.assertEquals(sp.get(1, 3), [1, 3])
        self.assertEquals(sp.get(3, 1), [3, 1])

        self.assertEquals(sp.get(4, 6), [4, 6])
        self.assertEquals(sp.get(6, 4), [6, 4])

        self.assertEquals(sp.get(2, 6), [2, 4, 6])
        self.assertEquals(sp.get(6, 2), [6, 4, 2])

        self.assertTrue(sp.get(1, 6) in [[1, 3, 6], [1, 5, 6]])
        self.assertTrue(sp.get(6, 1) in [[6, 3, 1], [6, 5, 1]])

        self.assertEquals(sp.get(2, 5), [2, 1, 5])
        self.assertEquals(sp.get(5, 2), [5, 1, 2])

        self.assertTrue(sp.get(4, 5) in [[4, 3, 5], [4, 6, 5]])
        self.assertTrue(sp.get(5, 4) in [[5, 3, 4], [6, 6, 4]])

        self.assertEquals(sp.get(7, 8), [7, 8])
        self.assertEquals(sp.get(8, 7), [8, 7])

        self.assertIsNone(sp.get(1, 7))
        self.assertIsNone(sp.get(7, 2))
