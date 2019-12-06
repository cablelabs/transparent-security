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


class ShortestPath:

    def __init__(self, path_edges):
        self.neighbors = {}
        for edge in path_edges:
            self.add_edge(*edge)

    def add_edge(self, a, b):
        if a not in self.neighbors:
            self.neighbors[a] = []
        if b not in self.neighbors[a]:
            self.neighbors[a].append(b)

        if b not in self.neighbors:
            self.neighbors[b] = []
        if a not in self.neighbors[b]:
            self.neighbors[b].append(a)

    def get(self, a, b, exclude=lambda node: False):
        # Shortest path from a to b
        return self.__rec_path(a, b, [], exclude)

    def __rec_path(self, a, b, visited, exclude):
        if a == b:
            return [a]
        new_visited = visited + [a]
        paths = list()
        for neighbor in self.neighbors[a]:
            if neighbor in new_visited:
                continue
            if exclude(neighbor) and neighbor != b:
                continue
            path = self.__rec_path(neighbor, b, new_visited, exclude)
            if path:
                paths.append(path)

        paths.sort(key=len)
        return [a] + paths[0] if len(paths) else None
