import unittest;
from tool import Tree, Node, Route;

class SingularNetworkTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tree = Tree();

    def test01AppendRoot(self):
        self.tree.append("1.1.1.1", "0.0.0.0", "ICMP");
        self.assertEqual(self.tree.root, Node("1.1.1.1"));

    def test02AppendNode(self):
        self.tree.append("2.2.2.2", "0.0.0.0", "ICMP");

        self.assertEqual(self.tree.root.routes[Route("0.0.0.0", "ICMP")], Node("2.2.2.2"));
        self.assertEqual(list(self.tree.root.routes.keys())[0], Route("0.0.0.0", "ICMP"));
        self.assertEqual(self.tree.root.routes[Route("0.0.0.0", "ICMP")], Node("2.2.2.2"));

    def test03FindNode(self):
        self.tree.append("3.3.3.3", "0.0.0.0", "ICMP");
        node = self.tree.find("2.2.2.2");
        expected = Node("2.2.2.2");
        expected.routes[Route("0.0.0.0", "ICMP")] = Node("3.3.3.3");

        self.assertEqual(node, expected);

    def test04FinishLinearNetwork(self):
        self.tree.append("0.0.0.0", "0.0.0.0", "ICMP");

        route = self.tree.getRoute("0.0.0.0", "ICMP");
        nodes = [self.tree.find("1.1.1.1"), self.tree.find("2.2.2.2"), self.tree.find("3.3.3.3"), self.tree.find("0.0.0.0")];

        self.assertEqual(route, nodes);

class SeparatedNetworkTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tree = Tree();
        cls.networkOne = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"];
        cls.networkTwo = ["1.1.1.1", "5.5.5.5", "6.6.6.6", "7.7.7.7"]

        for network in [cls.networkOne, cls.networkTwo]:
            for address in network:
                cls.tree.append(address, network[len(network) - 1], "ICMP");

    def test01CheckGetRoute(self):
        for network in [self.networkOne, self.networkTwo]:
            with self.subTest(network=network):
                route = self.tree.getRoute(network[len(network) - 1], "ICMP");
                nodes = [self.tree.find(x) for x in network];
                
                self.assertEqual(route, nodes);

    # should be implemented later to check if all routing tables are accurate
    def test02CheckRoutingTable(self):
        pass

class MergedNetworkTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tree = Tree();
        cls.networkOne = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"];
        cls.networkTwo = ["1.1.1.1", "5.5.5.5", "3.3.3.3", "7.7.7.7"]

        for network in [cls.networkOne, cls.networkTwo]:
            for address in network:
                cls.tree.append(address, network[-1], "ICMP");

    def test01CheckGetRoute(self):
        for network in [self.networkOne, self.networkTwo]:
            with self.subTest(network=network):
                route = self.tree.getRoute(network[-1], "ICMP");
                nodes = [self.tree.find(x) for x in network];
                
                self.assertEqual(route, nodes);

        node = self.tree.find("3.3.3.3");
        self.assertEqual(len(node.routes), 2);
        self.assertEqual(node.routes[Route(self.networkOne[-1], "ICMP")], self.tree.find(self.networkOne[-1]));
        self.assertEqual(node.routes[Route(self.networkTwo[-1], "ICMP")], self.tree.find(self.networkTwo[-1]));

if(__name__ == '__main__'):
    unittest.main();
