import sys
sys.path.insert(0, 'C:\\Program Files\\Graphviz\\bin')
import json
import graphviz
dot = graphviz.Digraph(comment='zap graph')

node_key = '0339e68a50c8f0fc342ffdbd866ad9fb1147455b7c8b85ddd84361db8b67883ff1'
zap_key = '02fe153690061fa27049bae0faa236ddb95df98c514416a350449c24a8018851dc'
MAX_NODES = 100

nodes = {}

with open('zap_graph.json','r', encoding="cp866") as r:
	js = json.loads(r.read())
	for i,e in enumerate(js['nodes']):
		pkey = e['pub_key']
		if pkey not in nodes:
		 	nodes[pkey] = e['alias']
		if i < MAX_NODES or node_key == pkey or zap_key == pkey:
			if node_key == pkey:
				dot.node(pkey, 'Local')
			elif zap_key == pkey:
				dot.node(pkey, 'Zap')
			# else:
			# 	dot.node(pkey, repr(nodes[pkey]))

	for i,e in enumerate(js['edges']):
		if i < MAX_NODES or node_key == e['node1_pub'] or node_key == e['node2_pub'] or zap_key == e['node1_pub'] or zap_key == e['node2_pub']:
			dot.edge(e['node1_pub'][:5], e['node2_pub'][:5])
print(dot.source)
# dot.render('zap_graph')
sys.stderr.write(f'nodes: {len(nodes)}\n')