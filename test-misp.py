from pymisp import PyMISP

misp = PyMISP("https://192.168.1.101/", hW0DZztasm17mclsC4lkkPgFq6n8JY4ohKRPk4v5, False)
print(misp.direct_call('servers/getVersion.json'))
