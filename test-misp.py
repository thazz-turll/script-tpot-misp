from pymisp import PyMISP

misp = PyMISP("https://192.168.1.101/", "<API_KEY>", False)
print(misp.direct_call('servers/getVersion.json'))
