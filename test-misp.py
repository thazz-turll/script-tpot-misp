from pymisp import ExpandedPyMISP

misp_url = "https://192.168.1.101/"
misp_key = "hW0DZztasm17mclsC4lkkPgFq6n8JY4ohKRPk4v5"  # key của bạn
misp_verifycert = False
misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)

# Cách 1: Gọi hàm server_info() để kiểm tra
info = misp.server_info()
print(info)
