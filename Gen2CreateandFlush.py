from operator import ge
from urllib import request
from wsgiref import headers
import requests
import os
import datetime


def createFilePathAndFlushGen2(token, gen2_path, local_file_path=""):
    date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    bearer_token = f'Bearer {token}'

    # read in local file to write
    if local_file_path == "":
        local_file_path = '/home/otilio/Documents/PythonDaemonData.csv'
    f = open(local_file_path, 'r')
    file_size = os.path.getsize(local_file_path)

    request_base_url = gen2_path

    # define URLs for each request
    create_file_url = f"{gen2_path}?resource=file"
    append_file_url = f"{gen2_path}?action=append&position=0"
    flush_file_url = f"{gen2_path}?action=flush&position={file_size}"

    # Define headers for each request
    base_headers = {
        "x-ms-version": "2019-12-12",
        "x-ms-date": date,
        "Authorization": bearer_token,
        "Content-type": "application/json"
    }

    create_flush_headers = base_headers.copy()
    create_flush_headers['Content-Length'] = "0"
    append_header = base_headers.copy()
    append_header['Content-Length'] = str(file_size)

    # Begin requests
    print("Attempting to create file path in the lake:")
    create_path = requests.put(create_file_url, headers=create_flush_headers)
    print(f"Status: {create_path.status_code}. Content: {create_path.content}")

    print("---------------------------------------------------------------------")
    if(create_path.status_code == 201):
        print("Attempting to append date to newly created path:")
        append_data = requests.patch(
            append_file_url, data=f, headers=append_header)
        print(
            f"Status Code: {append_data.status_code}. Content: {append_data.content}")
        print("---------------------------------------------------------------------")
        if(append_data.status_code == 202):
            print("Attempting to flush data to blob.")
            flush_data = requests.patch(
                flush_file_url, headers=create_flush_headers)
            print(
                f"Status Code: {flush_data.status_code}. Content: {flush_data.content}")
            print("---------------------------------------------------------------------")


# update token and file information before running
if __name__ == '__main__':
    createFilePathAndFlushGen2("some_token_here", "https://otiorgdatalake.dfs.core.windows.net/raw/123Directory/pythonMainFunction",
                               "/home/otilio/Documents/PythonDaemonData.csv")
