import json
import grpc
import time
import re


import pyvelociraptor
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc


def run(config, query, verbose):
    creds = grpc.ssl_channel_credentials(
        root_certificates=config["ca_certificate"].encode("utf8"),
        private_key=config["client_private_key"].encode("utf8"),
        certificate_chain=config["client_cert"].encode("utf8"))

    options = (('grpc.ssl_target_name_override', "VelociraptorServer",),)

    with grpc.secure_channel(config["api_connection_string"],
                             creds, options) as channel:
        stub = api_pb2_grpc.APIStub(channel)

        request = api_pb2.VQLCollectorArgs(
            max_wait=10000,
            max_row=10000,
            Query=[api_pb2.VQLRequest(
                Name="Hunt",
                VQL=query,
            )],
        )
        data = ""
        for response in stub.Query(request):
            if response.Response:
                package = json.loads(response.Response)
                # print(package)
                
            elif response.log:
                # print ("%s: %s" % (time.ctime(response.timestamp / 1000000), response.log))
                match = re.search(r'\[.*\]', response.log, re.DOTALL)
                if match: 
                    data = match.group(0)

        return str(package)

def Run_velociraptor_query(query, verbose=False):

    config = pyvelociraptor.LoadConfigFile("./config/api.config.yaml")
    data = run(config, query, verbose)
    return data