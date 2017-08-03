#encoding=utf-8
import sys
import signal
import time
import grpc
from config import config
from iptables import Iptables
from shadowsocks import Shadowsocks
from concurrent import futures
from proto import kratos_pb2
from proto import kratos_pb2_grpc

class KratosServiceServicer(kratos_pb2_grpc.KratosServiceServicer):

    def Status(self, request, context):
        counter_map = Iptables.getCounterMap()
        resp = kratos_pb2.StatusResponse()
        
        for port, traffic in counter_map.items():
            counter_info = resp.couter_info.add()
            counter_info.host = config['host']
            counter_info.port = port
            counter_info.inbound_traffic = traffic['inbound_traffic']
            counter_info.outbound_traffic = traffic['outbound_traffic']

        return resp

    def AddRule(self, request, context):
        resp = kratos_pb2.AddRuleResponse()
        add_ret = Iptables.addRule(request.port, request.traffic_qouta)
        if not add_ret:
            resp.error_code = kratos_pb2.ERROR_ADD_RULE_FAILED
            resp.error_msg = 'add rule failed'
            return resp
        
        return resp

    def DeleteRule(self, request, context):
        resp = kratos_pb2.DeleteRuleResponse()
        del_ret = Iptables.deleteRule(request.port)
        if not del_ret:
            resp.error_code = kratos_pb2.ERROR_DELETE_RULE_FAILED
            resp.error_msg = 'delete rule failed'
            return resp

        return resp

    def ResetCounter(self, request, context):
        resp = kratos_pb2.ResetCounterResponse()
        reset_ret = Iptables.resetCounter()
        if not reset_ret:
            resp.error_code = kratos_pb2.ERROR_RESET_FAILED
            resp.error_msg = 'reset counter failed'
            return resp

        return resp

    def AddService(self, request, context):
        resp = kratos_pb2.AddServiceResponse()
        add_ret = Shadowsocks.addService(request.port, request.traffic_qouta, request.config)
        if not add_ret:
            resp.error_code = kratos_pb2.ERROR_ADD_SERVICE_FAILED
            resp.error_msg = 'add service failed'
            return resp

        return resp

    def DeleteService(self, request, context):
        resp = kratos_pb2.DeleteServiceResponse()
        del_ret = Shadowsocks.deleteService(request.port)
        if not del_ret:
            resp.error_code = kratos_pb2.ERROR_DELETE_SERVICE_FAILED
            resp.error_msg = 'delete service failed'
            return resp

        return resp


def serve():
    server_credentials = grpc.ssl_server_credentials(((config['prikey'], config['cert'],),))
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    kratos_pb2_grpc.add_KratosServiceServicer_to_server(KratosServiceServicer(), server)
    server.add_secure_port('[::]:%s' % (config['port']), server_credentials)
    server.start()
    
    try:
        while True:
            signal.pause()
    except KeyboardInterrupt:
        pass
    server.stop(0)

