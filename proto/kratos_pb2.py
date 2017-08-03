# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: kratos.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='kratos.proto',
  package='kratos',
  syntax='proto3',
  serialized_pb=_b('\n\x0ckratos.proto\x12\x06kratos\"\\\n\x0b\x43ounterInfo\x12\x0c\n\x04host\x18\x01 \x01(\t\x12\x0c\n\x04port\x18\x02 \x01(\x05\x12\x17\n\x0finbound_traffic\x18\x03 \x01(\x03\x12\x18\n\x10outbound_traffic\x18\x04 \x01(\x03\"\x0f\n\rStatusRequest\"5\n\x0e\x41\x64\x64RuleRequest\x12\x0c\n\x04port\x18\x01 \x01(\x05\x12\x15\n\rtraffic_qouta\x18\x02 \x01(\x03\"!\n\x11\x44\x65leteRuleRequest\x12\x0c\n\x04port\x18\x01 \x01(\x05\"\x15\n\x13ResetCounterRequest\"H\n\x11\x41\x64\x64ServiceRequest\x12\x0c\n\x04port\x18\x01 \x01(\x05\x12\x15\n\rtraffic_qouta\x18\x02 \x01(\x03\x12\x0e\n\x06\x63onfig\x18\x03 \x01(\t\"$\n\x14\x44\x65leteServiceRequest\x12\x0c\n\x04port\x18\x01 \x01(\x05\"a\n\x0eStatusResponse\x12\x12\n\nerror_code\x18\x01 \x01(\x05\x12\x11\n\terror_msg\x18\x02 \x01(\t\x12(\n\x0b\x63outer_info\x18\x03 \x03(\x0b\x32\x13.kratos.CounterInfo\"8\n\x0f\x41\x64\x64RuleResponse\x12\x12\n\nerror_code\x18\x01 \x01(\x05\x12\x11\n\terror_msg\x18\x02 \x01(\t\";\n\x12\x44\x65leteRuleResponse\x12\x12\n\nerror_code\x18\x01 \x01(\x05\x12\x11\n\terror_msg\x18\x02 \x01(\t\"=\n\x14ResetCounterResponse\x12\x12\n\nerror_code\x18\x01 \x01(\x05\x12\x11\n\terror_msg\x18\x02 \x01(\t\";\n\x12\x41\x64\x64ServiceResponse\x12\x12\n\nerror_code\x18\x01 \x01(\x05\x12\x11\n\terror_msg\x18\x02 \x01(\t\">\n\x15\x44\x65leteServiceResponse\x12\x12\n\nerror_code\x18\x01 \x01(\x05\x12\x11\n\terror_msg\x18\x02 \x01(\t*\xab\x01\n\tErrorCode\x12\x0e\n\nERROR_NONE\x10\x00\x12\x16\n\x12\x45RROR_RESET_FAILED\x10\x01\x12\x19\n\x15\x45RROR_ADD_RULE_FAILED\x10\x02\x12\x1c\n\x18\x45RROR_DELETE_RULE_FAILED\x10\x03\x12\x1c\n\x18\x45RROR_ADD_SERVICE_FAILED\x10\x04\x12\x1f\n\x1b\x45RROR_DELETE_SERVICE_FAILED\x10\x05\x32\xb3\x03\n\rKratosService\x12\x39\n\x06Status\x12\x15.kratos.StatusRequest\x1a\x16.kratos.StatusResponse\"\x00\x12<\n\x07\x41\x64\x64Rule\x12\x16.kratos.AddRuleRequest\x1a\x17.kratos.AddRuleResponse\"\x00\x12\x45\n\nDeleteRule\x12\x19.kratos.DeleteRuleRequest\x1a\x1a.kratos.DeleteRuleResponse\"\x00\x12K\n\x0cResetCounter\x12\x1b.kratos.ResetCounterRequest\x1a\x1c.kratos.ResetCounterResponse\"\x00\x12\x45\n\nAddService\x12\x19.kratos.AddServiceRequest\x1a\x1a.kratos.AddServiceResponse\"\x00\x12N\n\rDeleteService\x12\x1c.kratos.DeleteServiceRequest\x1a\x1d.kratos.DeleteServiceResponse\"\x00\x62\x06proto3')
)
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

_ERRORCODE = _descriptor.EnumDescriptor(
  name='ErrorCode',
  full_name='kratos.ErrorCode',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='ERROR_NONE', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ERROR_RESET_FAILED', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ERROR_ADD_RULE_FAILED', index=2, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ERROR_DELETE_RULE_FAILED', index=3, number=3,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ERROR_ADD_SERVICE_FAILED', index=4, number=4,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ERROR_DELETE_SERVICE_FAILED', index=5, number=5,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=767,
  serialized_end=938,
)
_sym_db.RegisterEnumDescriptor(_ERRORCODE)

ErrorCode = enum_type_wrapper.EnumTypeWrapper(_ERRORCODE)
ERROR_NONE = 0
ERROR_RESET_FAILED = 1
ERROR_ADD_RULE_FAILED = 2
ERROR_DELETE_RULE_FAILED = 3
ERROR_ADD_SERVICE_FAILED = 4
ERROR_DELETE_SERVICE_FAILED = 5



_COUNTERINFO = _descriptor.Descriptor(
  name='CounterInfo',
  full_name='kratos.CounterInfo',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='host', full_name='kratos.CounterInfo.host', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='port', full_name='kratos.CounterInfo.port', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='inbound_traffic', full_name='kratos.CounterInfo.inbound_traffic', index=2,
      number=3, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='outbound_traffic', full_name='kratos.CounterInfo.outbound_traffic', index=3,
      number=4, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=24,
  serialized_end=116,
)


_STATUSREQUEST = _descriptor.Descriptor(
  name='StatusRequest',
  full_name='kratos.StatusRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=118,
  serialized_end=133,
)


_ADDRULEREQUEST = _descriptor.Descriptor(
  name='AddRuleRequest',
  full_name='kratos.AddRuleRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='port', full_name='kratos.AddRuleRequest.port', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='traffic_qouta', full_name='kratos.AddRuleRequest.traffic_qouta', index=1,
      number=2, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=135,
  serialized_end=188,
)


_DELETERULEREQUEST = _descriptor.Descriptor(
  name='DeleteRuleRequest',
  full_name='kratos.DeleteRuleRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='port', full_name='kratos.DeleteRuleRequest.port', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=190,
  serialized_end=223,
)


_RESETCOUNTERREQUEST = _descriptor.Descriptor(
  name='ResetCounterRequest',
  full_name='kratos.ResetCounterRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=225,
  serialized_end=246,
)


_ADDSERVICEREQUEST = _descriptor.Descriptor(
  name='AddServiceRequest',
  full_name='kratos.AddServiceRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='port', full_name='kratos.AddServiceRequest.port', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='traffic_qouta', full_name='kratos.AddServiceRequest.traffic_qouta', index=1,
      number=2, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='config', full_name='kratos.AddServiceRequest.config', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=248,
  serialized_end=320,
)


_DELETESERVICEREQUEST = _descriptor.Descriptor(
  name='DeleteServiceRequest',
  full_name='kratos.DeleteServiceRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='port', full_name='kratos.DeleteServiceRequest.port', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=322,
  serialized_end=358,
)


_STATUSRESPONSE = _descriptor.Descriptor(
  name='StatusResponse',
  full_name='kratos.StatusResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='error_code', full_name='kratos.StatusResponse.error_code', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='error_msg', full_name='kratos.StatusResponse.error_msg', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='couter_info', full_name='kratos.StatusResponse.couter_info', index=2,
      number=3, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=360,
  serialized_end=457,
)


_ADDRULERESPONSE = _descriptor.Descriptor(
  name='AddRuleResponse',
  full_name='kratos.AddRuleResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='error_code', full_name='kratos.AddRuleResponse.error_code', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='error_msg', full_name='kratos.AddRuleResponse.error_msg', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=459,
  serialized_end=515,
)


_DELETERULERESPONSE = _descriptor.Descriptor(
  name='DeleteRuleResponse',
  full_name='kratos.DeleteRuleResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='error_code', full_name='kratos.DeleteRuleResponse.error_code', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='error_msg', full_name='kratos.DeleteRuleResponse.error_msg', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=517,
  serialized_end=576,
)


_RESETCOUNTERRESPONSE = _descriptor.Descriptor(
  name='ResetCounterResponse',
  full_name='kratos.ResetCounterResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='error_code', full_name='kratos.ResetCounterResponse.error_code', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='error_msg', full_name='kratos.ResetCounterResponse.error_msg', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=578,
  serialized_end=639,
)


_ADDSERVICERESPONSE = _descriptor.Descriptor(
  name='AddServiceResponse',
  full_name='kratos.AddServiceResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='error_code', full_name='kratos.AddServiceResponse.error_code', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='error_msg', full_name='kratos.AddServiceResponse.error_msg', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=641,
  serialized_end=700,
)


_DELETESERVICERESPONSE = _descriptor.Descriptor(
  name='DeleteServiceResponse',
  full_name='kratos.DeleteServiceResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='error_code', full_name='kratos.DeleteServiceResponse.error_code', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='error_msg', full_name='kratos.DeleteServiceResponse.error_msg', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=702,
  serialized_end=764,
)

_STATUSRESPONSE.fields_by_name['couter_info'].message_type = _COUNTERINFO
DESCRIPTOR.message_types_by_name['CounterInfo'] = _COUNTERINFO
DESCRIPTOR.message_types_by_name['StatusRequest'] = _STATUSREQUEST
DESCRIPTOR.message_types_by_name['AddRuleRequest'] = _ADDRULEREQUEST
DESCRIPTOR.message_types_by_name['DeleteRuleRequest'] = _DELETERULEREQUEST
DESCRIPTOR.message_types_by_name['ResetCounterRequest'] = _RESETCOUNTERREQUEST
DESCRIPTOR.message_types_by_name['AddServiceRequest'] = _ADDSERVICEREQUEST
DESCRIPTOR.message_types_by_name['DeleteServiceRequest'] = _DELETESERVICEREQUEST
DESCRIPTOR.message_types_by_name['StatusResponse'] = _STATUSRESPONSE
DESCRIPTOR.message_types_by_name['AddRuleResponse'] = _ADDRULERESPONSE
DESCRIPTOR.message_types_by_name['DeleteRuleResponse'] = _DELETERULERESPONSE
DESCRIPTOR.message_types_by_name['ResetCounterResponse'] = _RESETCOUNTERRESPONSE
DESCRIPTOR.message_types_by_name['AddServiceResponse'] = _ADDSERVICERESPONSE
DESCRIPTOR.message_types_by_name['DeleteServiceResponse'] = _DELETESERVICERESPONSE
DESCRIPTOR.enum_types_by_name['ErrorCode'] = _ERRORCODE

CounterInfo = _reflection.GeneratedProtocolMessageType('CounterInfo', (_message.Message,), dict(
  DESCRIPTOR = _COUNTERINFO,
  __module__ = 'kratos_pb2'
  # @@protoc_insertion_point(class_scope:kratos.CounterInfo)
  ))
_sym_db.RegisterMessage(CounterInfo)

StatusRequest = _reflection.GeneratedProtocolMessageType('StatusRequest', (_message.Message,), dict(
  DESCRIPTOR = _STATUSREQUEST,
  __module__ = 'kratos_pb2'
  # @@protoc_insertion_point(class_scope:kratos.StatusRequest)
  ))
_sym_db.RegisterMessage(StatusRequest)

AddRuleRequest = _reflection.GeneratedProtocolMessageType('AddRuleRequest', (_message.Message,), dict(
  DESCRIPTOR = _ADDRULEREQUEST,
  __module__ = 'kratos_pb2'
  # @@protoc_insertion_point(class_scope:kratos.AddRuleRequest)
  ))
_sym_db.RegisterMessage(AddRuleRequest)

DeleteRuleRequest = _reflection.GeneratedProtocolMessageType('DeleteRuleRequest', (_message.Message,), dict(
  DESCRIPTOR = _DELETERULEREQUEST,
  __module__ = 'kratos_pb2'
  # @@protoc_insertion_point(class_scope:kratos.DeleteRuleRequest)
  ))
_sym_db.RegisterMessage(DeleteRuleRequest)

ResetCounterRequest = _reflection.GeneratedProtocolMessageType('ResetCounterRequest', (_message.Message,), dict(
  DESCRIPTOR = _RESETCOUNTERREQUEST,
  __module__ = 'kratos_pb2'
  # @@protoc_insertion_point(class_scope:kratos.ResetCounterRequest)
  ))
_sym_db.RegisterMessage(ResetCounterRequest)

AddServiceRequest = _reflection.GeneratedProtocolMessageType('AddServiceRequest', (_message.Message,), dict(
  DESCRIPTOR = _ADDSERVICEREQUEST,
  __module__ = 'kratos_pb2'
  # @@protoc_insertion_point(class_scope:kratos.AddServiceRequest)
  ))
_sym_db.RegisterMessage(AddServiceRequest)

DeleteServiceRequest = _reflection.GeneratedProtocolMessageType('DeleteServiceRequest', (_message.Message,), dict(
  DESCRIPTOR = _DELETESERVICEREQUEST,
  __module__ = 'kratos_pb2'
  # @@protoc_insertion_point(class_scope:kratos.DeleteServiceRequest)
  ))
_sym_db.RegisterMessage(DeleteServiceRequest)

StatusResponse = _reflection.GeneratedProtocolMessageType('StatusResponse', (_message.Message,), dict(
  DESCRIPTOR = _STATUSRESPONSE,
  __module__ = 'kratos_pb2'
  # @@protoc_insertion_point(class_scope:kratos.StatusResponse)
  ))
_sym_db.RegisterMessage(StatusResponse)

AddRuleResponse = _reflection.GeneratedProtocolMessageType('AddRuleResponse', (_message.Message,), dict(
  DESCRIPTOR = _ADDRULERESPONSE,
  __module__ = 'kratos_pb2'
  # @@protoc_insertion_point(class_scope:kratos.AddRuleResponse)
  ))
_sym_db.RegisterMessage(AddRuleResponse)

DeleteRuleResponse = _reflection.GeneratedProtocolMessageType('DeleteRuleResponse', (_message.Message,), dict(
  DESCRIPTOR = _DELETERULERESPONSE,
  __module__ = 'kratos_pb2'
  # @@protoc_insertion_point(class_scope:kratos.DeleteRuleResponse)
  ))
_sym_db.RegisterMessage(DeleteRuleResponse)

ResetCounterResponse = _reflection.GeneratedProtocolMessageType('ResetCounterResponse', (_message.Message,), dict(
  DESCRIPTOR = _RESETCOUNTERRESPONSE,
  __module__ = 'kratos_pb2'
  # @@protoc_insertion_point(class_scope:kratos.ResetCounterResponse)
  ))
_sym_db.RegisterMessage(ResetCounterResponse)

AddServiceResponse = _reflection.GeneratedProtocolMessageType('AddServiceResponse', (_message.Message,), dict(
  DESCRIPTOR = _ADDSERVICERESPONSE,
  __module__ = 'kratos_pb2'
  # @@protoc_insertion_point(class_scope:kratos.AddServiceResponse)
  ))
_sym_db.RegisterMessage(AddServiceResponse)

DeleteServiceResponse = _reflection.GeneratedProtocolMessageType('DeleteServiceResponse', (_message.Message,), dict(
  DESCRIPTOR = _DELETESERVICERESPONSE,
  __module__ = 'kratos_pb2'
  # @@protoc_insertion_point(class_scope:kratos.DeleteServiceResponse)
  ))
_sym_db.RegisterMessage(DeleteServiceResponse)


try:
  # THESE ELEMENTS WILL BE DEPRECATED.
  # Please use the generated *_pb2_grpc.py files instead.
  import grpc
  from grpc.beta import implementations as beta_implementations
  from grpc.beta import interfaces as beta_interfaces
  from grpc.framework.common import cardinality
  from grpc.framework.interfaces.face import utilities as face_utilities


  class KratosServiceStub(object):

    def __init__(self, channel):
      """Constructor.

      Args:
        channel: A grpc.Channel.
      """
      self.Status = channel.unary_unary(
          '/kratos.KratosService/Status',
          request_serializer=StatusRequest.SerializeToString,
          response_deserializer=StatusResponse.FromString,
          )
      self.AddRule = channel.unary_unary(
          '/kratos.KratosService/AddRule',
          request_serializer=AddRuleRequest.SerializeToString,
          response_deserializer=AddRuleResponse.FromString,
          )
      self.DeleteRule = channel.unary_unary(
          '/kratos.KratosService/DeleteRule',
          request_serializer=DeleteRuleRequest.SerializeToString,
          response_deserializer=DeleteRuleResponse.FromString,
          )
      self.ResetCounter = channel.unary_unary(
          '/kratos.KratosService/ResetCounter',
          request_serializer=ResetCounterRequest.SerializeToString,
          response_deserializer=ResetCounterResponse.FromString,
          )
      self.AddService = channel.unary_unary(
          '/kratos.KratosService/AddService',
          request_serializer=AddServiceRequest.SerializeToString,
          response_deserializer=AddServiceResponse.FromString,
          )
      self.DeleteService = channel.unary_unary(
          '/kratos.KratosService/DeleteService',
          request_serializer=DeleteServiceRequest.SerializeToString,
          response_deserializer=DeleteServiceResponse.FromString,
          )


  class KratosServiceServicer(object):

    def Status(self, request, context):
      context.set_code(grpc.StatusCode.UNIMPLEMENTED)
      context.set_details('Method not implemented!')
      raise NotImplementedError('Method not implemented!')

    def AddRule(self, request, context):
      context.set_code(grpc.StatusCode.UNIMPLEMENTED)
      context.set_details('Method not implemented!')
      raise NotImplementedError('Method not implemented!')

    def DeleteRule(self, request, context):
      context.set_code(grpc.StatusCode.UNIMPLEMENTED)
      context.set_details('Method not implemented!')
      raise NotImplementedError('Method not implemented!')

    def ResetCounter(self, request, context):
      context.set_code(grpc.StatusCode.UNIMPLEMENTED)
      context.set_details('Method not implemented!')
      raise NotImplementedError('Method not implemented!')

    def AddService(self, request, context):
      context.set_code(grpc.StatusCode.UNIMPLEMENTED)
      context.set_details('Method not implemented!')
      raise NotImplementedError('Method not implemented!')

    def DeleteService(self, request, context):
      context.set_code(grpc.StatusCode.UNIMPLEMENTED)
      context.set_details('Method not implemented!')
      raise NotImplementedError('Method not implemented!')


  def add_KratosServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
        'Status': grpc.unary_unary_rpc_method_handler(
            servicer.Status,
            request_deserializer=StatusRequest.FromString,
            response_serializer=StatusResponse.SerializeToString,
        ),
        'AddRule': grpc.unary_unary_rpc_method_handler(
            servicer.AddRule,
            request_deserializer=AddRuleRequest.FromString,
            response_serializer=AddRuleResponse.SerializeToString,
        ),
        'DeleteRule': grpc.unary_unary_rpc_method_handler(
            servicer.DeleteRule,
            request_deserializer=DeleteRuleRequest.FromString,
            response_serializer=DeleteRuleResponse.SerializeToString,
        ),
        'ResetCounter': grpc.unary_unary_rpc_method_handler(
            servicer.ResetCounter,
            request_deserializer=ResetCounterRequest.FromString,
            response_serializer=ResetCounterResponse.SerializeToString,
        ),
        'AddService': grpc.unary_unary_rpc_method_handler(
            servicer.AddService,
            request_deserializer=AddServiceRequest.FromString,
            response_serializer=AddServiceResponse.SerializeToString,
        ),
        'DeleteService': grpc.unary_unary_rpc_method_handler(
            servicer.DeleteService,
            request_deserializer=DeleteServiceRequest.FromString,
            response_serializer=DeleteServiceResponse.SerializeToString,
        ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
        'kratos.KratosService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


  class BetaKratosServiceServicer(object):
    """The Beta API is deprecated for 0.15.0 and later.

    It is recommended to use the GA API (classes and functions in this
    file not marked beta) for all further purposes. This class was generated
    only to ease transition from grpcio<0.15.0 to grpcio>=0.15.0."""
    def Status(self, request, context):
      context.code(beta_interfaces.StatusCode.UNIMPLEMENTED)
    def AddRule(self, request, context):
      context.code(beta_interfaces.StatusCode.UNIMPLEMENTED)
    def DeleteRule(self, request, context):
      context.code(beta_interfaces.StatusCode.UNIMPLEMENTED)
    def ResetCounter(self, request, context):
      context.code(beta_interfaces.StatusCode.UNIMPLEMENTED)
    def AddService(self, request, context):
      context.code(beta_interfaces.StatusCode.UNIMPLEMENTED)
    def DeleteService(self, request, context):
      context.code(beta_interfaces.StatusCode.UNIMPLEMENTED)


  class BetaKratosServiceStub(object):
    """The Beta API is deprecated for 0.15.0 and later.

    It is recommended to use the GA API (classes and functions in this
    file not marked beta) for all further purposes. This class was generated
    only to ease transition from grpcio<0.15.0 to grpcio>=0.15.0."""
    def Status(self, request, timeout, metadata=None, with_call=False, protocol_options=None):
      raise NotImplementedError()
    Status.future = None
    def AddRule(self, request, timeout, metadata=None, with_call=False, protocol_options=None):
      raise NotImplementedError()
    AddRule.future = None
    def DeleteRule(self, request, timeout, metadata=None, with_call=False, protocol_options=None):
      raise NotImplementedError()
    DeleteRule.future = None
    def ResetCounter(self, request, timeout, metadata=None, with_call=False, protocol_options=None):
      raise NotImplementedError()
    ResetCounter.future = None
    def AddService(self, request, timeout, metadata=None, with_call=False, protocol_options=None):
      raise NotImplementedError()
    AddService.future = None
    def DeleteService(self, request, timeout, metadata=None, with_call=False, protocol_options=None):
      raise NotImplementedError()
    DeleteService.future = None


  def beta_create_KratosService_server(servicer, pool=None, pool_size=None, default_timeout=None, maximum_timeout=None):
    """The Beta API is deprecated for 0.15.0 and later.

    It is recommended to use the GA API (classes and functions in this
    file not marked beta) for all further purposes. This function was
    generated only to ease transition from grpcio<0.15.0 to grpcio>=0.15.0"""
    request_deserializers = {
      ('kratos.KratosService', 'AddRule'): AddRuleRequest.FromString,
      ('kratos.KratosService', 'AddService'): AddServiceRequest.FromString,
      ('kratos.KratosService', 'DeleteRule'): DeleteRuleRequest.FromString,
      ('kratos.KratosService', 'DeleteService'): DeleteServiceRequest.FromString,
      ('kratos.KratosService', 'ResetCounter'): ResetCounterRequest.FromString,
      ('kratos.KratosService', 'Status'): StatusRequest.FromString,
    }
    response_serializers = {
      ('kratos.KratosService', 'AddRule'): AddRuleResponse.SerializeToString,
      ('kratos.KratosService', 'AddService'): AddServiceResponse.SerializeToString,
      ('kratos.KratosService', 'DeleteRule'): DeleteRuleResponse.SerializeToString,
      ('kratos.KratosService', 'DeleteService'): DeleteServiceResponse.SerializeToString,
      ('kratos.KratosService', 'ResetCounter'): ResetCounterResponse.SerializeToString,
      ('kratos.KratosService', 'Status'): StatusResponse.SerializeToString,
    }
    method_implementations = {
      ('kratos.KratosService', 'AddRule'): face_utilities.unary_unary_inline(servicer.AddRule),
      ('kratos.KratosService', 'AddService'): face_utilities.unary_unary_inline(servicer.AddService),
      ('kratos.KratosService', 'DeleteRule'): face_utilities.unary_unary_inline(servicer.DeleteRule),
      ('kratos.KratosService', 'DeleteService'): face_utilities.unary_unary_inline(servicer.DeleteService),
      ('kratos.KratosService', 'ResetCounter'): face_utilities.unary_unary_inline(servicer.ResetCounter),
      ('kratos.KratosService', 'Status'): face_utilities.unary_unary_inline(servicer.Status),
    }
    server_options = beta_implementations.server_options(request_deserializers=request_deserializers, response_serializers=response_serializers, thread_pool=pool, thread_pool_size=pool_size, default_timeout=default_timeout, maximum_timeout=maximum_timeout)
    return beta_implementations.server(method_implementations, options=server_options)


  def beta_create_KratosService_stub(channel, host=None, metadata_transformer=None, pool=None, pool_size=None):
    """The Beta API is deprecated for 0.15.0 and later.

    It is recommended to use the GA API (classes and functions in this
    file not marked beta) for all further purposes. This function was
    generated only to ease transition from grpcio<0.15.0 to grpcio>=0.15.0"""
    request_serializers = {
      ('kratos.KratosService', 'AddRule'): AddRuleRequest.SerializeToString,
      ('kratos.KratosService', 'AddService'): AddServiceRequest.SerializeToString,
      ('kratos.KratosService', 'DeleteRule'): DeleteRuleRequest.SerializeToString,
      ('kratos.KratosService', 'DeleteService'): DeleteServiceRequest.SerializeToString,
      ('kratos.KratosService', 'ResetCounter'): ResetCounterRequest.SerializeToString,
      ('kratos.KratosService', 'Status'): StatusRequest.SerializeToString,
    }
    response_deserializers = {
      ('kratos.KratosService', 'AddRule'): AddRuleResponse.FromString,
      ('kratos.KratosService', 'AddService'): AddServiceResponse.FromString,
      ('kratos.KratosService', 'DeleteRule'): DeleteRuleResponse.FromString,
      ('kratos.KratosService', 'DeleteService'): DeleteServiceResponse.FromString,
      ('kratos.KratosService', 'ResetCounter'): ResetCounterResponse.FromString,
      ('kratos.KratosService', 'Status'): StatusResponse.FromString,
    }
    cardinalities = {
      'AddRule': cardinality.Cardinality.UNARY_UNARY,
      'AddService': cardinality.Cardinality.UNARY_UNARY,
      'DeleteRule': cardinality.Cardinality.UNARY_UNARY,
      'DeleteService': cardinality.Cardinality.UNARY_UNARY,
      'ResetCounter': cardinality.Cardinality.UNARY_UNARY,
      'Status': cardinality.Cardinality.UNARY_UNARY,
    }
    stub_options = beta_implementations.stub_options(host=host, metadata_transformer=metadata_transformer, request_serializers=request_serializers, response_deserializers=response_deserializers, thread_pool=pool, thread_pool_size=pool_size)
    return beta_implementations.dynamic_stub(channel, 'kratos.KratosService', cardinalities, options=stub_options)
except ImportError:
  pass
# @@protoc_insertion_point(module_scope)