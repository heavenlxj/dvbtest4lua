--------------------------------------------------------------------------------------
-----------------------------EMMG/PDG protocol error values---------------------------
--------------------------------------------------------------------------------------


EMMG_ERROR_STATUS_VALUE_MAP = {
								[0x0000] = 'DVB Reserved',
								[0x0001] = 'invalid message',
								[0x0002] = 'unsupported protocol version',
								[0x0003] = 'unknown message_type value',
								[0x0004] = 'message too long',
								[0x0005] = 'unknown data_stream_id value',
								[0x0006] = 'unknown data_channel_id value',
								[0x0007] = 'too many channels on this MUX',
								[0x0008] = 'too many data streams on this channel',
								[0x0009] = 'too many data streams on this MUX',
								[0x000A] = 'unknown parameter_type',
								[0x000B] = 'inconsistent length for DVB parameter',
								[0x000C] = 'missing mandatory DVB parameter',
								[0x000D] = 'invalid value for DVB parameter',
								[0x000E] = 'unknown client_id value',
								[0x000F] = 'exceeded bandwidth',
								[0x0010] = 'unknown data_id value',
								[0x0011] = 'data_channel_id value already in use',
								[0x0012] = 'data_stream_id value already in use',
								[0x0013] = 'data_id value already in use',
								[0x0014] = 'client_id value already in use',
								[0x7000] = 'unknown error',
								[0x7001] = 'unrecoverable error'

}


------------------------------------------------------------------------------------------------
-----------------------------ECMG protocol error values-----------------------------------------
------------------------------------------------------------------------------------------------

ECMG_ERROR_STATUS_VALUE_MAP = {
								[0x0000] = 'DVB Reserved',
								[0x0001] = 'invalid message',
								[0x0002] = 'unsupported protocol version',
								[0x0003] = 'unknown message_type value',
								[0x0004] = 'message too long',
								[0x0005] = 'unknown Super_CAS_id value',
								[0x0006] = 'unknown ECM_channel_id value',
								[0x0007] = 'unknown ECM_stream_id value',
								[0x0008] = 'too many channels on this ECMG',
								[0x0009] = 'too many ECM streams on this channel',
								[0x000A] = 'too many ECM streams on this ECMG',
								[0x000B] = 'not enough control words to compute ECM',
								[0x000C] = 'ECMG out of storage capacity',
								[0x000D] = 'ECMG out of computational resources',
								[0x000E] = 'unknown parameter_type value',
								[0x000F] = 'inconsistent length for DVB parameter',
								[0x0010] = 'missing mandatory DVB parameter',
								[0x0011] = 'invalid value for DVB parameter',
								[0x0012] = 'unknown ECM_id value',
								[0x0013] = 'ECM_channel_id value already in use',
								[0x0014] = 'ECM_stream_id value already in use',
								[0x0015] = 'ECM_id value already in use',
								[0x7000] = 'unknown error',
								[0x7001] = 'unrecoverable error'
}