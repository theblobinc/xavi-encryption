import pytest
from xavi_void.math.types import Ordinal
from xavi_void.runtime.remote_protocol import MessageType,RemoteMessage,ReplayError
from xavi_void.runtime.remote_service import RemoteEvaluatorProtocol,RemoteProtocolError,RemoteSessionPhase


def _next(mt,sid,seq,prior,payload=b"x"):
    return RemoteMessage(mt,sid,Ordinal(seq),prior,payload)


def test_remote_message_binary_round_trip_and_transcript_chain():
    sid="session-A"; proto=RemoteEvaluatorProtocol()
    m1=_next(MessageType.CREATE_SESSION,sid,1,None,b"")
    assert RemoteMessage.decode(m1.encode())==m1
    c1=proto.accept(m1)
    m2=_next(MessageType.UPLOAD_PROGRAM,sid,2,c1,b"encrypted-program")
    c2=proto.accept(m2)
    m3=_next(MessageType.INSTRUCTION_CHUNK,sid,3,c2,b"chunk")
    c3=proto.accept(m3)
    m4=_next(MessageType.CHECKPOINT,sid,4,c3,b"cp-1")
    c4=proto.accept(m4)
    m5=_next(MessageType.RECOVER,sid,5,c4,b"cp-1")
    c5=proto.accept(m5)
    m6=_next(MessageType.FINISH,sid,6,c5,b"")
    proto.accept(m6)
    assert proto.sessions[sid].phase==RemoteSessionPhase.FINISHED


def test_remote_replay_and_out_of_phase_messages_fail_closed():
    sid="session-B"; proto=RemoteEvaluatorProtocol();m1=_next(MessageType.CREATE_SESSION,sid,1,None,b"");c1=proto.accept(m1)
    with pytest.raises(ReplayError): proto.accept(m1)
    m2=_next(MessageType.FINISH,sid,2,c1,b"")
    with pytest.raises(RemoteProtocolError): proto.accept(m2)
