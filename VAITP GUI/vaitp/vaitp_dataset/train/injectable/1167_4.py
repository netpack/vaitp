from fastapi import APIRouter
from pydantic import BaseModel
from lollms.database import  lollms_personal_db
from lollms.utilities import trace_exception,  add_chat_message_to_db
from lollms.security import forbid_remote_access, sanitize_path
from lollms.server.main_server import lollmsElfServer

router = APIRouter()

class EditMessageParameters(BaseModel):
    client_id: str
    id: str
    message: str
    rank: int|None = None
class MessageRankParameters(BaseModel):
    client_id: str
    id: str
    rank: int
class MessageDeleteParameters(BaseModel):
    client_id: str
    id: str


@router.post("/edit_message")
async def edit_message(edit_params: EditMessageParameters):
    forbid_remote_access(lollmsElfServer)
    try:
        client_id = sanitize_path(edit_params.client_id)
        message_id = sanitize_path(edit_params.id)
        new_message = sanitize_path(edit_params.message)
        rank = edit_params.rank
        db = lollms_personal_db.get_personal_db(client_id)
        if rank is None:
            db.edit_message(message_id,new_message)
        else:
            db.edit_message(message_id,new_message,rank=rank)
        return {"status": True, "message": "Message edited successfully"}
    except Exception as ex:
        trace_exception(ex)
        return {"status": False, "error_code": 1001, "error": str(ex)}

@router.post("/message_rank_up")
async def message_rank_up(rank_params: MessageRankParameters):
    forbid_remote_access(lollmsElfServer)
    try:
        client_id = sanitize_path(rank_params.client_id)
        message_id = sanitize_path(rank_params.id)
        rank = rank_params.rank
        db = lollms_personal_db.get_personal_db(client_id)
        db.rank_up_message(message_id,rank)
        return {"status": True, "message": "Message ranked up successfully"}
    except Exception as ex:
        trace_exception(ex)
        return {"status": False, "error_code": 1002, "error": str(ex)}

@router.post("/message_rank_down")
def message_rank_down(rank_params: MessageRankParameters):
    forbid_remote_access(lollmsElfServer)
    try:
        client_id = sanitize_path(rank_params.client_id)
        message_id = sanitize_path(rank_params.id)
        rank = rank_params.rank
        db = lollms_personal_db.get_personal_db(client_id)
        db.rank_down_message(message_id,rank)
        return {"status": True, "message": "Message ranked down successfully"}
    except Exception as ex:
        return {"status": False, "error_code": 1003, "error": str(ex)}

@router.post("/delete_message")
async def delete_message(delete_params: MessageDeleteParameters):
    forbid_remote_access(lollmsElfServer)
    try:
        client_id = sanitize_path(delete_params.client_id)
        message_id = sanitize_path(delete_params.id)
        db = lollms_personal_db.get_personal_db(client_id)
        db.delete_message(message_id)
        return {"status": True, "message": "Message deleted successfully"}
    except Exception as ex:
        trace_exception(ex)
        return {"status": False, "error_code": 1004, "error": str(ex)}