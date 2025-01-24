"""
project: lollms
file: lollms_generation_events.py 
author: ParisNeo
description: 
    This module contains a set of Socketio routes that provide information about the Lord of Large Language and Multimodal Systems (LoLLMs) Web UI
    application. These routes are specific to text generation operation

"""
from fastapi import APIRouter, Request
from fastapi import HTTPException
from pydantic import BaseModel
import pkg_resources
from lollms.server.elf_server import LOLLMSElfServer
from fastapi.responses import FileResponse
from lollms.binding import BindingBuilder, InstallOption
from ascii_colors import ASCIIColors
from lollms.personality import MSG_TYPE, AIPersonality
from lollms.types import MSG_TYPE, SENDER_TYPES
from lollms.utilities import load_config, trace_exception, gc
from lollms.utilities import find_first_available_file_index, convert_language_name
from lollms.security import forbid_remote_access
from lollms_webui import LOLLMSWebUI
from pathlib import Path
from typing import List
import socketio
import threading
import os

router = APIRouter()
lollmsElfServer = LOLLMSWebUI.get_instance()


# ----------------------------------- events -----------------------------------------
def add_events(sio:socketio):
    forbid_remote_access(lollmsElfServer)
    @sio.on('generate_msg')
    def handle_generate_msg(sid, data):        
        client_id = sid
        lollmsElfServer.cancel_gen = False
        client = lollmsElfServer.session.get_client(client_id)

        if client is None:
            lollmsElfServer.error("Client not found", client_id=client_id)
            return

        client.generated_text=""
        client.cancel_generation=False
        client.continuing=False
        client.first_chunk=True
        

        
        if not lollmsElfServer.model:
            ASCIIColors.error("Model not selected. Please select a model")
            lollmsElfServer.error("Model not selected. Please select a model", client_id=client_id)
            return

        if not lollmsElfServer.busy:
            if client.discussion is None:
                if lollmsElfServer.db.does_last_discussion_have_messages():
                    client.discussion = lollmsElfServer.db.create_discussion()
                else:
                    client.discussion = lollmsElfServer.db.load_last_discussion()

            if not isinstance(data, dict) or "prompt" not in data:
                lollmsElfServer.error("Invalid data received", client_id=client_id)
                return
            
            prompt = data["prompt"]
            if not isinstance(prompt,str):
                lollmsElfServer.error("Invalid prompt received", client_id=client_id)
                return

            ump = lollmsElfServer.config.discussion_prompt_separator +lollmsElfServer.config.user_name.strip() if lollmsElfServer.config.use_user_name_in_discussions else lollmsElfServer.personality.user_message_prefix
            message = client.discussion.add_message(
                message_type    = MSG_TYPE.MSG_TYPE_FULL.value,
                sender_type     = SENDER_TYPES.SENDER_TYPES_USER.value,
                sender          = ump.replace(lollmsElfServer.config.discussion_prompt_separator,"").replace(":",""),
                content=prompt,
                metadata=None,
                parent_message_id=lollmsElfServer.message_id
            )

            ASCIIColors.green("Starting message generation by "+lollmsElfServer.personality.name)
            client.generation_thread = threading.Thread(target=lollmsElfServer.start_message_generation, args=(message, message.id, client_id))
            client.generation_thread.start()
            
            # lollmsElfServer.sio.sleep(0.01)
            ASCIIColors.info("Started generation task")
            lollmsElfServer.busy=True
            #tpe = threading.Thread(target=lollmsElfServer.start_message_generation, args=(message, message_id, client_id))
            #tpe.start()
        else:
            lollmsElfServer.error("I am busy. Come back later.", client_id=client_id)
    @sio.on('generate_msg_with_internet')
    def generate_msg_with_internet(sid, data):        
        client_id = sid
        lollmsElfServer.cancel_gen = False
        client = lollmsElfServer.session.get_client(client_id)
        
        if client is None:
            lollmsElfServer.error("Client not found", client_id=client_id)
            return

        client.generated_text=""
        client.cancel_generation=False
        client.continuing=False
        client.first_chunk=True
        

        
        if not lollmsElfServer.model:
            ASCIIColors.error("Model not selected. Please select a model")
            lollmsElfServer.error("Model not selected. Please select a model", client_id=client_id)
            return

        if not lollmsElfServer.busy:
            if client.discussion is None:
                if lollmsElfServer.db.does_last_discussion_have_messages():
                    client.discussion = lollmsElfServer.db.create_discussion()
                else:
                    client.discussion = lollmsElfServer.db.load_last_discussion()

            if not isinstance(data, dict) or "prompt" not in data:
                lollmsElfServer.error("Invalid data received", client_id=client_id)
                return
            
            prompt = data["prompt"]
            if not isinstance(prompt,str):
                lollmsElfServer.error("Invalid prompt received", client_id=client_id)
                return
            ump = lollmsElfServer.config.discussion_prompt_separator +lollmsElfServer.config.user_name.strip() if lollmsElfServer.config.use_user_name_in_discussions else lollmsElfServer.personality.user_message_prefix
            message = client.discussion.add_message(
                message_type    = MSG_TYPE.MSG_TYPE_FULL.value,
                sender_type     = SENDER_TYPES.SENDER_TYPES_USER.value,
                sender          = ump.replace(lollmsElfServer.config.discussion_prompt_separator,"").replace(":",""),
                content=prompt,
                metadata=None,
                parent_message_id=lollmsElfServer.message_id
            )

            ASCIIColors.green("Starting message generation by "+lollmsElfServer.personality.name)
            
            client.generation_thread = threading.Thread(target=lollmsElfServer.start_message_generation, args=(message, message.id, client_id, False, None, True))
            client.generation_thread.start()
            
            # lollmsElfServer.sio.sleep(0.01)
            ASCIIColors.info("Started generation task")
            lollmsElfServer.busy=True
            #tpe = threading.Thread(target=lollmsElfServer.start_message_generation, args=(message, message_id, client_id))
            #tpe.start()
        else:
            lollmsElfServer.error("I am busy. Come back later.", client_id=client_id)




    @sio.on('generate_msg_from')
    def handle_generate_msg_from(sid, data):
        client_id = sid
        client = lollmsElfServer.session.get_client(client_id)
        if client is None:
            lollmsElfServer.error("Client not found", client_id=client_id)
            return

        lollmsElfServer.cancel_gen = False
        client.continuing=False
        client.first_chunk=True
        
        if client.discussion is None:
            ASCIIColors.warning("Please select a discussion")
            lollmsElfServer.error("Please select a discussion first", client_id=client_id)
            return

        if not isinstance(data, dict) or "id" not in data:
            lollmsElfServer.error("Invalid data received", client_id=client_id)
            return

        id_ = data['id']
        if not isinstance(id_,int):
            lollmsElfServer.error("Invalid id received", client_id=client_id)
            return

        generation_type = data.get('msg_type',None)
        if id_==-1:
            message = client.discussion.current_message
        else:
            message = client.discussion.load_message(id_)
        if message is None:
            return            
        client.generation_thread = threading.Thread(target=lollmsElfServer.start_message_generation, args=(message, message.id, client_id, False, generation_type))
        client.generation_thread.start()

    @sio.on('continue_generate_msg_from')
    def handle_continue_generate_msg_from(sid, data):
        client_id = sid
        client = lollmsElfServer.session.get_client(client_id)
        if client is None:
            lollmsElfServer.error("Client not found", client_id=client_id)
            return

        lollmsElfServer.cancel_gen = False
        client.continuing=True
        client.first_chunk=True
        
        if client.discussion is None:
            ASCIIColors.yellow("Please select a discussion")
            lollmsElfServer.error("Please select a discussion", client_id=client_id)
            return

        if not isinstance(data, dict) or "id" not in data:
            lollmsElfServer.error("Invalid data received", client_id=client_id)
            return
            
        id_ = data['id']
        if not isinstance(id_,int):
            lollmsElfServer.error("Invalid id received", client_id=client_id)
            return
        if id_==-1:
            message = client.discussion.current_message
        else:
            message = client.discussion.load_message(id_)
        if message is None:
            return
        client.generated_text=message.content
        client.generation_thread = threading.Thread(target=lollmsElfServer.start_message_generation, args=(message, message.id, client_id, True))
        client.generation_thread.start()
