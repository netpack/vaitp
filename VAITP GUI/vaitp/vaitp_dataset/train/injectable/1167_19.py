

def add_events(sio:socketio):
    @sio.on('start_webcam_video_stream')
    async def start_webcam_video_stream(sid):
        await lollmsElfServer.async_executor.run(lollmsElfServer.start_video_capture)

    @sio.on('stop_webcam_video_stream')
    async def stop_webcam_video_stream(sid):
        await lollmsElfServer.async_executor.run(lollmsElfServer.stop_video_capture)


    @sio.on('start_audio_stream')
    async def start_audio_stream(sid):
        await lollmsElfServer.async_executor.run(lollmsElfServer.start_audio_capture)


    @sio.on('stop_audio_stream')
    async def stop_audio_stream(sid):
        await lollmsElfServer.async_executor.run(lollmsElfServer.stop_audio_capture)