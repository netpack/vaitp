from nicegui import ui, app

@ui.page('/')
def index():
    if 'user' not in app.storage.user:
      ui.label('Not logged in')
      with ui.row():
        username = ui.input(label="Username")
        password = ui.input(label="Password", password=True)
        ui.button("Login", on_click=lambda: login(username.value, password.value))
    else:
        ui.label(f"Logged in as {app.storage.user['user']}")
        ui.button("Logout", on_click=logout)

def login(username, password):
  # In a real scenario, you'd check the user and password against a database
    if username == "test" and password == "test":
        app.storage.user['user'] = username
        ui.notify("Logged in successfully")
    else:
        ui.notify("Invalid credentials", color='negative')

    
def logout():
    app.storage.user.clear()
    ui.notify("Logged out")
    

ui.run(storage_secret='my_secret')