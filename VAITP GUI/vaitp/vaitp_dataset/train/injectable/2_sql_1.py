def configure_app(app, pwd):
    app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://user:{pwd}@domain.com"
