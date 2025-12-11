import os
from app import create_app


env = os.getenv("FLASK_ENV")
host = os.getenv("FLASK_HOST", "0.0.0.0")
port = os.getenv("FLASK_PORT", 8080)
debuggable = env == "dev"


app = create_app(env)


if __name__ == "__main__":
    app.run(host, port, debug=debuggable)
