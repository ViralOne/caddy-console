from dotenv import load_dotenv

load_dotenv()

import os

from src import create_app

app = create_app()

if __name__ == "__main__":
    # Local dev with FLASK_DEBUG=1.
    debug = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
    from src.geoip_update import start_background
    start_background()
    app.run(host="0.0.0.0", port=9090, debug=debug)
