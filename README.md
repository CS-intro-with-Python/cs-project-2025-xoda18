# Simple Flask Hello Service

## Project Structure

- `server.py` – Flask app exposing:
  - `GET /hello` – returns `Hello, world!`
  - `GET /hi` – redirects to an external URL
- `client.py` – Python script that sends a `GET` request to `http://localhost:8080/hello` and exits with:
  - code `0` if the server responds with status `200`
  - code `1` otherwise
- `run_client.sh` – shell script that runs `client.py` up to 10 times, waiting 1 second between attempts
- `requirements.txt` – Python dependencies

## Requirements

- Python 3.8+
- `pip` for installing dependencies
- Docker, if you want to run it in a container

Install dependencies:

```bash
pip install -r requirements.txt
