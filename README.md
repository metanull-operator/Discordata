# Discordata
Discordata is a simple bridge between incoming Quadrata webhook
requests and outgoing Discord webhook requests. Each time a
Quadrata request is received, Discordata formats a Discord
and sends it via the Discord webhook URL.

Discord data can be run as a standalone application or as a
docker container. 

By default Discordata will listen on port `1276` for requests
to the `webhook` endpoint. Port 1276 must be opened and forwarded
to Discordata. The URL to the webhook endpoint must be provided to
Quadrata. For example, `http://XXX.XXX.XXX.XXX:1276/webhook/`.

## Clone the Repository

Clone the Discordata github repository:

```console
git clone https://github.com/metanull-operator/discordata.git
```

Change directory into the Discordata repository:

```console
cd discordata
```

## Environment Variables

### Required Environment Variables

Two environment variables are required to be exported to Discordata in order to run:

- `QUADRATA_WEBHOOK_SECRET` - A shared secret for secure
  communication with Quadrata. Provided by Quadrata.
- `DISCORD_WEBHOOK_URL` - The URL for the Discord webhook to be 
  used to send messages to Discord. This can be provided by the
  administrators of the Discord server.

### Optional Environment Variables

Two additional environment variables may be set to modify default behaviors:

- `ALLOWED_IPS` - Comma-delimited list of IP addresses or subnets
  from which requests will be accepted. Defaults to `0.0.0.0`.
- `PORT` - Port on which Discordata will listen. For Docker containers,
  this is the internal port on which Discordata is listening. The
  external port can be adjusted with the `-p` flag on the run
  command. Defaults to `1276`.

### Set Environment Variables in .env

Copy `.env.sample` to `.env` and modify the values of the variables to 
suit your environment.

```console
cp .env.sample .env
```

Both examples of running the application below rely on
a `.env` environment variable file, but other methods of setting
the environment variables may be used.

## Run as Docker Container

### Build the Docker Image

```console
docker build -t discordata .
```

### Run Docker Container

Run the following docker command, mapping your desired external port to
the value of the `PORT` environment variable:

```console
docker run -p 1276:1276 --env-file .env --name discordata discordata
```

## Standalone

### Run discordata.sh

```console
./discordata.sh
```

# mock-quadrata-request.py

`mock-quadrata-request.py` sends a fake Quadrata webhook request to the
provided webhook URL.

To run:

```console
python3 mock-quadrata-request.py http://localhost:1276/webhook
```

`mock-quadrata-request.py` will send a single request to the Discordata webhook
URL and then exit.