# Discordata
Discordata is a simple bridge between incoming KYC provider webhook
requests and outgoing Discord webhook requests. Each time a
webhook request is received, Discordata formats a Discord
and sends it via the Discord webhook URL.

Discord data can be run as a standalone application or as a
docker container. 

By default Discordata will listen on port `1276` for requests
to the `webhook` endpoint. Port 1276 must be opened and forwarded
to Discordata. The URL to the webhook endpoint must be provided to
the KYC provider. For example, `http://XXX.XXX.XXX.XXX:1276/webhook/`.

## Clone the Repository

Clone the Discordata github repository:

```console
git clone https://github.com/metanull-operator/discordata.git
```

Change directory into the Discordata repository:

```console
cd discordata
```

## Generate Certificate

If you want to use a self-signed certificate, generate the certificate and key.
Adjust `-days` to the appropriate length of time your certificate should be valid.

```console
cd certs
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
cd ..
```

## Environment Variables

### Required Environment Variables

Two environment variables are required to be exported to Discordata in order to run:

- `WEBHOOK_SECRET` - A shared secret for secure
  communication with the KYC provider. Provided by the KYC provider.
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

Run the following docker command, making the appropriate substitutions:

- Substitute `<PATH_TO_REPO>` with the absolute path to your Discordata repository'
- Change the external container port 1276 with another port, if necessary.
  For example `-p 5000:1276`.

```console
docker run \
    -p 1276:1276 \
    --env-file .env \
    --name discordata \
    -v <PATH_TO_REPO>/certs/cert.pem:/certs/cert.pem \
    -v <PATH_TO_REPO>/certs/key.pem:/certs/key.pem \
    discordata
```

Otherwise, place your organization's `cert.pem` and `key.pem` file in the `certs/` directory.

## Standalone

### Install Python Packages

```console
pip3 install flask flask-talisman requests
```

### Run discordata.sh

```console
./discordata.sh
```

# mock-webhook-request.py

`mock-webhook-request.py` sends a fake webhook request to the
provided webhook URL.

To run:

```console
python3 mock-webhook-request.py http://localhost:1276/webhook
```

`mock-webhook-request.py` will send a single request to the Discordata webhook
URL and then exit.