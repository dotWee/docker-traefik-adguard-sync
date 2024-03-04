FROM python:3.8-alpine3.19
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
ENTRYPOINT [ "python", "/app/sync.py" ]

