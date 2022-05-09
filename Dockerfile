FROM python:3-alpine

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ./
COPY static/ ./static/

EXPOSE 1234/tcp

CMD [ "python", "./app.py" ]
