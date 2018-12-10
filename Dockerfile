FROM python:2.7
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
EXPOSE 6514
CMD python ./syslog2la.py