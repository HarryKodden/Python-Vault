FROM python:3

WORKDIR /app

EXPOSE 5000

RUN apt-get update && apt-get install -y libsasl2-dev libldap2-dev ldap-utils

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD [ "uwsgi", "--ini", "app.ini" ]