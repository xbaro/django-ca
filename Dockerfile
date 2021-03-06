####################
# Test build stage #
####################
FROM python:3-alpine as test
WORKDIR /usr/src/django-ca
RUN apk --no-cache add --update gcc linux-headers libc-dev libffi-dev libressl-dev make

COPY requirements.txt requirements-dev.txt setup.py tox.ini ./
COPY ca/ ca/

# Additional utilities required for testing:
RUN pip install --no-cache-dir -r requirements.txt -r requirements-dev.txt

# Add user (some tests check if it's impossible to write a file)
RUN addgroup -g 9000 -S django-ca && \
    adduser -S -u 9000 -G django-ca django-ca
USER django-ca:django-ca

# copy this late so that changes do not trigger a cache miss during build
RUN python setup.py code_quality
RUN python setup.py test

# cleanup some files so they are not included later
USER root:root
RUN rm -r ca/django_ca/tests/

######################
# Actual build stage #
######################
FROM python:3-alpine
WORKDIR /usr/src/django-ca

COPY requirements.txt docker/start.sh ./
RUN apk --no-cache add --update gcc linux-headers libc-dev libffi-dev libressl-dev pcre pcre-dev mailcap && \
    pip install --no-cache-dir -r requirements.txt uwsgi pyyaml
RUN addgroup -g 9000 -S django-ca && \
    adduser -S -u 9000 -G django-ca django-ca && \
    mkdir -p /usr/share/django-ca/ /var/lib/django-ca/ && \
    chown django-ca:django-ca /usr/share/django-ca/ /var/lib/django-ca/
COPY --from=test /usr/src/django-ca/ca/ ca/
COPY uwsgi/ uwsgi/
COPY docker/localsettings.py ca/ca/

CMD ./start.sh

USER django-ca:django-ca
EXPOSE 8000
VOLUME ["/var/lib/django-ca/", "/usr/share/django-ca/"]
