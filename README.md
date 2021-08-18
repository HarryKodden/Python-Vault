# README

This repository serves as a basic skeleton for Python based application.

It uses docker to build some containers:

- <b>development:</b>
    This container serves the application in debug mode. Every modification in the source file will live-reload the appplication so that the adjustments can be reviewed immediately.
    Also debug is active output is highly verbose

- <b>staging:</b>
    This container runs the application as in the last builded version. Adjustments are only becoming visible after a new build.
    The application runs as a WSGI application.

- <b>proxy</b>
    This container proxies request towards the WSGI application in the staging container.

(c) Harry Kodden, 2021
