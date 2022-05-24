FROM python:3.7.5-slim AS base
WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY atlas_log ./atlas_log

FROM base AS test
COPY requirements-dev.txt ./
RUN pip install -r requirements-dev.txt
RUN pytest -v --cov=atlas_log
RUN flake8 --ignore=E501,E203,W503,E711,E722 atlas_log
RUN black --check .

FROM base AS run
CMD [ "python", "-m", "atlas_log.get_latest" ]
RUN apt update && apt upgrade -y