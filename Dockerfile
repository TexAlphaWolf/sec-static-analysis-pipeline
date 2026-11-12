FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    MPLCONFIGDIR=/tmp/matplotlib

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install . \
    && useradd --system --no-create-home --uid 10001 pescan \
    && install -d -o pescan /data

# The files to analyse are mounted read-only (for example on /in); reports go to /data. Nothing needs the network or a
# privilege: run with --network none, --read-only, --cap-drop ALL and --tmpfs /tmp (matplotlib's cache).
USER pescan
WORKDIR /data
VOLUME ["/data"]
ENTRYPOINT ["pescan"]
CMD ["--help"]
