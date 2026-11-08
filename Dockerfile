# Official multi-platform image, pinned to immutable content; includes Git.
FROM python:3.14-bookworm@sha256:3fe825da0a80fa8e2cd79baadeb76b03c0ddf3d6cdbc8346778a0208b9d6038c
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 CI=true CODESHIELD_AUTOMATED=1
WORKDIR /opt/codeshield
COPY requirements.lock pyproject.toml README.md LICENSE ./
COPY codeshield/ ./codeshield/
RUN git --version \
    && python -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements.lock \
    && python -m pip install --no-cache-dir --no-build-isolation --no-deps . \
    && python -m pip check \
    && git config --system --add safe.directory /repo \
    && useradd --uid 10001 --create-home scanner
USER 10001:10001
WORKDIR /repo
ENTRYPOINT ["python", "-I", "-m", "codeshield.integrations", "docker"]
CMD ["--staged"]
