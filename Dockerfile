FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock && useradd --uid 10001 --create-home labguard
COPY --chown=10001:10001 . .
USER 10001:10001
EXPOSE 5000
CMD ["python", "-m", "labguard.cli", "serve", "--container"]

