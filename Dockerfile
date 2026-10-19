FROM node:22-bookworm-slim AS verifier
FROM python:3.12-slim
COPY --from=verifier /usr/local/bin/node /usr/local/bin/node
WORKDIR /otherwise
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PYTHONPATH=/otherwise PYTHONDONTWRITEBYTECODE=1
CMD ["python", "-m", "unittest", "discover", "-s", "tests", "-v"]
