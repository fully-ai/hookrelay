FROM python:3.12-slim
WORKDIR /app
RUN useradd -m -u 10001 hookrelay
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir . && mkdir -p /data && chown -R hookrelay:hookrelay /data
USER hookrelay
EXPOSE 8093
ENV HOOKRELAY_HOST=0.0.0.0
ENV HOOKRELAY_PORT=8093
ENV HOOKRELAY_DATA_DIR=/data
CMD ["hookrelay"]
