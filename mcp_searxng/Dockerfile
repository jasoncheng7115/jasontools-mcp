FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir "mcp==2.0.0" "httpx>=0.27"
COPY mcp_searxng.py .
EXPOSE 8021
CMD ["python", "mcp_searxng.py"]
