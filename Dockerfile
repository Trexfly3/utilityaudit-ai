ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UTILITYAUDIT_DATA_DIR=/app/data
WORKDIR /app
COPY requirements.lock pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.lock
COPY utilityaudit ./utilityaudit
COPY app.py ./
COPY samples ./samples
COPY .streamlit ./.streamlit
RUN pip install --no-cache-dir --no-deps -e . \
    && useradd --uid 10001 --create-home app \
    && mkdir -p /app/data \
    && chown app:app /app/data \
    && chmod 700 /app/data
USER 10001:10001
EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=3)"
CMD ["streamlit", "run", "app.py", "--server.address", "0.0.0.0"]
