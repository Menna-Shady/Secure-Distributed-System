import pika
import psycopg2
import time
import os
import requests

INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY")
API_SERVICE_URL = "http://api1:5000"

def notify_api(request_id):
    try:
        res = requests.post(
            f"{API_SERVICE_URL}/internal/status",
            json={"request_id": request_id, "status": "processed"},
            headers={"X-Internal-Key": INTERNAL_API_KEY},
            timeout=5
        )
        print(f"Internal notify status: {res.status_code}", flush=True)
    except Exception as e:
        print(f"Internal notify failed: {e}", flush=True)

def get_db_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "db"),
        database=os.getenv("DB_NAME", "secure_system"),
        user=os.getenv("DB_USER", "admin"),
        password=os.getenv("DB_PASSWORD", "admin")
    )

def log_to_db(request_id, instance, message):
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id SERIAL PRIMARY KEY,
                request_id TEXT,
                instance TEXT,
                message TEXT
            );
        """)

        cur.execute(
            "INSERT INTO logs (request_id, instance, message) VALUES (%s, %s, %s)",
            (request_id, instance, message)
        )

        conn.commit()
        cur.close()
        conn.close()

    except Exception as e:
        print("DB ERROR:", e, flush=True)

def callback(ch, method, properties, body):
    message = body.decode()
    print("Received:", message, flush=True)

    parts = message.split(" from ")
    request_id = parts[0] if len(parts) > 0 else "unknown"

    log_to_db(request_id, "worker", "Task consumed")
    log_to_db(request_id, "worker", "Task processed")
    notify_api(request_id)

    ch.basic_ack(delivery_tag=method.delivery_tag)

def start_worker():
    while True:
        try:
            print("Trying to connect to RabbitMQ...", flush=True)

            connection = pika.BlockingConnection(
    pika.ConnectionParameters(
        host=os.getenv("RABBITMQ_HOST", "rabbitmq"),
        credentials=pika.PlainCredentials(
            os.getenv("RABBITMQ_USER", "guest"),
            os.getenv("RABBITMQ_PASSWORD", "guest")
        ),
        heartbeat=600,
        blocked_connection_timeout=300
    )
)
            

            channel = connection.channel()
            channel.queue_declare(queue="tasks")

            channel.basic_consume(
                queue="tasks",
                on_message_callback=callback
            )

            print("Worker connected and waiting...", flush=True)
            channel.start_consuming()

        except Exception as e:
            print("RabbitMQ ERROR:", e, flush=True)
            print("Retrying in 5 seconds...", flush=True)
            time.sleep(5)

if __name__ == "__main__":
    start_worker()