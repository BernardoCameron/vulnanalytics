import pika
import sys
import os
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
logger = logging.getLogger(__name__)

RABBITMQ_HOST = "localhost"

def main():
    try:
        credentials = pika.PlainCredentials('admin', 'admin123')
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials)
        )
        channel = connection.channel()

        # Aseguramos que la cola exista antes de intentar consumir
        channel.queue_declare(queue='mvp_test_queue')

        def callback(ch, method, properties, body):
            logger.info(f"Mensaje recibido: {body.decode()}")

        channel.basic_consume(queue='mvp_test_queue',
                              auto_ack=True,
                              on_message_callback=callback)

        logger.info('Esperando mensajes en [mvp_test_queue]...')
        channel.start_consuming()

    except KeyboardInterrupt:
        logger.info("Interrumpido por el usuario, saliendo...")
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
    except Exception as e:
        logger.error(f"Error en Consumidor RabbitMQ: {e}")

if __name__ == '__main__':
    main()
