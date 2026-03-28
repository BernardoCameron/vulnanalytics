import pika
import sys
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
logger = logging.getLogger(__name__)

import os

RABBITMQ_HOST = os.environ.get('RABBITMQ_HOST', 'host.docker.internal')

def main():
    try:
        credentials = pika.PlainCredentials('admin', 'admin123')
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials)
        )
        channel = connection.channel()

        # Aseguramos que la cola existe
        channel.queue_declare(queue='scan_tasks_queue', durable=True)

        # Si el usuario mando un argumento, lo usamos como IP, si no, mandamos localhost
        args = sys.argv[1:]
        target_ip = args[0] if len(args) > 0 else "127.0.0.1"

        # Formato JSON simulando a Spring Boot con credenciales opcionales
        # USO: python queue_producer_mvp.py <IP> <TIPO_CREDENCIAL> <USER> <PASS>
        # Ejemplo: python queue_producer_mvp.py 192.168.100.10 smb admin miPass123
        import json
        message_dict = {"target_ip": target_ip}
        
        if len(args) >= 4:
             message_dict["credentials"] = {
                 "type": args[1].lower(), # 'smb' o 'ssh'
                 "username": args[2],
                 "password": args[3]
             }
             
        payload = json.dumps(message_dict)

        channel.basic_publish(exchange='',
                              routing_key='scan_tasks_queue',
                              body=payload,
                              properties=pika.BasicProperties(
                                 delivery_mode=2, # persistente
                              ))
        
        logger.info(f"Orden de escaneo enviada para: '{target_ip}'")
        connection.close()

    except Exception as e:
        logger.error(f"Error conectando a RabbitMQ: {e}")

if __name__ == '__main__':
    main()
