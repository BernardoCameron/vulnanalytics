import pika
import os
import sys
import json
import logging
from dataclasses import asdict
from manual_runner import run_full_audit, DataclassEncoder

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
logger = logging.getLogger(__name__)

# Lee el host de RabbitMQ desde una variable de entorno, o usa un valor por defecto
# En Docker-compose usaremos 'rabbitmq', localmente 'localhost'
RABBITMQ_HOST = os.environ.get('RABBITMQ_HOST', 'host.docker.internal')

def main():
    try:
        credentials = pika.PlainCredentials('admin', 'admin123')
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(
                host=RABBITMQ_HOST, 
                credentials=credentials,
                connection_attempts=10, # Reintentar si rabbit no esta listo
                retry_delay=5,
                heartbeat=0  # INFO: Deshabilita el timeout. Esencial para escaneos largos de GVM.
            )
        )
        channel = connection.channel()

        # Asegurar que las colas existan
        channel.queue_declare(queue='scan_tasks_queue', durable=True)
        channel.queue_declare(queue='scan_results_queue', durable=True)

        logger.info(f"Conectado a RabbitMQ en {RABBITMQ_HOST}.")
        logger.info("Esperando tareas de escaneo en [scan_tasks_queue]...")

        def callback(ch, method, properties, body):
            try:
                # El body esperado es un JSON como {"target_ip": "127.0.0.1"} o solo el string
                message = body.decode()
                logger.info(f"Tarea recibida: {message}")
                
                try:
                    payload = json.loads(message)
                    target_ip = payload.get("target_ip", message)
                    credentials = payload.get("credentials", None)
                except json.JSONDecodeError:
                    # Si no es JSON, asumimos que es directamente la IP (ej: "192.168.x.x")
                    target_ip = message.strip()
                    credentials = None

                auth_msg = f"SI ({credentials['type'].upper()})" if credentials else "NO"
                logger.info(f"Iniciando escaneo: {target_ip} (Autenticado: {auth_msg})")
                
                # Ejecutar auditoria
                final_report = run_full_audit(target_ip, credentials=credentials)
                
                # Convertir el resultado a JSON string usando el encoder personalizado
                report_json = json.dumps(asdict(final_report), cls=DataclassEncoder)
                
                # Publicar el resultado en la cola de resultados
                ch.basic_publish(
                    exchange='',
                    routing_key='scan_results_queue',
                    body=report_json,
                    properties=pika.BasicProperties(
                        delivery_mode=2,  # persistente
                    )
                )
                
                # Guardar copia local utilitaria
                with open("audit_report.json", "w", encoding="utf-8") as f:
                    f.write(report_json)

                logger.info("[x] Tarea finalizada. Resultados publicados en RabbitMQ y guardados localmente.")
                
                # Confirmar a RabbitMQ que el mensaje fue procesado ok
                ch.basic_ack(delivery_tag=method.delivery_tag)
                
            except Exception as e:
                logger.error(f"Error procesando la tarea de escaneo: {e}")
                # En caso de un error critico, opcionalmente podrias agregar logica de re-encolado.
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

        # Configuramos para consumir mensajes y no pedir otro hasta que termine el actual
        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(queue='scan_tasks_queue', on_message_callback=callback)
        channel.start_consuming()

    except Exception as e:
        logger.error(f"Error critico en RabbitMQ Consumer: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
