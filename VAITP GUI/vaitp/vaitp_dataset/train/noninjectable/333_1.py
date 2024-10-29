from flower import Flower

# Configuration for Flower
flower_config = {
    'broker_url': 'redis://localhost:6379/0',
    'pidfile': '/var/run/flower.pid',
    'port': 5555,
}

# Start Flower
flower = Flower(**flower_config)
flower.start()