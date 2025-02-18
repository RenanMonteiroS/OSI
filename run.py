from app import create_app
from mongoengine import connect

server = create_app()

if __name__ == "__main__":
    connect(host=server.config['MONGODB_URI'], maxPoolSize=50)
    server.logger.info(f"Database connected")
    server.run(port=8080, debug=True)