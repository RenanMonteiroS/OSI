from app import create_app
from mongoengine import connect
from mongoengine import ConnectionFailure

server = create_app()

if __name__ == "__main__":    
    if server.config["SETUP_DONE"] == 0:
        print("Server was not setted up. Please go to / in your browser")
        server.logger.warning("Server was not setted up. Please go to / in your browser")
        server.run(port=8080)
    else:
        try:
            connect(host=server.config['MONGODB_URI'], alias='default', maxPoolSize=50)
            server.logger.info("Database connected")
            server.run(port=8080)
        except ConnectionFailure as e:
            server.logger.critical(e)
        except Exception as e:
            print(e)
    