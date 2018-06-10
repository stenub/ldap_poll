from datetime import datetime
from ldap3 import Server, Connection, SIMPLE, ALL
import threading, logging, sys, time

#TODO: catch exceptions from threads


### Change the following settings to your needs

hostname = 'ipa.demo1.freeipa.org'

user_dn = 'uid=admin,cn=users,cn=accounts,dc=demo1,dc=freeipa,dc=org'
password = 'Secret123'

tf = 2  #Trigger frequency in seconds


### Don't change anything below this line



def setup_logger():
    logger = logging.getLogger('ldap_poll')
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    file_handler = logging.FileHandler('logfile.log')
    stream_handler = logging.StreamHandler(sys.stdout)

    file_handler.setFormatter(formatter)
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    return logger


def bind_to_it(host, user_dn, pw):
    #threading.Timer(tf, bind_to_it(host, user, pw, tf)).start()

    server = Server(host, get_info=ALL)
    conn = Connection(server, user=user_dn, password=pw, authentication=SIMPLE, raise_exceptions=True)

    logger.info("Trying to bind to ldap server")
    conn.bind()
    logger.info("result: " + str(conn.result))
    logger.info("Trying to unbind")
    conn.unbind()
    logger.info("Unbound...")




if __name__ == "__main__":

    logger = setup_logger()

    logger.info("Running ldap_poll in standalone mode")

    try:
        while True:
            bind_to_it(hostname, user_dn, password)
            time.sleep(tf)
    except Exception as exception:
        logger.exception(exception)
