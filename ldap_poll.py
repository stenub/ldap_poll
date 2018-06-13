from datetime import datetime
from ldap3 import Server, Connection, SIMPLE, NTLM, ALL
import logging, sys, time, argparse



def read_cmd_params():
    parser = argparse.ArgumentParser(description="Possible options:")
    parser.add_argument("-s", "--server", dest="hostname", required=True,
                        help="hostname or ip address of the ldap-server")
    parser.add_argument("-a", "--auth", dest="auth_method", required=True, choices=["SIMPLE", "NTLM"],
                        help="auth method to use")
    parser.add_argument("-u", "--user_dn", dest="user_dn", required=True,
                        help="user distinguished name, eg: 'uid=admin,cn=users,cn=accounts,dc=demo1,dc=freeipa,dc=org'")
    parser.add_argument("-p", "--password", dest="password", required=True,
                        help="the password for the given user")
    parser.add_argument("-tf", "--trigger_frequency", dest="tf", required=True,
                        help="the frequency for polling the ldap server")
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)


    return parser.parse_args()



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



def bind_to_it(host, user_dn, pw, auth_method):
    server = Server(host, get_info=ALL)
    conn = Connection(server, user=user_dn, password=pw, authentication=auth_method, raise_exceptions=True)

    logger.info("Trying to bind to ldap server")
    conn.bind()
    logger.info("result: " + str(conn.result))
    logger.info("Trying to unbind")
    conn.unbind()
    logger.info("Unbound...")




if __name__ == "__main__":

    param = read_cmd_params()
    logger = setup_logger()

    logger.info("Running ldap_poll in standalone mode")


    try:
        while True:
            bind_to_it(param.hostname, param.user_dn, param.password)
            #bind_to_it(hostname, user_dn, password)
            time.sleep(param.tf)
    except Exception as exception:
        logger.exception(exception)
