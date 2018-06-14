import logging, sys, argparse, threading, time
from ldap3 import Server, Connection, SIMPLE, NTLM, ALL


class LogThread(threading.Thread):
    """LogThread should always be used in preference to threading.Thread.

    The interface provided by LogThread is identical to that of threading.Thread,
    however, if an exception occurs in the thread the error will be logged
    (using logging.exception) rather than printed to stderr.

    This is important in daemon style applications where stderr is redirected
    to /dev/null.

    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._real_run = self.run
        self.run = self._wrap_run

    def _wrap_run(self):
        try:
            self._real_run()
        except Exception as exception:
            logger.exception(exception)


class LdapBind(LogThread):
    lock = threading.Lock()

    def __init__(self, hostname, auth_method, user_dn, password, logger_object, delay, end_time):
        LogThread.__init__(self)
        self.Hostname = hostname
        self.Auth_Method = auth_method
        self.User_DN = user_dn
        self.Password = password
        self.Logger = logger_object
        self.Delay = delay
        self.End_Time = end_time


    def run(self):
        server = Server(self.Hostname, get_info=ALL)
        conn = Connection(server,
                          user=self.User_DN,
                          password=self.Password,
                          authentication=self.Auth_Method,
                          raise_exceptions=False #Set this to true to throw exceptions, threads will be destroyed on exception
                          )
        #with LdapBind.lock:
        while time.time() < self.End_Time:
            self.Logger.info("Trying to bind to ldap server")
            #print("YAY!")
            conn.bind()
            self.Logger.info("result: " + str(conn.result))
            self.Logger.info("Trying to unbind")
            conn.unbind()
            self.Logger.info("Unbound...")
            time.sleep(int(self.Delay))



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
    parser.add_argument("-d", "--delay", dest="delay", required=True,
                        help="the time threads are waiting until they run again")
    parser.add_argument("-t", "--thread_count", dest="thread_count", required=True,
                        help="number of parallel threads")
    parser.add_argument("-i", "--interval", dest="interval", required=True,
                        help="interval (in minutes) after which the threads terminate themselves")
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()



def setup_logger():
    logger = logging.getLogger('ldap_poll')
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(threadName)s - %(levelname)s - %(message)s')

    file_handler = logging.FileHandler('logfile.log')
    stream_handler = logging.StreamHandler(sys.stdout)

    file_handler.setFormatter(formatter)
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    return logger



if __name__ == "__main__":
    param = read_cmd_params()
    logger = setup_logger()

    logger.info("Running ldap_poll in standalone mode")

    threads = []

    # TODO: limit number of threads

    #delay = 2  #helper - replace with param.delay
    #thread_count = 100 #helper - replace with param.threads
    #interval = 10 #helper - replace with param.interval

    end_time = time.time() + float(param.interval) * 60

    for x in range(int(param.thread_count)):
        thread = LdapBind(param.hostname, param.auth_method, param.user_dn, param.password, logger, param.delay, end_time)
        threads += [thread]
        thread.start()

    for x in threads:
        x.join()