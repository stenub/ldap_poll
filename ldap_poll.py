from ldap3 import Server, Connection, ALL
import threading

def bindtoit():
    threading.Timer(1.0 , bindtoit).start()

    server = Server("ipa.demo1.freeipa.org")
    conn = Connection(server)

    print("Try to bind to LDAP Server", conn.bind())
    print("Unbinding!", conn.unbind())


if __name__ == "__main__":
    print("Running ldap_poll in standalone mode")
    bindtoit()

