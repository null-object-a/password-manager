#!/usr/bin/python3
import argparse, os
from columnar import columnar
from hashlib import md5
from base64 import b64decode
from base64 import b64encode
import mariadb
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# print("Establishing connection with MYSQL Server..")
db = mariadb.connect(
  host="localhost",
  user="passwd_admin",
  password="$PASSWORD",
  database="password_manager",
  port=3306
)



class AESCipher:
    def __init__(self, key):
        self.key = md5(key.encode('utf8')).digest()

    def encrypt(self, data):
        iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data.encode('utf-8'), 
            AES.block_size)))

    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
        return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)



parser = argparse.ArgumentParser(description='Personal information')
parser.add_argument('--action', dest='action', type=str, help='Action to realize, such as: new, get.', required=True)
parser.add_argument('--host', dest='host', type=str, help='Name of the host.')
parser.add_argument('--login-candidate', dest='login_candidate', type=str, help='Login candidate a.k.a username || password')
parser.add_argument('--password', dest='password', type=str, help=':/')
parser.add_argument('-i', dest='index', type=int, help='index to delete')

args = parser.parse_args()

key = "$KEY"

def encrypt(data):
    return AESCipher(key).encrypt(data).decode('utf-8')
def decrypt(data):
    return AESCipher(key).decrypt(data).decode('utf-8')
def save_data(datalist):
    bga = [datalist["host"], encrypt(datalist["login_candidate"]), encrypt(datalist["password"])]
    cursor = db.cursor()
    sql = "INSERT INTO passwd (id, host, login_candidate, password) VALUES (NULL, ?, ?, ?)"
    cursor.execute(sql, (bga[0], bga[1], bga[2]))
    db.commit()

def get_data(host, all=False):
    cursor = db.cursor()
    sql = "SELECT * FROM passwd;"
    cursor.execute(sql)
    data = cursor.fetchall()
    rows = data
    if all == False:
        rows = []
        for i in range(len(data)):
            if host.lower() in data[i][1].lower():
                rows.append(list(data[i]))
        count = [i for i in range(0,len(data)) if data[i][1].lower() == host.lower()]
        if len(count) <= 0:
            print("No results found matching your query, did you add this host??")
            exit(1) 
        for x in rows:
            x[2] = decrypt(x[2])
            x[3] = decrypt(x[3])
        
    elif all == True: 
        old = rows
        rows = [] 
        for i in old:
            rows.append(list(i))
        for x in rows:
            x[2] = decrypt(x[2])
            x[3] = decrypt(x[3])
    
    if len(rows) <= 0:
            print("Password database is empty.")
            exit(1) 
    print(columnar(rows, headers=["ID", "HOST", "LOGIN CANDIDATE", "PASSWORD"]))
    pass
def delete_index(idx):
    cursor = db.cursor()
    sql = "DELETE FROM passwd WHERE id = ?"
    cursor.execute(sql, (idx,))
    db.commit()
    print("Saved login data deleted if existed.")
    pass
def main():       
    if args.action.lower() == "new":
        if args.login_candidate is None:
            print("E: login-candidate is undefined, define it.")
            exit(-1)
        if args.password is None:
            print("E: password is undefined, define it.")
            exit(-1)
        if args.host is None:
            print("E: host is undefined, define it.")
            exit(-1)
        summary = {
            "host": args.host,
            "login_candidate": args.login_candidate,
            "password": args.password
        }
        print("Do you really wish to make these changes?\n")
        headers = ["HOST", "LOGIN CANDIDATE", "PASSWORD"]
        tofrm = [[summary["host"], summary["login_candidate"], summary["password"]]]
        print(columnar(tofrm, headers, no_borders=True))
        save = False
        while True:
            stdin = input("\n(Y/n)")
            if stdin.lower() == "yes" or stdin.lower() == "y":
                save = True
                break
            elif stdin.lower() == "no" or stdin.lower() == "n":
                break
            else:
                pass
        if save:
            save_data(summary)
            bashpath = os.path.expanduser('~')+r"/.bash_history"   
            zshpath = os.path.expanduser('~')+r"/.zsh_history"   
            last_id = 0    
            try:   
                os.remove(bashpath)
            except:
                pass
            try:
                os.remove(zshpath)
            except: 
                pass
        else:
            print("\nOperation cancelled.")
            exit(2)
    elif args.action.lower() == "get":
        if args.host != '*':
            get_data(args.host)
        elif args.host == '*':
            get_data(args.host, all=True)
        pass
    elif args.action.lower() == "del":
        if args.index is None:
            print("E: index is required for this action.")
            exit(-1)
        delete_index(args.index)
        pass
    else:
        print("E: INVALID ACTION")
        exit(1)
    

    # First let us encrypt secret message
    #encrypted = encrypt("This is a secret message", password)
    #print(encrypted)
    
    # Let us decrypt using our original password
    #decrypted = decrypt(encrypted)
    #print(bytes.decode(decrypted))

if __name__ == "__main__":
    main()