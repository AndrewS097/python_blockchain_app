\
import datetime
import json
import requests
from flask import render_template, redirect, request, jsonify
from app import app
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import os
from codecs import encode
# The node with which our application interacts, there can be multiple
# such nodes as well.
CONNECTED_NODE_ADDRESS = "http://127.0.0.1:8000"

posts = []
#password/username counter
passwords=[]
usernames=[]

def fetch_posts():
    """
    Function to fetch the chain from a blockchain node, parse the
    data and store it locally.
    """
    get_chain_address = "{}/chain".format(CONNECTED_NODE_ADDRESS)
    response = requests.get(get_chain_address)
    if response.status_code == 200:
        content = []
        chain = json.loads(response.content)
        for block in chain["chain"]:
            for tx in block["transactions"]:
                tx["index"] = block["index"]
                tx["hash"] = block["previous_hash"]
                content.append(tx)

        global posts
        posts = sorted(content, key=lambda k: k['timestamp'],
                       reverse=True)


@app.route('/')
def index1():
    return render_template('index.html', node_address=CONNECTED_NODE_ADDRESS,)
#Decrypts  Passwords                           
@app.route ('/decrypt_method', methods=['POST', 'GET'])
def decrypt_method():
    for i in range(len(passwords)):
        passwords[i]=decrypt(str(passwords[i]))
        passwords[i]=str(passwords[i])
        new_passwords=[x[2:-1] for x in passwords]
    return jsonify(Usernames=usernames,Decrypted_Passwords=new_passwords)  
@app.route('/home')
def index():
    fetch_posts()
    return render_template('home.html',
                           title='BlockVault',
                           posts=posts, node_address=CONNECTED_NODE_ADDRESS,
                           readable_time=timestamp_to_string)


@app.route('/submit', methods=['POST'])
def submit_textarea():
    """
    Endpoint to create a new transaction via our application.
    """
    post_content = request.form["content"]
    author = encrypt(str(request.form["author"]))

    post_object = {
        'author': author,
        'content': post_content,
    }

    # Submit a transaction
    new_tx_address = "{}/new_transaction".format(CONNECTED_NODE_ADDRESS)

    requests.post(new_tx_address,
                  json=post_object,
                  headers={'Content-type': 'application/json'})
    password=request.form['author']
    username=request.form['content']
    credentialsArray(encrypt(str(password)), username)
    return redirect('/home')

def credentialsArray(password, username):
    passwords.append(password)
    usernames.append(username)
    return "done"


def timestamp_to_string(epoch_time):
    return datetime.datetime.fromtimestamp(epoch_time).strftime('%H:%M')


'''
Function to retrieve the password hash using the username as an input
'''
def get_key():
    os.chdir("/home/") # set the directory to the home directory in Linux file system
    for root, dirs, files in os.walk("."): #walk through the directories
        for file in files: 
            if file == "userLoggedIn.txt": # if the file is the file we are looking for then print
                userLoggedInFile = open(os.path.join(root, file)) # open file  but first find the file in the directorydef get_key(username):
    lines=userLoggedInFile.readlines()
    loggedInUser=''                
    for i in lines: # searches the credential file line by line
        loggedInUser= loggedInUser + i 
        length_username = len(loggedInUser)
        key = i[length_username+1: len(i)]
        key = SHA256.SHA256Hash.new(key) # rehash the password hash to double the security
        key = str(SHA256.SHA256Hash.hexdigest(key))
        key = bytes(key[:16], 'utf-8')
        return key #error for key length in the encryption algorithm will have to double check that

    print("The username '" + username + "' does not exist.")


def encrypt(password):
    key = get_key()
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(password.encode('utf-8').strip())
    encrypted_password = str(ciphertext) + str(nonce) # store the nonce and password together in the encryption
    return encrypted_password # returns the bytes format to decode into string use .decode('utf-8) function


def find_pword_nonce(key):
    password = ''
    for character in key:
        password = password + character
        length_password = len(password)
        try: # exception handling for the first 3 iterations of the for loop
            if password[length_password-1] == "'" and password[length_password-2] != 'b':
                password = password[2:length_password-1] #strip the first 2 characters which are b' and the last character which is '
                nonce = key[length_password+2:].strip("'") # create nonce password and return the two variables
                return password, nonce
        except:
            pass

def decrypt(encrypted_password): #seperate the nonce and the password -> iterate through a list to match the password
    key = get_key() # retrieved the key based on user account
    ciphertext, nonce = find_pword_nonce(encrypted_password) #seperate key into nonce and password
    ciphertext = encode(ciphertext.encode().decode('unicode_escape'), 'raw_unicode_escape') # need to convert the ciphertext into the correct byte object
    global cipher
    nonce = encode(nonce.encode().decode('unicode_escape'),'raw_unicode_escape') # need to convert the nonce into the correct byte object
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce) # create encryption object
    plaintext = cipher.decrypt(ciphertext) # decrypt the cipher text
    return plaintext # returns the byte object of the password -> may want to work with stripping the b' and ' from the printed text


