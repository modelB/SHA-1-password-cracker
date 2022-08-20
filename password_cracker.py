import hashlib

def hash_with_salt(password, salt = '', append = False):
  password_with_salt = password + salt if append else salt + password
  return hashlib.sha1((password_with_salt).encode('utf-8')).hexdigest()

  
def crack_sha1_hash(hash, use_salts = False):
  with open('top-10000-passwords.txt') as passwords_file, open('known-salts.txt') as known_salts_file:
    salts = known_salts_file.read().split()
    passwords = passwords_file.read().split()
    for password in passwords:
      if use_salts:
        for salt in salts:
          if hash_with_salt(password, salt) == hash or hash_with_salt(password, salt, True) == hash:
            return password
      else:
        if hash_with_salt(password) == hash:
          return password
  
  return 'PASSWORD NOT IN DATABASE'
    