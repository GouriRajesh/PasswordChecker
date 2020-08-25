import requests
import hashlib  # to convert to hashed form
import sys


def request_api_data(query_char):  # pass the 5 chars of hashed password
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    # We are using the pwned api
    # We need to pass the password as second argument. K-anonymity(only first 5 characters) and SHA1 Hashing
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error finding: {res.status_code}, please check the api and try again!')
    return res  # entire file of all the password tails which have been matched with starting 5 char


def get_password_leak_count(hashes, hash_to_check):
    hashes= (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        # h is the tails of the hashed passwords which have the starting 5 chars same as ours,count is number of times it has been pwned
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    # print(hashlib.sha1(password.encode('utf-8')).hexdigest().upper())
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    # print(response, first5_char, tail)
    return get_password_leak_count(response, tail)

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} has been found {count} number of times...You should probably change it!')
        else:
            print(f'{password} has not been found...Carry on!')
    return 'done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
# Accepts command line arguments. To improve the safety it can be modified to read from a file.