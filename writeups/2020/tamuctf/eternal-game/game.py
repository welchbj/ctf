#!/usr/bin/python2

from collections import defaultdict
import random
import hashlib
import sys

x = 1
d = defaultdict(int)
game_running = True
high_score = 653086069891774904466108141306028536722619133804


def gen_hash(x):
    with open('key.txt', 'r') as f:
        key = f.read()[:-1]
        return hashlib.sha512(key + x).hexdigest()


def extract_int(s):
    i = len(s) - 1
    result = 0
    while i >= 0 and s[i].isdigit():
        result *= 10
        result += ord(s[i]) - ord('0')
        i -= 1
    return result


def multiply():
    global x
    print 'Multiplier: '
    sys.stdout.flush()
    m = extract_int(raw_input())
    sys.stdout.flush()
    if m < 2 or m > 10:
        print 'Disallowed value.'
    elif d[m] == 5:
        print 'You already multiplied by ' + str(m) + ' five times!'
    else:
        x *= m
        d[m] += 1
    sys.stdout.flush()


def print_value():
    print x
    sys.stdout.flush()


def get_proof():
    global game_running
    game_running = False
    print gen_hash(str(x))
    sys.stdout.flush()


game_options = [multiply, print_value, get_proof]
def play_game():
    global game_running
    game_running = True
    print(
            '''
            Welcome the The Game. You are allowed to multiply the initial number (which is 1) by any
            number in the range 2-10. Make decisions wisely! You can only multiply by each
            number at most 5 times... so be careful. Also, at a random point during The Game, an asteroid
            will impact the Earth and The Game will be over.

            Feel free to get your proof of achievement and claim your prize at the main menu once
            you start reaching big numbers. Bet you can't beat my high score!
            '''
            )
    while game_running:
        print '1. Multiply'
        print '2. Print current value'
        print '3. Get proof and quit'
        sys.stdout.flush()
        game_options[extract_int(raw_input())-1]()
        sys.stdout.flush()
        if random.randint(1, 20) == 10:
            print 'ASTEROID!'
            game_running = False
        sys.stdout.flush()


def prize():
    print 'Input the number you reached: '
    sys.stdout.flush()
    num = raw_input()

    sys.stdout.flush()
    print 'Present the proof of your achievement: '
    sys.stdout.flush()
    proof = raw_input()
    sys.stdout.flush()
    num_hash = gen_hash(num)
    num = extract_int(num)

    if proof == num_hash:
        if num > high_score:
            with open('flag.txt', 'r') as f:
                print f.read()
        elif num > 10**18:
            print 'It sure is a good thing I wrote this in Python. Incredible!'
        elif num > 10**9:
            print 'This is becoming ridiculous... almost out of bounds on a 32 bit integer!'
        elif num > 10**6:
            print 'Into the millions!'
        elif num > 1000:
            print 'Good start!'
        else:
            print 'You can do better than that.'
    else:
        print 'Don\'t play games with me. I told you you couldn\'t beat my high score, so why are you even trying?'
    sys.stdout.flush()

def new():
    global x
    global d
    x = 1
    d = defaultdict(int)
    sys.stdout.flush()
    play_game()


main_options = [new, prize, exit]


def main_menu():
    print '1. New Game'
    print '2. Claim Prize'
    print '3. Exit'
    sys.stdout.flush()
    main_options[extract_int(raw_input())-1]()
    sys.stdout.flush()

if __name__ == '__main__':
    while True:
        main_menu()
