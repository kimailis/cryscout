import os

# Data Enrichment: Expanded Dictionary for Brainwallet Scanning
# Includes common mnemonic seeds, movie quotes, literary phrases, and patterns.

NEW_PHRASES = [
    # 1. Historical & Bitcoin Quotes
    "vires in numeris",
    "Chancellor on brink of second bailout for banks",
    "Running bitcoin",
    "The Times 03/Jan/2009",
    "In math we trust",
    "Taxation is theft",
    "End the fed",
    "Be your own bank",
    
    # 2. Movie & Literature Quotes
    "To be or not to be",
    "Bond, James Bond",
    "Elementary, my dear Watson",
    "May the force be with you",
    "I'll be back",
    "Here's looking at you kid",
    "One ring to rule them all",
    "In the beginning was the word",
    "God save the queen",
    "Long live the king",
    "The quick brown fox jumps over the lazy dog",
    
    # 3. Famous Passwords & Patterns (Top 50+)
    "password123", "admin123", "welcome", "12345678", "dragon",
    "monkey", "superman", "batman", "iloveyou", "princess",
    "football", "soccer", "basketball", "baseball", "hockey",
    "master", "secret", "killer", "shadow", "ghost",
    
    # 4. Common BIP39 Words & Combinations
    "abandon", "ability", "able", "about", "above", "absent",
    "absorb", "abstract", "absurd", "abuse", "access", "accident",
    "account", "accuse", "achieve", "acid", "acoustic", "acquire",
    
    # 5. Technical & Security Phrases
    "correct horse battery staple", # XKCD
    "hunter2", # Famous meme
    "root123", "adminpass", "system123",
    
    # 6. Famous Personas
    "Hal Finney", "Nick Szabo", "Wei Dai", "Adam Back",
    "Satoshi Nakamoto", "Dorian Nakamoto", "Craig Wright",
    "Laszlo Hanyecz", "10000 bitcoins for two pizzas"
]

def enrich():
    dict_file = "extended_dictionary.txt"
    existing = set()
    if os.path.exists(dict_file):
        with open(dict_file, "r") as f:
            existing = {line.strip() for line in f if line.strip()}
    
    added_count = 0
    with open(dict_file, "a") as f:
        for p in NEW_PHRASES:
            if p not in existing:
                f.write(p + "\n")
                added_count += 1
                existing.add(p)
    
    print(f"Added {added_count} new base phrases to {dict_file}.")
    print(f"Total phrases now: {len(existing)}")

if __name__ == "__main__":
    enrich()
