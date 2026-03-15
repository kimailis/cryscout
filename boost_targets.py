import sqlite3
import pandas as pd
from db_manager import get_connection

real_targets = [
    "12ib7dApVFvg82TXKycWBNpN8kFyiAN1dr",
    "15Z5YJaaNSxeynvr6uW6jQZLwq3n1Hu6RX",
    "1BeouDc6jtHpitvPz3gR3LQnBGb7dKRrtC",
    "1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx",
    "1EgH7EUfgjr8gAK9t1BeHLDC1ijrVvdec3",
    "1KpwMa1w9DTUCB5asCgUdLRA22hto1Qgqv",
    "1Dp1yVTFmgb6oL5WoNVsLsZso4ATMzxD1M",
    "1JaPNwMXt2AuVkWmkUHbsw78MbGorTfmm2",
    "1FdPpELnjHfwSM4Nvi7LdYS4S4GVGsLUQY",
    "13FKHnREotr4jrjiSJwPUpecogVT7Rj7bu",
    "1HDNfSr5ExyGfe77GX681PPZtN2deoewfd",
    "174NVbudzKV1jZnZvRzKvauZxnq25NfG4v",
    "1AV4KGCsvtPZ9tG7hvwgb85wJyFd9xdpFv",
    "194RLDTv6rjkDu9kX99mTBuK6KunAWRRkk",
    "13kxWCuDWN1gGSe2vPmsSBVXyPfYLMh6M4",
    "1FUGUiJFcsLktTAkexy2ghT3Kus7yyEuUJ",
    "152kzDqjAVuPBMmJqcWvFbB7qkvigFXSLh",
    "19xjndVpGTqmFAC1ZL3gV6MpxJUMkvqSrd",
    "16xSAf5uYCrEgTfXxjrUgq9c5qSjZowSCa",
    "12yqUYtcCvDgiDgzJTT7DsSCoSifwYavhH",
    "15USWMmGtSHnnkmcJBrwYrAjtjBg6i4N8w",
    "1KVyYVs7qbzuZt4s6M1hKRwtQZm2QQZLiA",
    "3PyRWFMLSPDunU6TsMkKs39ikwDpk8LxzG"
]

def boost_targets():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Reset processing status for these targets to ensure they are picked up immediately
    # And mark them as not fully analyzed to trigger re-analysis if needed
    for addr in real_targets:
        print(f"Boosting target: {addr}")
        cursor.execute('''
            UPDATE addresses 
            SET status = 'Spent/Active',
                sigs_fetched = 0,
                analyzed = 0,
                processing_by = NULL,
                processing_since = NULL,
                last_updated = datetime('now', '-30 days')
            WHERE address = ?
        ''', (addr,))
    
    conn.commit()
    conn.close()
    print("All real targets boosted and reset for processing.")

if __name__ == "__main__":
    boost_targets()
