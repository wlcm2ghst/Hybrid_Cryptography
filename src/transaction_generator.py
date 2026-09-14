# ============================================================
# transaction_generator.py
# Generates simulated transaction records for experiments
# ============================================================

import random
import string
import datetime
import json

def generate_transaction_id(number):
    """Generate a unique transaction ID"""
    return f"TXN-{number:05d}"

def generate_account_number():
    """Generate a random 10-digit account number"""
    return ''.join([str(random.randint(0, 9)) for _ in range(10)])

def generate_amount():
    """Generate a random transaction amount between 1.00 and 10000.00"""
    return round(random.uniform(1.00, 10000.00), 2)

def generate_timestamp():
    """Generate current timestamp"""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def generate_transaction(number):
    """Generate a single transaction record"""
    transaction = {
        "transaction_id": generate_transaction_id(number),
        "sender_account": generate_account_number(),
        "receiver_account": generate_account_number(),
        "amount": generate_amount(),
        "timestamp": generate_timestamp()
    }
    return transaction

def generate_transaction_batch(volume):
    """Generate a batch of transactions"""
    transactions = []
    for i in range(1, volume + 1):
        transactions.append(generate_transaction(i))
    return transactions

def transaction_to_bytes(transaction):
    """Convert transaction dictionary to bytes for encryption"""
    return json.dumps(transaction).encode('utf-8')

def bytes_to_transaction(transaction_bytes):
    """Convert bytes back to transaction dictionary after decryption"""
    return json.loads(transaction_bytes.decode('utf-8'))

# ============================================================
# TESTING
# ============================================================
if __name__ == "__main__":
    print("=" * 50)
    print("TRANSACTION GENERATOR TEST")
    print("=" * 50)

    # Generate a single transaction
    single = generate_transaction(1)
    print("\nSingle Transaction:")
    for key, value in single.items():
        print(f"  {key}: {value}")

    # Convert to bytes
    transaction_bytes = transaction_to_bytes(single)
    print(f"\nTransaction as bytes ({len(transaction_bytes)} bytes):")
    print(f"  {transaction_bytes}")

    # Convert back
    recovered = bytes_to_transaction(transaction_bytes)
    print(f"\nRecovered Transaction:")
    for key, value in recovered.items():
        print(f"  {key}: {value}")

    # Generate a small batch
    batch = generate_transaction_batch(5)
    print(f"\nBatch of 5 Transactions:")
    for t in batch:
        print(f"  {t['transaction_id']} | "
              f"Amount: {t['amount']} | "
              f"From: {t['sender_account']} | "
              f"To: {t['receiver_account']}")

    print("\n Transaction Generator working correctly!")