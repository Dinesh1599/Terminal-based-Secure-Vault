from auth import signup, login
from database import init_db, add_vault_entry, get_vault_entries
from crypto_utils import derive_key, encrypt_data, decrypt_data