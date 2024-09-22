import random
import hashlib
import ecdsa
import base58
from multiprocessing import Pool, cpu_count
from tqdm import tqdm

def generate_private_key():
    return ''.join(random.choices('0123456789ABCDEF', k=64))

def private_key_to_wif(private_key, compressed=True):
    extended_key = '80' + private_key
    if compressed:
        extended_key += '01'
    first_sha256 = hashlib.sha256(bytes.fromhex(extended_key)).hexdigest()
    second_sha256 = hashlib.sha256(bytes.fromhex(first_sha256)).hexdigest()
    checksum = second_sha256[:8]
    wif = extended_key + checksum
    return base58.b58encode(bytes.fromhex(wif)).decode()

def private_key_to_public_key(private_key, compressed=True):
    pk_bytes = bytes.fromhex(private_key)
    sk = ecdsa.SigningKey.from_string(pk_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    if compressed:
        public_key = b'\x02' + vk.to_string()[:32] if vk.to_string()[32] < 128 else b'\x03' + vk.to_string()[:32]
    else:
        public_key = b'\x04' + vk.to_string()
    return public_key.hex()

def public_key_to_p2pkh(public_key):
    sha256 = hashlib.sha256(bytes.fromhex(public_key)).hexdigest()
    ripemd160 = hashlib.new('ripemd160', bytes.fromhex(sha256)).hexdigest()
    extended_ripemd160 = '00' + ripemd160
    first_sha256 = hashlib.sha256(bytes.fromhex(extended_ripemd160)).hexdigest()
    second_sha256 = hashlib.sha256(bytes.fromhex(first_sha256)).hexdigest()
    checksum = second_sha256[:8]
    address_hex = extended_ripemd160 + checksum
    return base58.b58encode(bytes.fromhex(address_hex)).decode()

def generate_address_pair():
    private_key = generate_private_key()
    public_key_compressed = private_key_to_public_key(private_key, compressed=True)
    public_key_uncompressed = private_key_to_public_key(private_key, compressed=False)
    address_compressed = public_key_to_p2pkh(public_key_compressed)
    address_uncompressed = public_key_to_p2pkh(public_key_uncompressed)
    wif_compressed = private_key_to_wif(private_key, compressed=True)
    wif_uncompressed = private_key_to_wif(private_key, compressed=False)
    return (address_compressed, wif_compressed), (address_uncompressed, wif_uncompressed)

def analyze_patterns(addresses, initial_patterns, final_patterns):
    pattern_matches = []
    for address in addresses:
        initial_match = all(address[i+1] == initial_patterns[i] for i in range(len(initial_patterns)))
        final_match = all(address[-(i+1)] == final_patterns[-(i+1)] for i in range(len(final_patterns)))
        if initial_match and final_match:
            pattern_matches.append(address)
    return pattern_matches

def save_patterns_to_file(pattern_matches, filename):
    with open(filename, 'a') as file:
        for address in pattern_matches:
            file.write(f"{address}\n")

def save_private_keys_to_file(private_keys, pattern_matches, filename):
    with open(filename, 'a') as file:
        for i, (address, key) in enumerate(zip(pattern_matches, private_keys), 1):
            file.write(f"{i}. {address}: {key}\n")

def save_all_public_keys_to_file(public_keys, private_keys, filename):
    with open(filename, 'a') as file:
        for i, (address, key) in enumerate(zip(public_keys, private_keys), 1):
            file.write(f"{i}. {address}: {key}\n")

def worker(_):
    (address_compressed, wif_compressed), (address_uncompressed, wif_uncompressed) = generate_address_pair()
    return (address_compressed, wif_compressed), (address_uncompressed, wif_uncompressed)

def main(initial_count, final_count, initial_patterns, final_patterns, num_keys):
    # Genera direcciones sin compresión
    addresses_uncompressed = []
    private_keys_uncompressed = []

    print("Generando direcciones y claves privadas sin compresión...")

    with Pool(cpu_count()) as pool:
        results = list(tqdm(pool.imap(worker, range(num_keys // 2)), total=num_keys // 2))

    for result in results:
        (_, _), (address_uncompressed, wif_uncompressed) = result
        addresses_uncompressed.append(address_uncompressed)
        private_keys_uncompressed.append(wif_uncompressed)

    print("Generación sin compresión completada.")

    # Analiza los patrones sin compresión
    print("Analizando patrones sin compresión...")
    pattern_matches_uncompressed = analyze_patterns(addresses_uncompressed, initial_patterns, final_patterns)
    print("Análisis sin compresión completado.")

    # Guarda los patrones y las claves privadas sin compresión en archivos
    if pattern_matches_uncompressed:
        print("Guardando resultados sin compresión en archivos...")
        save_patterns_to_file(pattern_matches_uncompressed, "patronesS.txt")
        save_private_keys_to_file(private_keys_uncompressed, pattern_matches_uncompressed, "clavesps.txt")
    else:
        print("No se encontraron coincidencias sin compresión.")

    # Genera direcciones con compresión
    addresses_compressed = []
    private_keys_compressed = []

    print("Generando direcciones y claves privadas con compresión...")

    with Pool(cpu_count()) as pool:
        results = list(tqdm(pool.imap(worker, range(num_keys // 2)), total=num_keys // 2))

    for result in results:
        (address_compressed, wif_compressed), (_, _) = result
        addresses_compressed.append(address_compressed)
        private_keys_compressed.append(wif_compressed)

    print("Generación con compresión completada.")

    # Analiza los patrones con compresión
    print("Analizando patrones con compresión...")
    pattern_matches_compressed = analyze_patterns(addresses_compressed, initial_patterns, final_patterns)
    print("Análisis con compresión completado.")

    # Guarda los patrones y las claves privadas con compresión en archivos
    if pattern_matches_compressed:
        print("Guardando resultados con compresión en archivos...")
        save_patterns_to_file(pattern_matches_compressed, "patronesC.txt")
        save_private_keys_to_file(private_keys_compressed, pattern_matches_compressed, "clavespc.txt")
    else:
        print("No se encontraron coincidencias con compresión.")

    # Guarda todas las claves públicas y privadas que coinciden en todo.txt
    all_pattern_matches = pattern_matches_uncompressed + pattern_matches_compressed
    if all_pattern_matches:
        print("Guardando todas las claves públicas y privadas que coinciden en todo.txt...")
        all_private_keys = private_keys_uncompressed + private_keys_compressed
        save_all_public_keys_to_file(all_pattern_matches, all_private_keys, "todo.txt")
        print("Resultados guardados en patronesS.txt, patronesC.txt, clavesps.txt, clavespc.txt y todo.txt")
    else:
        print("No se encontraron coincidencias en total.")

if __name__ == "__main__":
    initial_count = int(input("¿Cuántos caracteres iniciales buscar (1-5)? "))
    initial_patterns = [input(f"Introduce el carácter a buscar en la posición {i+2}: ") for i in range(initial_count)]

    search_final = input("¿Deseas buscar caracteres finales? (s/n): ").lower() == 's'
    final_patterns = []
    if search_final:
        final_count = int(input("¿Cuántos caracteres finales buscar (1-3)? "))
        final_patterns = [input(f"Introduce el carácter a buscar en la posición {34-i}: ") for i in range(final_count)]

    num_keys = int(input("Introduce el número de claves a generar: "))
    main(initial_count, final_count if search_final else 0, initial_patterns, final_patterns, num_keys)

    input("Presiona Enter para salir...")
